"""Web paneli (sefalet/web) testleri.

FastAPI'nin TestClient'ı, gerçek bir sunucu açmadan API'ye istek gönderir.
Ağ kullanan fonksiyonlar (hedef çözümleme, tarama) sahteleriyle değiştirilir.
"""

import time

import pytest
from fastapi.testclient import TestClient

from sefalet.authorization import TokenStore
from sefalet.models import AuthorizationInfo, AuthorizationMethod, CheckResult, CheckStatus, ScanResult, Severity
from sefalet.risk import apply_risk
from sefalet.target import Target, TargetError
from sefalet.web import app as web_app
from sefalet.web.history import ScanHistory, is_valid_scan_id

TOKEN = "test-oturum-anahtari"
HOSTS = frozenset({"testserver", "127.0.0.1", "localhost"})


def fake_target(raw, lab_mode=False):
    if raw.startswith("ozel"):
        raise TargetError("Hedef özel/iç ağ adresine çözümlendi")
    host = "localhost" if lab_mode else "ornek.com"
    ip = "127.0.0.1" if lab_mode else "93.184.216.34"
    return Target(original=raw, scheme="https", hostname=host, port=443, is_ip=False,
                  ip_addresses=(ip,), lab_mode=lab_mode)


@pytest.fixture
def make_scan(make_finding):
    def _make(target="ornek.com", severity=Severity.MEDIUM, days_left=40, method=AuthorizationMethod.LAB):
        tls = CheckResult(check_name="tls", status=CheckStatus.COMPLETED,
                          findings=[make_finding(id="TLS-002", severity=severity)],
                          details={"days_left": days_left})
        headers = CheckResult(check_name="headers", status=CheckStatus.COMPLETED,
                              findings=[make_finding(id="HDR-004", title="<script>alert(1)</script>")])
        ports = CheckResult(check_name="ports", status=CheckStatus.SKIPPED, message="Kapalı")
        return apply_risk(ScanResult(target=target, target_ips=["93.184.216.34"],
                                     authorization=AuthorizationInfo(method=method, details="x"),
                                     checks=[tls, headers, ports]))
    return _make


@pytest.fixture
def setup(tmp_path, monkeypatch, make_scan):
    calls = []

    def runner(target, authorization, *, enable_port_scan, progress):
        calls.append({"target": target, "auth": authorization, "ports": enable_port_scan})
        for name in ("tls", "headers", "dns", "ports"):
            progress(name, "başladı")
            progress(name, "bitti")
        return make_scan(target=target.display_name, method=authorization.method)

    monkeypatch.setattr(web_app, "resolve_target", fake_target)
    application = web_app.create_app(tmp_path, session_token=TOKEN, allowed_hosts=HOSTS, runner=runner)
    client = TestClient(application, headers={"X-Sefalet-Token": TOKEN})
    return client, tmp_path, calls


def wait_job(client, job_id, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] in ("done", "error"):
            return job
        time.sleep(0.02)
    raise AssertionError("İş zamanında bitmedi")


# --- Güvenlik ------------------------------------------------------------


def test_index_contains_session_token(setup):
    client, *_ = setup
    response = client.get("/")
    assert response.status_code == 200
    assert TOKEN in response.text
    assert "__SESSION_TOKEN__" not in response.text
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_foreign_host_rejected(setup):
    client, *_ = setup
    response = client.get("/api/summary", headers={"Host": "kotu-site.com"})
    assert response.status_code == 403


def test_host_with_port_accepted(setup):
    client, *_ = setup
    assert client.get("/api/summary", headers={"Host": "127.0.0.1:8765"}).status_code == 200


def test_post_without_token_rejected(setup):
    client, *_ = setup
    response = client.post("/api/scans", json={"target": "x", "mode": "lab"},
                           headers={"X-Sefalet-Token": "yanlis"})
    assert response.status_code == 403
    assert "Oturum anahtarı" in response.json()["detail"]["message"]


def test_delete_without_token_rejected(setup, make_scan):
    client, tmp_path, _ = setup
    scan = make_scan()
    ScanHistory(tmp_path / "scans").save(scan)
    assert client.delete(f"/api/scans/{scan.scan_id}", headers={"X-Sefalet-Token": ""}).status_code == 403


def test_static_files_served(setup):
    client, *_ = setup
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/app.css").status_code == 200


@pytest.mark.parametrize("bad_id", ["../../etc/passwd", "abc", "..%2F..%2Fx"])
def test_invalid_scan_ids(setup, bad_id):
    client, *_ = setup
    assert client.get(f"/api/scans/{bad_id}").status_code == 404


def test_scan_id_validation():
    assert is_valid_scan_id("123e4567-e89b-12d3-a456-426614174000")
    assert not is_valid_scan_id("../123e4567-e89b-12d3-a456-426614174000")


# --- Özet ve listeler ----------------------------------------------------


def test_empty_summary(setup):
    client, *_ = setup
    data = client.get("/api/summary").json()
    assert data["total_scans"] == 0
    assert data["latest"] is None
    assert data["modules"] == []


def test_summary_uses_latest_scan_per_target(setup, make_scan):
    client, tmp_path, _ = setup
    history = ScanHistory(tmp_path / "scans")
    old = make_scan(target="ornek.com", severity=Severity.HIGH)
    new = make_scan(target="ornek.com", severity=Severity.LOW, days_left=12)
    new.started_at = old.started_at.replace(year=old.started_at.year + 1)
    other = make_scan(target="baska.com")
    for s in (old, new, other):
        history.save(s)

    data = client.get("/api/summary").json()
    assert data["total_scans"] == 3
    assert data["targets"] == 2
    assert data["latest"]["scan_id"] == new.scan_id
    assert data["ssl_days_left"] == 12
    # ornek.com için yalnızca en yeni tarama sayılır (HIGH değil LOW)
    assert data["totals"]["high"] == 0
    assert {m["name"] for m in data["modules"]} == {"tls", "headers", "ports"}


def test_scan_detail_and_downloads(setup, make_scan):
    client, tmp_path, _ = setup
    scan = make_scan()
    ScanHistory(tmp_path / "scans").save(scan)

    detail = client.get(f"/api/scans/{scan.scan_id}").json()
    assert detail["summary"]["grade"] == scan.risk.grade
    assert {f["check"] for f in detail["findings_sorted"]} == {"tls", "headers"}
    assert detail["findings_sorted"][0]["severity_label"]

    js = client.get(f"/api/scans/{scan.scan_id}/json")
    assert js.headers["content-disposition"].startswith("attachment")
    assert js.json()["scan_id"] == scan.scan_id

    pdf = client.get(f"/api/scans/{scan.scan_id}/pdf")
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")


def test_delete_scan(setup, make_scan):
    client, tmp_path, _ = setup
    scan = make_scan()
    ScanHistory(tmp_path / "scans").save(scan)
    client.get(f"/api/scans/{scan.scan_id}/pdf")  # PDF önbelleğe alınsın
    assert client.delete(f"/api/scans/{scan.scan_id}").status_code == 200
    assert client.get(f"/api/scans/{scan.scan_id}").status_code == 404
    assert not (tmp_path / "pdf" / f"{scan.scan_id}.pdf").exists()


def test_corrupt_history_file_is_skipped(setup, make_scan):
    client, tmp_path, _ = setup
    history = ScanHistory(tmp_path / "scans")
    history.save(make_scan())
    (tmp_path / "scans" / "bozuk.json").write_text("{bozuk")
    assert len(client.get("/api/scans").json()) == 1


# --- Token ---------------------------------------------------------------


def test_token_endpoint(setup):
    client, tmp_path, _ = setup
    data = client.post("/api/token", json={"target": "https://Ornek.com/"}).json()
    stored = TokenStore(tmp_path / "verifications.json").get("ornek.com")
    assert data["value"] == f"sefalet-verify={stored}"
    assert data["dns_name"] == "_sefalet-verify.ornek.com"


def test_token_invalid_target(setup):
    client, *_ = setup
    assert client.post("/api/token", json={"target": "ftp://x"}).status_code == 400


# --- Tarama başlatma -----------------------------------------------------


def test_lab_scan_runs_and_is_saved(setup):
    client, _, calls = setup
    response = client.post("/api/scans", json={"target": "localhost", "mode": "lab"})
    assert response.status_code == 202
    job = wait_job(client, response.json()["job_id"])
    assert job["status"] == "done"
    assert job["completed_steps"] == ["tls", "headers", "dns", "ports"]
    assert calls[0]["auth"].method is AuthorizationMethod.LAB
    assert client.get(f"/api/scans/{job['scan_id']}").status_code == 200


def test_declaration_scan(setup):
    client, _, calls = setup
    response = client.post("/api/scans", json={"target": "ornek.com", "mode": "declaration",
                                               "declarant": "Ayşe Yılmaz", "accept_declaration": True})
    assert response.status_code == 202
    wait_job(client, response.json()["job_id"])
    assert "Ayşe Yılmaz" in calls[0]["auth"].details


def test_declaration_must_be_accepted(setup):
    client, _, calls = setup
    response = client.post("/api/scans", json={"target": "ornek.com", "mode": "declaration",
                                               "declarant": "Ayşe Yılmaz"})
    assert response.status_code == 403
    assert calls == []


def test_declaration_cannot_enable_ports(setup):
    client, _, calls = setup
    response = client.post("/api/scans", json={"target": "ornek.com", "mode": "declaration",
                                               "declarant": "Ayşe", "accept_declaration": True,
                                               "enable_port_scan": True})
    assert response.status_code == 403
    assert calls == []


def test_verify_without_token_returns_instructions(setup):
    client, _, calls = setup
    response = client.post("/api/scans", json={"target": "ornek.com", "mode": "verify"})
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["value"].startswith("sefalet-verify=")
    assert detail["hostname"] == "ornek.com"
    assert calls == []


def test_verify_failure_lists_errors(setup, monkeypatch):
    from sefalet.authorization import AuthorizationError

    client, tmp_path, calls = setup
    TokenStore(tmp_path / "verifications.json").get_or_create("ornek.com")

    def fail(target, token):
        raise AuthorizationError("kayıt bulunamadı")

    monkeypatch.setattr(web_app, "verify_dns_txt", fail)
    monkeypatch.setattr(web_app, "verify_http_file", fail)
    response = client.post("/api/scans", json={"target": "ornek.com", "mode": "verify"})
    assert response.status_code == 403
    assert response.json()["detail"]["errors"] == ["kayıt bulunamadı", "kayıt bulunamadı"]
    assert calls == []


def test_verify_success_with_port_scan(setup, monkeypatch):
    client, tmp_path, calls = setup
    TokenStore(tmp_path / "verifications.json").get_or_create("ornek.com")
    monkeypatch.setattr(web_app, "verify_dns_txt", lambda t, v: AuthorizationInfo(
        method=AuthorizationMethod.DNS_TXT, details="TXT bulundu"))
    response = client.post("/api/scans", json={"target": "ornek.com", "mode": "verify",
                                               "enable_port_scan": True})
    assert response.status_code == 202
    wait_job(client, response.json()["job_id"])
    assert calls[0]["ports"] is True


def test_invalid_target_rejected(setup):
    client, _, calls = setup
    response = client.post("/api/scans", json={"target": "ozel-ag", "mode": "verify"})
    assert response.status_code == 400
    assert "özel/iç ağ" in response.json()["detail"]["message"]


def test_failing_scan_marks_job_error(tmp_path, monkeypatch):
    def crash(*args, **kwargs):
        raise RuntimeError("motor çöktü")

    monkeypatch.setattr(web_app, "resolve_target", fake_target)
    client = TestClient(web_app.create_app(tmp_path, session_token=TOKEN, allowed_hosts=HOSTS, runner=crash),
                        headers={"X-Sefalet-Token": TOKEN})
    job_id = client.post("/api/scans", json={"target": "localhost", "mode": "lab"}).json()["job_id"]
    job = wait_job(client, job_id)
    assert job["status"] == "error"
    assert "motor çöktü" in job["error"]


def test_unknown_job(setup):
    client, *_ = setup
    assert client.get("/api/jobs/yok").status_code == 404
