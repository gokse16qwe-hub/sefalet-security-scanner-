"""scanner.py için testler. Kontrol modülleri sahte fonksiyonlarla değiştirilir."""

import pytest

from sefalet import scanner
from sefalet.authorization import AuthorizationError
from sefalet.models import (
    AuthorizationInfo,
    AuthorizationMethod,
    CheckResult,
    CheckStatus,
    Severity,
)
from sefalet.target import Target


def make_target():
    return Target(original="ornek.com", scheme="https", hostname="ornek.com", port=443,
                  is_ip=False, ip_addresses=("93.184.216.34",))


@pytest.fixture
def fake_checks(monkeypatch, make_finding):
    """Ağ kullanan gerçek kontrolleri sahteleriyle değiştirir."""
    calls = {}

    def fake(name, findings=()):
        def _check(*args, **kwargs):
            calls[name] = kwargs
            return CheckResult(check_name=name, status=CheckStatus.COMPLETED, findings=list(findings))
        return _check

    monkeypatch.setattr(scanner.tls_check, "check_tls",
                        fake("tls", [make_finding(id="TLS-001", severity=Severity.HIGH)]))
    monkeypatch.setattr(scanner.headers_check, "check_headers",
                        fake("headers", [make_finding(id="HDR-004", severity=Severity.MEDIUM)]))
    monkeypatch.setattr(scanner.dns_check, "check_dns", fake("dns"))
    return calls


def declaration():
    return AuthorizationInfo(method=AuthorizationMethod.DECLARATION, details="Ayşe")


def test_full_scan(fake_checks):
    events = []
    scan = scanner.run_scan(make_target(), declaration(),
                            progress=lambda name, state: events.append((name, state)))
    assert [c.check_name for c in scan.checks] == ["tls", "headers", "dns", "ports"]
    assert scan.checks[3].status is CheckStatus.SKIPPED  # port kontrolü varsayılan kapalı
    assert scan.target == "ornek.com"
    assert scan.target_ips == ["93.184.216.34"]
    assert scan.finished_at >= scan.started_at
    assert scan.risk.grade == "C"  # doğrulanmış Yüksek bulgu → en fazla C
    assert [f.id for f in scan.all_findings()] == ["TLS-001", "HDR-004"]
    assert events[0] == ("tls", "başladı") and events[-1] == ("ports", "bitti")


def test_crashing_check_does_not_stop_scan(fake_checks, monkeypatch):
    def boom(target):
        raise RuntimeError("beklenmeyen")

    monkeypatch.setattr(scanner.dns_check, "check_dns", boom)
    scan = scanner.run_scan(make_target(), declaration())
    dns_result = next(c for c in scan.checks if c.check_name == "dns")
    assert dns_result.status is CheckStatus.ERROR
    assert "RuntimeError" in dns_result.message
    assert scan.risk.complete is False
    assert len(scan.checks) == 4  # sonraki kontroller yine çalıştı


def test_port_scan_with_declaration_rejected_early(fake_checks):
    with pytest.raises(AuthorizationError, match="teknik doğrulama"):
        scanner.run_scan(make_target(), declaration(), enable_port_scan=True)
    assert fake_checks == {}  # hiçbir kontrol başlamadı


def test_port_scan_enabled_is_passed_through(fake_checks, monkeypatch):
    received = {}

    def fake_ports(target, authorization, *, enabled):
        received["enabled"] = enabled
        return CheckResult(check_name="ports", status=CheckStatus.COMPLETED)

    monkeypatch.setattr(scanner.port_check, "check_ports", fake_ports)
    auth = AuthorizationInfo(method=AuthorizationMethod.DNS_TXT, details="x")
    scanner.run_scan(make_target(), auth, enable_port_scan=True)
    assert received == {"enabled": True}
