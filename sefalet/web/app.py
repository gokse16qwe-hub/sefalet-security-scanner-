"""Yerel web paneli API'si (FastAPI).

Güvenlik önlemleri (panel yalnızca bu bilgisayardan kullanılmalı):
  1. Sunucu yalnızca 127.0.0.1'i dinler (cli.py).
  2. Host başlığı kontrolü: İstek "localhost"/"127.0.0.1" dışında bir adla
     gelirse reddedilir. Bu, kötü niyetli bir sitenin DNS rebinding ile
     tarayıcınız üzerinden panele erişmesini engeller.
  3. Oturum anahtarı: Değişiklik yapan istekler (tarama başlatma, silme)
     her açılışta rastgele üretilen bir anahtarı "X-Sefalet-Token"
     başlığında taşımalıdır. Başka bir site bu anahtarı bilemez (CSRF koruması).

Uç noktalar:
    GET    /                       → Panel arayüzü
    GET    /api/summary            → Panel özeti
    GET    /api/scans              → Tarama listesi
    GET    /api/scans/{id}         → Tarama ayrıntısı
    GET    /api/scans/{id}/pdf     → PDF rapor indir
    GET    /api/scans/{id}/json    → JSON indir
    DELETE /api/scans/{id}         → Taramayı sil
    POST   /api/token              → Doğrulama talimatı
    POST   /api/scans              → Tarama başlat (iş kimliği döner)
    GET    /api/jobs/{id}          → Tarama işinin durumu
"""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from sefalet import __version__, config
from sefalet.authorization import (
    DECLARATION_TEXT,
    AuthorizationError,
    TokenStore,
    create_declaration,
    create_lab_authorization,
    expected_value,
    verification_instructions,
    verify_dns_txt,
    verify_http_file,
)
from sefalet.models import AuthorizationInfo, CheckStatus, ScanResult, Severity
from sefalet.reporting.json_report import default_filename
from sefalet.scanner import CHECK_LABELS_TR
from sefalet.target import TargetError, parse_target, resolve_target
from sefalet.web.history import ScanHistory, is_valid_scan_id
from sefalet.web.jobs import JobManager, TooManyJobs

STATIC_DIR = Path(__file__).parent / "static"
TOKEN_HEADER = "X-Sefalet-Token"
DEFAULT_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]"})


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=300)
    mode: Literal["verify", "declaration", "lab"] = "verify"
    verify_method: Literal["auto", "dns", "http"] = "auto"
    declarant: str | None = Field(default=None, max_length=200)
    accept_declaration: bool = False
    enable_port_scan: bool = False


class TokenRequest(BaseModel):
    target: str = Field(min_length=1, max_length=300)
    regenerate: bool = False


def _host_name(header: str) -> str:
    """Host başlığından port numarasını atar: "localhost:8765" → "localhost"."""
    if header.startswith("["):  # IPv6: "[::1]:8765"
        return header.split("]", 1)[0] + "]"
    return header.split(":", 1)[0].lower()


def _error(status: int, message: str, **extra) -> HTTPException:
    return HTTPException(status_code=status, detail={"message": message, **extra})


def _scan_summary(scan: ScanResult) -> dict:
    """Listelerde gösterilecek kısa tarama bilgisi."""
    risk = scan.risk
    return {
        "scan_id": scan.scan_id,
        "target": scan.target,
        "started_at": scan.started_at.isoformat(),
        "grade": risk.grade if risk else None,
        "score": risk.score if risk else None,
        "complete": risk.complete if risk else False,
        "counts": {s.value: n for s, n in scan.severity_counts().items()},
        "auth_method": scan.authorization.method.value,
        "auth_label": scan.authorization.method.label_tr,
        "checks": [{"name": c.check_name, "status": c.status.value, "findings": len(c.findings)}
                   for c in scan.checks],
    }


def _ssl_days_left(scan: ScanResult) -> int | None:
    for check in scan.checks:
        if check.check_name == "tls" and check.status is CheckStatus.COMPLETED:
            value = check.details.get("days_left")
            return value if isinstance(value, int) else None
    return None


def create_app(
    data_dir: Path | None = None,
    *,
    session_token: str | None = None,
    allowed_hosts: frozenset[str] = DEFAULT_ALLOWED_HOSTS,
    runner=None,
) -> FastAPI:
    """Panel uygulamasını oluşturur.

    Args:
        data_dir: Tarama geçmişi ve token'ların saklanacağı klasör.
        session_token: Oturum anahtarı (verilmezse rastgele üretilir).
        allowed_hosts: Kabul edilen Host başlıkları (testlerde değiştirilir).
        runner: Tarama fonksiyonu (testlerde sahtesi verilir).
    """
    data_dir = Path(data_dir or config.DATA_DIR)
    token = session_token or secrets.token_urlsafe(32)
    history = ScanHistory(data_dir / "scans")
    token_store = TokenStore(data_dir / "verifications.json")
    jobs = JobManager(history, **({"runner": runner} if runner else {}))
    pdf_cache = data_dir / "pdf"

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        jobs.shutdown()  # Panel kapanırken bekleyen taramaları iptal et

    app = FastAPI(title="Sefalet Security Scanner", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.session_token = token
    app.state.jobs = jobs

    @app.middleware("http")
    async def security_guard(request: Request, call_next):
        if _host_name(request.headers.get("host", "")) not in allowed_hosts:
            return JSONResponse({"detail": {"message": "Geçersiz Host başlığı."}}, status_code=403)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            sent = request.headers.get(TOKEN_HEADER, "")
            if not secrets.compare_digest(sent.encode(), token.encode()):
                return JSONResponse({"detail": {"message": "Oturum anahtarı geçersiz."}},
                                    status_code=403)
        response: Response = await call_next(request)
        # Panelin başka sitelerin içine gömülmesini engelle; kendi kurallarımızı uygulayalım
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        return response

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    # --- Sayfa ----------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
        html = html.replace("__SESSION_TOKEN__", token).replace("__VERSION__", __version__)
        return HTMLResponse(html, headers={"Cache-Control": "no-store"})

    # --- Okuma ----------------------------------------------------------

    @app.get("/api/meta")
    def meta() -> dict:
        return {"version": __version__, "declaration_text": DECLARATION_TEXT,
                "check_labels": CHECK_LABELS_TR,
                "severities": [{"value": s.value, "label": s.label_tr} for s in Severity]}

    @app.get("/api/summary")
    def summary() -> dict:
        scans = history.list()
        latest_by_target: dict[str, ScanResult] = {}
        for scan in scans:  # liste en yeniden eskiye sıralı
            latest_by_target.setdefault(scan.target, scan)

        totals = {s.value: 0 for s in Severity}
        for scan in latest_by_target.values():
            for sev, n in scan.severity_counts().items():
                totals[sev.value] += n

        latest = scans[0] if scans else None
        modules = []
        if latest:
            for check in latest.checks:
                modules.append({
                    "name": check.check_name,
                    "label": CHECK_LABELS_TR.get(check.check_name, check.check_name),
                    "status": check.status.value,
                    "status_label": check.status.label_tr,
                    "findings": len(check.findings),
                    "worst": max((f.severity for f in check.findings), key=lambda s: s.rank,
                                 default=None),
                    "message": check.message,
                })
        return {
            "total_scans": len(scans),
            "targets": len(latest_by_target),
            "active_jobs": jobs.active_count(),
            "totals": totals,
            "latest": _scan_summary(latest) if latest else None,
            # TLS verisi olan en son tarama (son tarama HTTP olabilir)
            "ssl_days_left": next((d for d in map(_ssl_days_left, scans) if d is not None), None),
            "modules": modules,
            "recent": [_scan_summary(s) for s in scans[:6]],
        }

    @app.get("/api/scans")
    def list_scans() -> list[dict]:
        return [_scan_summary(s) for s in history.list()]

    def _load(scan_id: str) -> ScanResult:
        if not is_valid_scan_id(scan_id):
            raise _error(404, "Tarama bulunamadı.")
        try:
            return history.get(scan_id)
        except KeyError:
            raise _error(404, "Tarama bulunamadı.") from None

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str) -> dict:
        scan = _load(scan_id)
        data = scan.model_dump(mode="json")
        data["summary"] = _scan_summary(scan)
        data["findings_sorted"] = [
            {**f.model_dump(mode="json"), "severity_label": f.severity.label_tr,
             "confidence_label": f.confidence.label_tr,
             "check": next(c.check_name for c in scan.checks if f in c.findings)}
            for f in scan.all_findings()
        ]
        return data

    @app.get("/api/scans/{scan_id}/json")
    def download_json(scan_id: str) -> Response:
        scan = _load(scan_id)
        return Response(scan.to_json(), media_type="application/json", headers={
            "Content-Disposition": f'attachment; filename="{default_filename(scan, "json")}"'})

    @app.get("/api/scans/{scan_id}/pdf")
    def download_pdf(scan_id: str) -> FileResponse:
        scan = _load(scan_id)
        from sefalet.reporting.pdf_report import write_pdf  # ReportLab'i gerektiğinde yükle

        path = pdf_cache / f"{scan.scan_id}.pdf"
        if not path.exists():
            try:
                write_pdf(scan, path)
            except OSError as exc:
                raise _error(500, f"PDF oluşturulamadı: {exc}") from None
        return FileResponse(path, media_type="application/pdf",
                            filename=default_filename(scan, "pdf"))

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str) -> dict:
        try:
            return jobs.get(job_id).to_dict()
        except KeyError:
            raise _error(404, "İş bulunamadı.") from None

    # --- Değişiklik -----------------------------------------------------

    @app.delete("/api/scans/{scan_id}")
    def delete_scan(scan_id: str) -> dict:
        _load(scan_id)
        history.delete(scan_id)
        (pdf_cache / f"{scan_id}.pdf").unlink(missing_ok=True)
        return {"deleted": scan_id}

    @app.post("/api/token")
    def token_instructions(req: TokenRequest) -> dict:
        try:
            parsed = parse_target(req.target)
            value = (token_store.regenerate(parsed.hostname) if req.regenerate
                     else token_store.get_or_create(parsed.hostname))
        except TargetError as exc:
            raise _error(400, str(exc)) from None
        except AuthorizationError as exc:
            raise _error(500, str(exc)) from None
        return {
            "hostname": parsed.hostname,
            "display_name": parsed.display_name,
            "dns_name": f"_sefalet-verify.{parsed.hostname}",
            "http_url": f"https://{parsed.hostname}/.well-known/sefalet-verify.txt",
            "value": expected_value(value),
            "instructions": verification_instructions(parsed.hostname, value),
        }

    # Senkron fonksiyon: FastAPI bunu ayrı bir iş parçacığında çalıştırır, böylece
    # DNS/HTTP doğrulaması sırasında panelin geri kalanı donmaz.
    @app.post("/api/scans", status_code=202)
    def start_scan(req: ScanRequest) -> dict:
        if req.mode == "declaration" and req.enable_port_scan:
            raise _error(403, "Port kontrolü için teknik doğrulama gerekir; izin beyanı yeterli değildir.")
        try:
            target = resolve_target(req.target, lab_mode=req.mode == "lab")
        except TargetError as exc:
            raise _error(400, str(exc)) from None

        try:
            authorization = _authorize(target, req)
        except AuthorizationError as exc:
            raise _error(403, str(exc)) from None

        try:
            job = jobs.submit(target, authorization, enable_port_scan=req.enable_port_scan)
        except TooManyJobs:
            raise _error(429, "Aynı anda en fazla 2 tarama çalışabilir. Lütfen bekleyin.") from None
        return {"job_id": job.id, "authorization": authorization.method.label_tr}

    def _authorize(target, req: ScanRequest) -> AuthorizationInfo:
        if req.mode == "lab":
            return create_lab_authorization(target)
        if req.mode == "declaration":
            return create_declaration(target, req.declarant or "", req.accept_declaration)

        value = token_store.get(target.hostname)
        if not value:
            value = token_store.get_or_create(target.hostname)
            raise _error(409, "Bu hedef için henüz doğrulama yapılmamış. Aşağıdaki kayıtlardan birini "
                              "ekleyip tekrar deneyin.",
                         instructions=verification_instructions(target.hostname, value),
                         value=expected_value(value), hostname=target.hostname)
        methods = {"dns": [verify_dns_txt], "http": [verify_http_file],
                   "auto": [verify_dns_txt, verify_http_file]}[req.verify_method]
        errors = []
        for method in methods:
            try:
                return method(target, value)
            except AuthorizationError as exc:
                errors.append(str(exc))
        raise _error(403, "Tarama izni doğrulanamadı.", errors=errors,
                     instructions=verification_instructions(target.hostname, value),
                     value=expected_value(value), hostname=target.hostname)

    return app
