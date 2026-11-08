"""Komut satırı arayüzü.

Kullanım örnekleri:
    sefalet token ornek.com                  # Doğrulama talimatı al
    sefalet scan ornek.com                   # DNS TXT veya HTTP dosyasıyla doğrulayıp tara
    sefalet scan ornek.com --declare "Ad Soyad"   # İzin beyanıyla (yalnızca pasif)
    sefalet scan localhost:8443 --lab        # Kendi yerel test ortamın
    sefalet scan ornek.com --enable-port-scan     # + sınırlı port kontrolü

Çıkış kodları (betiklerde kullanmak için):
    0 başarılı · 2 geçersiz girdi · 3 yetki doğrulanamadı · 4 rapor yazılamadı
"""

from __future__ import annotations

import logging
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from sefalet import __version__
from sefalet.authorization import (
    DECLARATION_TEXT,
    AuthorizationError,
    TokenStore,
    create_declaration,
    create_lab_authorization,
    verification_instructions,
    verify_dns_txt,
    verify_http_file,
)
from sefalet.models import AuthorizationInfo, CheckStatus, ScanResult, Severity
from sefalet.reporting.json_report import default_filename, write_json
from sefalet.scanner import CHECK_LABELS_TR, run_scan
from sefalet.target import Target, TargetError, parse_target, resolve_target

EXIT_INPUT = 2
EXIT_AUTH = 3
EXIT_OUTPUT = 4

app = typer.Typer(
    help="Sefalet Security Scanner: web sitesi güvenlik yapılandırma analizi.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err = Console(stderr=True)

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}
STATUS_STYLES = {CheckStatus.COMPLETED: "green", CheckStatus.ERROR: "red", CheckStatus.SKIPPED: "dim"}


class VerifyMethod(StrEnum):
    auto = "auto"
    dns = "dns"
    http = "http"


def _fail(message: str, code: int) -> typer.Exit:
    err.print(f"[bold red]Hata:[/] {escape(message)}")
    return typer.Exit(code)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"Sefalet Security Scanner {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[bool, typer.Option("--version", callback=_version_callback, is_eager=True,
                                          help="Sürümü göster.")] = False,
    verbose: Annotated[bool, typer.Option("-v", "--verbose", help="Ayrıntılı log çıktısı.")] = False,
) -> None:
    logging.basicConfig(level=logging.INFO if verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")


# ---------------------------------------------------------------------------
# token
# ---------------------------------------------------------------------------


@app.command()
def token(
    target: Annotated[str, typer.Argument(help="Alan adı, ör. ornek.com")],
    regenerate: Annotated[bool, typer.Option("--yenile", help="Yeni token üret (eskisi geçersiz olur).")] = False,
    token_file: Annotated[Path | None, typer.Option(hidden=True)] = None,
) -> None:
    """Tarama izni doğrulaması için token ve talimat göster."""
    try:
        parsed = parse_target(target)
        store = TokenStore(token_file)
        value = store.regenerate(parsed.hostname) if regenerate else store.get_or_create(parsed.hostname)
    except TargetError as exc:
        raise _fail(str(exc), EXIT_INPUT) from None
    except AuthorizationError as exc:
        raise _fail(str(exc), EXIT_AUTH) from None
    console.print(escape(verification_instructions(parsed.hostname, value)))
    console.print(f"Kaydı ekledikten sonra: [bold]sefalet scan {escape(parsed.hostname)}[/]")


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def _authorize(target: Target, *, lab: bool, declare: str | None, accept: bool,
               verify: VerifyMethod, token_file: Path | None) -> AuthorizationInfo:
    """Seçilen yönteme göre tarama iznini doğrular. Başarısızsa typer.Exit fırlatır."""
    if lab:
        return create_lab_authorization(target)

    if declare is not None:
        console.print(f"\n[bold]İzin beyanı[/]\n{DECLARATION_TEXT}\n")
        if not accept:
            accept = typer.confirm("Bu beyanı kabul ediyor musunuz?", default=False)
        return create_declaration(target, declare, accept)

    store = TokenStore(token_file)
    value = store.get(target.hostname)
    if not value:
        value = store.get_or_create(target.hostname)
        err.print("[yellow]Bu hedef için henüz doğrulama yapılmamış.[/]\n")
        err.print(escape(verification_instructions(target.hostname, value)))
        err.print("Teknik doğrulama yapamıyorsanız ve hedefin sahibi veya yetkilisiyseniz "
                  "--declare \"Ad Soyad\" ile izin beyanı verebilirsiniz (yalnızca pasif kontroller).")
        raise typer.Exit(EXIT_AUTH)

    methods = {
        VerifyMethod.dns: [verify_dns_txt],
        VerifyMethod.http: [verify_http_file],
        VerifyMethod.auto: [verify_dns_txt, verify_http_file],
    }[verify]
    errors = []
    for method in methods:
        try:
            return method(target, value)
        except AuthorizationError as exc:
            errors.append(str(exc))
    for message in errors:
        err.print(f"[red]•[/] {escape(message)}")
    err.print()
    err.print(escape(verification_instructions(target.hostname, value)))
    raise typer.Exit(EXIT_AUTH)


def _print_summary(scan: ScanResult) -> None:
    risk = scan.risk
    console.print()
    console.rule(f"[bold]{escape(scan.target)}[/]")
    if risk:
        console.print(f"Genel not: [bold]{risk.grade}[/]   Puan: [bold]{risk.score}[/]/100")
        console.print(escape(risk.summary_tr))

    checks = Table(title="Kontroller", show_lines=False)
    for col in ("Kontrol", "Durum", "Bulgu", "Not"):
        checks.add_column(col)
    for c in scan.checks:
        checks.add_row(CHECK_LABELS_TR.get(c.check_name, c.check_name),
                       f"[{STATUS_STYLES[c.status]}]{c.status.label_tr}[/]",
                       str(len(c.findings)), escape(c.message or ""))
    console.print(checks)

    findings = scan.all_findings()
    if findings:
        table = Table(title="Bulgular")
        for col in ("Kod", "Risk", "Güven", "Bulgu"):
            table.add_column(col)
        for f in findings:
            table.add_row(f.id, f"[{SEVERITY_STYLES[f.severity]}]{f.severity.label_tr}[/]",
                          f.confidence.label_tr, escape(f.title))
        console.print(table)


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Hedef: alan adı, URL veya IP (ör. ornek.com)")],
    verify: Annotated[VerifyMethod, typer.Option(help="Teknik doğrulama yöntemi.")] = VerifyMethod.auto,
    declare: Annotated[str | None, typer.Option(
        "--declare", help="İzin beyanı veren kişinin adı soyadı (yalnızca pasif kontroller).")] = None,
    accept_declaration: Annotated[bool, typer.Option(
        "--accept-declaration", help="Beyan metnini onay sorusu sormadan kabul et.")] = False,
    lab: Annotated[bool, typer.Option(
        "--lab", help="Yerel test ortamı: yalnızca özel/yerel IP'ler taranabilir.")] = False,
    enable_port_scan: Annotated[bool, typer.Option(
        "--enable-port-scan", help="Sınırlı TCP port kontrolünü etkinleştir (teknik doğrulama gerekir).")] = False,
    output_dir: Annotated[Path, typer.Option("--output-dir", "-o", help="Raporların yazılacağı klasör.")] = Path("reports"),
    pdf: Annotated[bool, typer.Option("--pdf/--no-pdf", help="PDF rapor üret.")] = True,
    json_out: Annotated[bool, typer.Option("--json/--no-json", help="JSON çıktı üret.")] = True,
    token_file: Annotated[Path | None, typer.Option(hidden=True)] = None,
) -> None:
    """Hedefin güvenlik yapılandırmasını tara ve rapor üret."""
    if lab and declare is not None:
        raise _fail("--lab ve --declare birlikte kullanılamaz.", EXIT_INPUT)
    if enable_port_scan and declare is not None:
        raise _fail("Port kontrolü için teknik doğrulama gerekir; izin beyanı yeterli değildir. "
                    "--declare olmadan DNS TXT veya HTTP dosyası doğrulaması kullanın.", EXIT_AUTH)

    # 1) Hedef
    try:
        resolved = resolve_target(target, lab_mode=lab)
    except TargetError as exc:
        raise _fail(str(exc), EXIT_INPUT) from None

    # 2) Yetki
    try:
        authorization = _authorize(resolved, lab=lab, declare=declare, accept=accept_declaration,
                                   verify=verify, token_file=token_file)
    except AuthorizationError as exc:
        raise _fail(str(exc), EXIT_AUTH) from None
    console.print(f"[green]✓[/] Tarama izni: {escape(authorization.method.label_tr)}")

    # 3) Tarama
    with console.status("Taranıyor...") as status:
        def progress(name: str, state: str) -> None:
            if state == "başladı":
                status.update(f"{CHECK_LABELS_TR.get(name, name)} kontrol ediliyor...")

        try:
            result = run_scan(resolved, authorization, enable_port_scan=enable_port_scan,
                              progress=progress)
        except AuthorizationError as exc:
            raise _fail(str(exc), EXIT_AUTH) from None

    _print_summary(result)

    # 4) Raporlar
    written = []
    try:
        if json_out:
            written.append(write_json(result, output_dir / default_filename(result, "json")))
        if pdf:
            from sefalet.reporting.pdf_report import write_pdf  # ReportLab'i yalnızca gerektiğinde yükle

            written.append(write_pdf(result, output_dir / default_filename(result, "pdf")))
    except OSError as exc:
        raise _fail(f"Rapor yazılamadı: {exc}", EXIT_OUTPUT) from None
    for path in written:
        console.print(f"[green]✓[/] Rapor: {escape(str(path))}")


@app.command()
def gui(
    port: Annotated[int, typer.Option(help="Panelin çalışacağı port.")] = 8765,
    no_browser: Annotated[bool, typer.Option("--no-browser", help="Tarayıcıyı otomatik açma.")] = False,
) -> None:
    """Neon temalı yerel web panelini başlat (yalnızca bu bilgisayardan erişilir)."""
    import threading
    import webbrowser

    import uvicorn

    from sefalet.web.app import create_app

    url = f"http://127.0.0.1:{port}/"
    console.print(f"[bold cyan]Sefalet Console[/] çalışıyor: [link={url}]{url}[/link]")
    console.print("Kapatmak için Ctrl+C. Panel yalnızca bu bilgisayardan erişilebilir.")
    if not no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        # host=127.0.0.1: panel ağdaki diğer cihazlara AÇILMAZ
        uvicorn.run(create_app(), host="127.0.0.1", port=port, log_level="warning")
    except OSError as exc:
        raise _fail(f"Panel başlatılamadı (port {port} kullanımda olabilir): {exc}", EXIT_INPUT) from None


@app.command()
def kontrol() -> None:
    """Aracın düzgün kurulup kurulmadığını kontrol eder (sorun gidermenin ilk adımı).

    Bir şey çalışmıyorsa önce bu komutu çalıştırın: Python sürümü, sanal ortam,
    kütüphaneler, fontlar ve yazma izni tek tek kontrol edilir ve ne yapmanız
    gerektiği yazılır.
    """
    import importlib
    import sys

    problems = 0

    def ok(label: str) -> None:
        console.print(f"  [green]✓[/] {label}")

    def fail(label: str, fix: str) -> None:
        nonlocal problems
        problems += 1
        console.print(f"  [bold red]✗[/] {label}")
        console.print(f"     [yellow]Çözüm:[/] {escape(fix)}")

    console.print("[bold]Sefalet Security Scanner — kurulum kontrolü[/]\n")

    # 1) Python sürümü
    v = sys.version_info
    if v >= (3, 11):
        ok(f"Python sürümü: {v.major}.{v.minor}.{v.micro}")
    else:
        fail(f"Python sürümü çok eski: {v.major}.{v.minor}",
             "Python 3.11 veya üzeri gerekir. Kali'de: sudo apt install python3")

    # 2) Sanal ortam
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    if in_venv:
        ok("Sanal ortam etkin (.venv)")
    else:
        fail("Sanal ortam etkin değil",
             "Şunu çalıştırın: source .venv/bin/activate  (yoksa önce: python3 -m venv .venv)")

    # 3) Kütüphaneler
    libs = {"requests": "requests", "dns": "dnspython", "cryptography": "cryptography",
            "reportlab": "reportlab", "typer": "typer", "rich": "rich",
            "fastapi": "fastapi", "uvicorn": "uvicorn"}
    missing = []
    for module, package in libs.items():
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(package)
    if not missing:
        ok(f"Gerekli kütüphaneler kurulu ({len(libs)} paket)")
    else:
        fail(f"Eksik kütüphaneler: {', '.join(missing)}",
             'Şunu çalıştırın: pip install -e ".[dev]"')

    # 4) PDF fontları
    from sefalet.reporting.pdf_report import FONT_DIR

    fonts = [FONT_DIR / "DejaVuSans.ttf", FONT_DIR / "DejaVuSans-Bold.ttf"]
    if all(f.exists() for f in fonts):
        ok("Türkçe PDF fontları mevcut")
    else:
        fail("PDF fontları eksik (Türkçe karakterler bozuk çıkar)",
             "Depoyu eksiksiz indirdiğinizden emin olun; git clone'u tekrar deneyin.")

    # 5) Rapor klasörüne yazma izni
    try:
        test_dir = Path("reports")
        test_dir.mkdir(exist_ok=True)
        probe = test_dir / ".sefalet_yazma_testi"
        probe.write_text("x", encoding="utf-8")
        probe.unlink()
        ok("Rapor klasörüne yazılabiliyor")
    except OSError as exc:
        fail(f"Rapor klasörüne yazılamıyor: {exc}",
             "Yazma izniniz olan bir klasörde çalıştırın veya -o ile başka klasör verin.")

    console.print()
    if problems == 0:
        console.print("[bold green]Her şey yolunda.[/] Aracı kullanabilirsiniz:")
        console.print("  sefalet token ornek.com   ·   sefalet scan ornek.com   ·   sefalet gui")
    else:
        console.print(f"[bold red]{problems} sorun bulundu.[/] Yukarıdaki çözümleri uygulayıp "
                      "'sefalet kontrol' komutunu tekrar çalıştırın.")
        raise typer.Exit(EXIT_INPUT)


if __name__ == "__main__":
    app()
