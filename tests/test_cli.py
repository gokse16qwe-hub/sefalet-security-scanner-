"""cli.py için testler.

typer'ın CliRunner'ı komutu gerçek terminal açmadan çalıştırır ve
çıktıyı/çıkış kodunu yakalar. Ağ kullanan fonksiyonlar sahteleriyle değiştirilir.
"""

import json

import pytest
from typer.testing import CliRunner

from sefalet import cli
from sefalet.authorization import AuthorizationError, TokenStore
from sefalet.models import (
    AuthorizationInfo,
    AuthorizationMethod,
    CheckResult,
    CheckStatus,
    ScanResult,
)
from sefalet.risk import apply_risk
from sefalet.target import Target, TargetError

runner = CliRunner()


def public_target(raw="ornek.com", lab_mode=False):
    return Target(original=raw, scheme="https", hostname="ornek.com", port=443, is_ip=False,
                  ip_addresses=("93.184.216.34",), lab_mode=lab_mode)


@pytest.fixture
def env(monkeypatch, tmp_path, make_finding):
    """Ağ çağrılarını sahteleriyle değiştirir; çağrıları kaydeder."""
    state = {"scan_calls": []}

    def fake_resolve(raw, lab_mode=False):
        if lab_mode:
            return Target(original=raw, scheme="https", hostname="localhost", port=443,
                          is_ip=False, ip_addresses=("127.0.0.1",), lab_mode=True)
        return public_target(raw)

    def fake_run_scan(target, authorization, *, enable_port_scan=False, progress=None):
        state["scan_calls"].append({"auth": authorization, "ports": enable_port_scan})
        check = CheckResult(check_name="headers", status=CheckStatus.COMPLETED,
                            findings=[make_finding(id="HDR-004", title="CSP yok")])
        return apply_risk(ScanResult(target=target.display_name, authorization=authorization,
                                     checks=[check]))

    monkeypatch.setattr(cli, "resolve_target", fake_resolve)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    state["token_file"] = tmp_path / "tokens.json"
    state["out"] = tmp_path / "out"
    return state


def scan_args(env, *extra):
    return ["scan", "ornek.com", "--token-file", str(env["token_file"]), "-o", str(env["out"]), *extra]


def test_version():
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert "Sefalet Security Scanner" in result.output


def test_token_command_prints_instructions(tmp_path):
    token_file = tmp_path / "t.json"
    result = runner.invoke(cli.app, ["token", "https://Ornek.com/", "--token-file", str(token_file)])
    assert result.exit_code == 0
    value = TokenStore(token_file).get("ornek.com")
    assert f"sefalet-verify={value}" in result.output
    assert "_sefalet-verify.ornek.com" in result.output


def test_token_invalid_target(tmp_path):
    result = runner.invoke(cli.app, ["token", "ftp://x", "--token-file", str(tmp_path / "t.json")])
    assert result.exit_code == cli.EXIT_INPUT


def test_scan_without_verification_shows_instructions(env):
    result = runner.invoke(cli.app, scan_args(env))
    assert result.exit_code == cli.EXIT_AUTH
    assert "henüz doğrulama yapılmamış" in result.output
    assert env["scan_calls"] == []  # tarama başlamadı


def test_scan_with_failed_verification(env, monkeypatch):
    TokenStore(env["token_file"]).get_or_create("ornek.com")

    def fail(target, token):
        raise AuthorizationError("kayıt yok")

    monkeypatch.setattr(cli, "verify_dns_txt", fail)
    monkeypatch.setattr(cli, "verify_http_file", fail)
    result = runner.invoke(cli.app, scan_args(env))
    assert result.exit_code == cli.EXIT_AUTH
    assert result.output.count("kayıt yok") == 2  # iki yöntem de denendi
    assert env["scan_calls"] == []


def test_scan_with_dns_verification_writes_reports(env, monkeypatch):
    TokenStore(env["token_file"]).get_or_create("ornek.com")
    monkeypatch.setattr(cli, "verify_dns_txt", lambda t, v: AuthorizationInfo(
        method=AuthorizationMethod.DNS_TXT, details="TXT bulundu"))
    result = runner.invoke(cli.app, scan_args(env, "--enable-port-scan"))
    assert result.exit_code == 0, result.output
    assert "DNS TXT kaydı ile doğrulandı" in result.output
    assert "HDR-004" in result.output
    assert env["scan_calls"][0]["ports"] is True

    json_files = list(env["out"].glob("*.json"))
    pdf_files = list(env["out"].glob("*.pdf"))
    assert len(json_files) == 1 and len(pdf_files) == 1
    assert json.loads(json_files[0].read_text())["authorization"]["method"] == "dns_txt"


def test_http_only_verification(env, monkeypatch):
    TokenStore(env["token_file"]).get_or_create("ornek.com")
    called = []
    monkeypatch.setattr(cli, "verify_dns_txt", lambda t, v: called.append("dns"))
    monkeypatch.setattr(cli, "verify_http_file", lambda t, v: called.append("http") or AuthorizationInfo(
        method=AuthorizationMethod.HTTP_FILE, details="dosya"))
    result = runner.invoke(cli.app, scan_args(env, "--verify", "http", "--no-pdf"))
    assert result.exit_code == 0, result.output
    assert called == ["http"]


def test_declaration_with_confirmation_prompt(env):
    result = runner.invoke(cli.app, scan_args(env, "--declare", "Ayşe Yılmaz", "--no-pdf"), input="y\n")
    assert result.exit_code == 0, result.output
    assert env["scan_calls"][0]["auth"].method is AuthorizationMethod.DECLARATION
    assert "Ayşe Yılmaz" in env["scan_calls"][0]["auth"].details


def test_declaration_rejected_at_prompt(env):
    result = runner.invoke(cli.app, scan_args(env, "--declare", "Ayşe Yılmaz"), input="n\n")
    assert result.exit_code == cli.EXIT_AUTH
    assert env["scan_calls"] == []


def test_declaration_with_accept_flag(env):
    result = runner.invoke(cli.app, scan_args(env, "--declare", "Ayşe Yılmaz", "--accept-declaration",
                                              "--no-pdf", "--no-json"))
    assert result.exit_code == 0, result.output
    assert not env["out"].exists()  # rapor istenmedi


def test_declaration_cannot_enable_port_scan(env):
    result = runner.invoke(cli.app, scan_args(env, "--declare", "Ayşe", "--accept-declaration",
                                              "--enable-port-scan"))
    assert result.exit_code == cli.EXIT_AUTH
    assert "teknik doğrulama" in result.output
    assert env["scan_calls"] == []


def test_lab_mode(env):
    result = runner.invoke(cli.app, ["scan", "localhost", "--lab", "--no-pdf", "-o", str(env["out"])])
    assert result.exit_code == 0, result.output
    assert env["scan_calls"][0]["auth"].method is AuthorizationMethod.LAB


def test_lab_and_declare_conflict(env):
    result = runner.invoke(cli.app, scan_args(env, "--lab", "--declare", "Ayşe"))
    assert result.exit_code == cli.EXIT_INPUT


def test_invalid_target(env, monkeypatch):
    def bad(raw, lab_mode=False):
        raise TargetError("Hedef özel/iç ağ adresine çözümlendi")

    monkeypatch.setattr(cli, "resolve_target", bad)
    result = runner.invoke(cli.app, scan_args(env))
    assert result.exit_code == cli.EXIT_INPUT
    assert "özel/iç ağ" in result.output


def test_report_write_failure(env, tmp_path):
    blocker = tmp_path / "dosya"
    blocker.write_text("x")  # klasör yerine dosya: içine yazılamaz
    result = runner.invoke(cli.app, ["scan", "localhost", "--lab", "-o", str(blocker / "alt")])
    assert result.exit_code == cli.EXIT_OUTPUT
    assert "Rapor yazılamadı" in result.output


def test_kontrol_passes_in_healthy_env():
    result = runner.invoke(cli.app, ["kontrol"])
    assert result.exit_code == 0
    assert "Her şey yolunda" in result.output
    assert "Python sürümü" in result.output


def test_kontrol_reports_missing_library(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "fastapi":
            raise ImportError("yok")
        return real_import(name, *args, **kwargs)

    # importlib.import_module fastapi'yi bulamasın
    import importlib
    real_module = importlib.import_module

    def fake_module(name, *a, **k):
        if name == "fastapi":
            raise ImportError("yok")
        return real_module(name, *a, **k)

    monkeypatch.setattr(importlib, "import_module", fake_module)
    result = runner.invoke(cli.app, ["kontrol"])
    assert result.exit_code == cli.EXIT_INPUT
    assert "Eksik kütüphaneler" in result.output
    assert "fastapi" in result.output
