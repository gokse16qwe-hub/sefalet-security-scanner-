"""authorization.py için testler.

- DNS: sahte `lookup` fonksiyonu veriyoruz (gerçek DNS yok).
- HTTP: `responses` kütüphanesi requests çağrılarını yakalayıp
  bizim belirlediğimiz cevabı döndürür (gerçek internet yok).
- Token dosyası: pytest'in `tmp_path` fixture'ı her test için geçici
  bir klasör verir; gerçek ~/.sefalet klasörüne dokunulmaz.
"""

import json
import stat

import dns.exception
import dns.resolver
import pytest
import requests
import responses

from sefalet.authorization import (
    DECLARATION_TEXT,
    MAX_HTTP_FILE_BYTES,
    AuthorizationError,
    TokenStore,
    create_declaration,
    create_lab_authorization,
    ensure_allowed,
    expected_value,
    generate_token,
    verification_instructions,
    verify_dns_txt,
    verify_http_file,
)
from sefalet.models import AuthorizationInfo, AuthorizationMethod
from sefalet.target import Target

TOKEN = "TestToken123"
FILE_URL = "https://ornek.com/.well-known/sefalet-verify.txt"


def make_target(**overrides) -> Target:
    data = {
        "original": "ornek.com",
        "scheme": "https",
        "hostname": "ornek.com",
        "port": 443,
        "is_ip": False,
        "ip_addresses": ("93.184.216.34",),
    }
    data.update(overrides)
    return Target(**data)


# --- Token ---------------------------------------------------------------


def test_tokens_are_random_and_long():
    tokens = {generate_token() for _ in range(50)}
    assert len(tokens) == 50
    assert all(len(t) >= 30 for t in tokens)


def test_expected_value_format():
    assert expected_value("abc") == "sefalet-verify=abc"


def test_store_creates_and_reuses_token(tmp_path):
    store = TokenStore(tmp_path / "v.json")
    first = store.get_or_create("ornek.com")
    assert store.get_or_create("ornek.com") == first
    assert store.get("baska.com") is None


def test_store_regenerate_replaces_token(tmp_path):
    store = TokenStore(tmp_path / "v.json")
    first = store.get_or_create("ornek.com")
    assert store.regenerate("ornek.com") != first


def test_store_persists_to_disk_with_private_permissions(tmp_path):
    path = tmp_path / "alt" / "v.json"  # alt klasör de oluşturulmalı
    token = TokenStore(path).get_or_create("ornek.com")

    assert TokenStore(path).get("ornek.com") == token  # yeni nesne aynı dosyayı okur
    assert json.loads(path.read_text())["ornek.com"]["token"] == token
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize("content", ["{bozuk json", "[1, 2, 3]"])
def test_store_corrupt_file_gives_clear_error(tmp_path, content):
    path = tmp_path / "v.json"
    path.write_text(content)
    with pytest.raises(AuthorizationError, match="Token dosyası"):
        TokenStore(path).get("ornek.com")


def test_instructions_contain_both_methods():
    text = verification_instructions("ornek.com", TOKEN)
    assert "_sefalet-verify.ornek.com" in text
    assert FILE_URL in text
    assert f"sefalet-verify={TOKEN}" in text


# --- DNS TXT -------------------------------------------------------------


def lookup_returning(*records):
    calls = []

    def _lookup(name):
        calls.append(name)
        return list(records)

    _lookup.calls = calls
    return _lookup


def lookup_raising(exc):
    def _lookup(name):
        raise exc

    return _lookup


def test_dns_success():
    lookup = lookup_returning("v=spf1 -all", f"sefalet-verify={TOKEN}")
    info = verify_dns_txt(make_target(), TOKEN, lookup=lookup)
    assert info.method is AuthorizationMethod.DNS_TXT
    assert "_sefalet-verify.ornek.com" in info.details
    assert lookup.calls == ["_sefalet-verify.ornek.com"]


def test_dns_tolerates_surrounding_whitespace():
    info = verify_dns_txt(make_target(), TOKEN, lookup=lookup_returning(f"  sefalet-verify={TOKEN} "))
    assert info.method is AuthorizationMethod.DNS_TXT


@pytest.mark.parametrize(
    "records",
    [
        ["sefalet-verify=YanlisToken"],
        [f"sefalet-verify={TOKEN}ekstra"],   # öneki/eki olan değer kabul edilmez
        [TOKEN],                             # önek olmadan kabul edilmez
        [],
    ],
)
def test_dns_wrong_or_missing_value(records):
    with pytest.raises(AuthorizationError, match="beklenen doğrulama değeri yok"):
        verify_dns_txt(make_target(), TOKEN, lookup=lookup_returning(*records))


@pytest.mark.parametrize(
    ("exc", "message_part"),
    [
        (dns.resolver.NXDOMAIN(), "bulunamadı"),
        (dns.resolver.NoAnswer(), "TXT kaydı yok"),
        (dns.exception.Timeout(), "zaman aşımı"),
        (dns.resolver.NoNameservers(), "başarısız"),
    ],
)
def test_dns_errors_are_translated(exc, message_part):
    with pytest.raises(AuthorizationError, match=message_part):
        verify_dns_txt(make_target(), TOKEN, lookup=lookup_raising(exc))


def test_dns_not_possible_for_ip_target():
    target = make_target(hostname="93.184.216.34", is_ip=True)
    with pytest.raises(AuthorizationError, match="HTTP dosyası"):
        verify_dns_txt(target, TOKEN, lookup=lookup_returning(f"sefalet-verify={TOKEN}"))


# --- HTTP dosyası --------------------------------------------------------


@responses.activate
def test_http_success():
    responses.get(FILE_URL, body=f"sefalet-verify={TOKEN}\n")
    info = verify_http_file(make_target(), TOKEN)
    assert info.method is AuthorizationMethod.HTTP_FILE
    assert FILE_URL in info.details
    # Kendimizi tanıtıyoruz
    assert responses.calls[0].request.headers["User-Agent"].startswith("SefaletScanner/")


@responses.activate
def test_http_token_on_any_line():
    responses.get(FILE_URL, body=f"# yorum\r\nsefalet-verify={TOKEN}\r\n")
    assert verify_http_file(make_target(), TOKEN).method is AuthorizationMethod.HTTP_FILE


@responses.activate
def test_http_uses_custom_port():
    url = "https://ornek.com:8443/.well-known/sefalet-verify.txt"
    responses.get(url, body=f"sefalet-verify={TOKEN}")
    assert verify_http_file(make_target(port=8443), TOKEN)


@responses.activate
def test_http_wrong_content():
    responses.get(FILE_URL, body="sefalet-verify=Baska")
    with pytest.raises(AuthorizationError, match="beklenen doğrulama değeri yok"):
        verify_http_file(make_target(), TOKEN)


@responses.activate
def test_http_redirect_is_not_followed():
    responses.get(FILE_URL, status=302, headers={"Location": "https://saldirgan.com/dosya.txt"})
    with pytest.raises(AuthorizationError, match="yönlendirme"):
        verify_http_file(make_target(), TOKEN)
    assert len(responses.calls) == 1  # ikinci istek yapılmadı


@responses.activate
@pytest.mark.parametrize("status", [404, 403, 500])
def test_http_error_status(status):
    responses.get(FILE_URL, status=status)
    with pytest.raises(AuthorizationError, match=f"HTTP {status}"):
        verify_http_file(make_target(), TOKEN)


@responses.activate
def test_http_reads_limited_bytes():
    # Token, okuma sınırının ötesindeyse bulunmamalı
    body = "x" * (MAX_HTTP_FILE_BYTES + 10) + f"\nsefalet-verify={TOKEN}"
    responses.get(FILE_URL, body=body)
    with pytest.raises(AuthorizationError, match="beklenen doğrulama değeri yok"):
        verify_http_file(make_target(), TOKEN)


@responses.activate
@pytest.mark.parametrize(
    ("exc", "message_part"),
    [
        (requests.exceptions.SSLError("cert"), "sertifika"),
        (requests.exceptions.ConnectTimeout("t"), "zamanında yanıt"),
        (requests.exceptions.ConnectionError("c"), "bağlanılamadı"),
        (requests.exceptions.TooManyRedirects("r"), "okunamadı"),
    ],
)
def test_http_network_errors_are_translated(exc, message_part):
    responses.get(FILE_URL, body=exc)
    with pytest.raises(AuthorizationError, match=message_part):
        verify_http_file(make_target(), TOKEN)


# --- Beyan ---------------------------------------------------------------


def test_declaration_recorded():
    info = create_declaration(make_target(), "Ayşe Yılmaz", accepted=True)
    assert info.method is AuthorizationMethod.DECLARATION
    assert "Ayşe Yılmaz" in info.details
    assert "ornek.com" in info.details
    assert DECLARATION_TEXT in info.details


def test_declaration_requires_acceptance():
    with pytest.raises(AuthorizationError, match="kabul"):
        create_declaration(make_target(), "Ayşe Yılmaz", accepted=False)


@pytest.mark.parametrize("name", ["", "  ", "ab", None])
def test_declaration_requires_name(name):
    with pytest.raises(AuthorizationError, match="adı soyadı"):
        create_declaration(make_target(), name, accepted=True)


# --- Lab -----------------------------------------------------------------


def test_lab_authorization():
    target = make_target(hostname="localhost", ip_addresses=("127.0.0.1",), lab_mode=True)
    info = create_lab_authorization(target)
    assert info.method is AuthorizationMethod.LAB
    assert "127.0.0.1" in info.details


def test_lab_authorization_requires_lab_target():
    with pytest.raises(AuthorizationError, match="lab modunda"):
        create_lab_authorization(make_target())


# --- Politika (1-a) ------------------------------------------------------


@pytest.mark.parametrize("method", list(AuthorizationMethod))
def test_every_method_allows_passive_checks(method):
    ensure_allowed(AuthorizationInfo(method=method, details="x"), active=False)


@pytest.mark.parametrize(
    "method",
    [AuthorizationMethod.DNS_TXT, AuthorizationMethod.HTTP_FILE, AuthorizationMethod.LAB],
)
def test_technical_methods_allow_active_checks(method):
    ensure_allowed(AuthorizationInfo(method=method, details="x"), active=True)


def test_declaration_does_not_allow_active_checks():
    info = AuthorizationInfo(method=AuthorizationMethod.DECLARATION, details="x")
    with pytest.raises(AuthorizationError, match="teknik doğrulama"):
        ensure_allowed(info, active=True)
