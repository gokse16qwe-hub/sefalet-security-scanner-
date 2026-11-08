"""headers_check.py için testler."""

import pytest
import requests
import responses

from sefalet.checks.headers_check import (
    analyze_headers,
    check_headers,
    parse_set_cookie,
)
from sefalet.models import CheckStatus, Confidence, Severity
from sefalet.target import Target

# Tüm önerilen başlıkları içeren "iyi" yapılandırma
GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}
GOOD_COOKIE = "oturum=abc; Path=/; Secure; HttpOnly; SameSite=Lax"


def ids(findings):
    return sorted(f.id for f in findings)


def with_headers(**changes):
    """GOOD_HEADERS'ın bir kopyasını değiştirir. Değer None ise başlık silinir."""
    headers = dict(GOOD_HEADERS)
    for key, value in changes.items():
        key = key.replace("_", "-")
        if value is None:
            headers.pop(key, None)
        else:
            headers[key] = value
    return headers


# --- analyze_headers -----------------------------------------------------


def test_good_configuration_has_no_findings():
    assert analyze_headers(GOOD_HEADERS, set_cookies=[GOOD_COOKIE]) == []


def test_empty_headers_https():
    found = ids(analyze_headers({}, is_https=True))
    assert found == ["HDR-001", "HDR-004", "HDR-006", "HDR-007", "HDR-008", "HDR-009"]


def test_hsts_not_checked_over_http():
    assert "HDR-001" not in ids(analyze_headers({}, is_https=False))


def test_header_names_are_case_insensitive():
    lower = {k.lower(): v for k, v in GOOD_HEADERS.items()}
    assert analyze_headers(lower) == []


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("max-age=300; includeSubDomains", ["HDR-002"]),
        ("max-age=0", ["HDR-002", "HDR-003"]),
        ("max-age=31536000", ["HDR-003"]),
        ('max-age="31536000"; includesubdomains; preload', []),
        ("includeSubDomains", ["HDR-002"]),  # max-age yok → 0 kabul edilir
    ],
)
def test_hsts_variants(value, expected):
    found = ids(analyze_headers(with_headers(Strict_Transport_Security=value)))
    assert found == expected


@pytest.mark.parametrize(
    ("csp", "expected"),
    [
        ("default-src 'self' 'unsafe-inline'; frame-ancestors 'none'", ["HDR-005"]),
        ("script-src 'self' 'unsafe-eval'; frame-ancestors 'none'", ["HDR-005"]),
        # nonce varsa 'unsafe-inline' tarayıcılarca yok sayılır
        ("script-src 'nonce-abc' 'unsafe-inline'; frame-ancestors 'none'", []),
        # script-src, default-src'den önceliklidir
        ("default-src 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'", []),
        ("img-src *; frame-ancestors 'none'", ["HDR-005"]),
    ],
)
def test_csp_weaknesses(csp, expected):
    assert ids(analyze_headers(with_headers(Content_Security_Policy=csp))) == expected


def test_missing_csp_is_medium_and_confirmed():
    findings = analyze_headers(with_headers(Content_Security_Policy=None, X_Frame_Options="DENY"))
    assert ids(findings) == ["HDR-004"]
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].confidence is Confidence.CONFIRMED


def test_x_frame_options_satisfies_clickjacking_check():
    headers = with_headers(Content_Security_Policy="default-src 'self'", X_Frame_Options="DENY")
    assert ids(analyze_headers(headers)) == []


def test_clickjacking_finding_without_xfo_or_frame_ancestors():
    headers = with_headers(Content_Security_Policy="default-src 'self'")
    assert ids(analyze_headers(headers)) == ["HDR-006"]


def test_x_content_type_options_wrong_value():
    assert ids(analyze_headers(with_headers(X_Content_Type_Options="sniff"))) == ["HDR-007"]


@pytest.mark.parametrize(("server", "flag"), [("nginx/1.18.0", True), ("Apache/2.4.41 (Ubuntu)", True),
                                               ("nginx", False), ("cloudflare", False)])
def test_server_version_disclosure(server, flag):
    found = ids(analyze_headers(with_headers(Server=server)))
    assert ("HDR-011" in found) is flag


def test_powered_by_disclosure():
    findings = analyze_headers(with_headers(X_Powered_By="PHP/8.1.2"))
    assert ids(findings) == ["HDR-012"]
    assert "PHP/8.1.2" in findings[0].evidence


def test_cors_wildcard_with_credentials_is_probable():
    findings = analyze_headers(with_headers(Access_Control_Allow_Origin="*",
                                            Access_Control_Allow_Credentials="true"))
    assert ids(findings) == ["HDR-017"]
    assert findings[0].confidence is Confidence.PROBABLE


def test_cors_wildcard_alone_is_not_reported():
    assert analyze_headers(with_headers(Access_Control_Allow_Origin="*")) == []


# --- Çerezler ------------------------------------------------------------


def test_parse_set_cookie():
    cookie = parse_set_cookie("oturum=a=b; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert cookie.name == "oturum"
    assert cookie.attributes == {"path", "secure", "httponly", "samesite"}


@pytest.mark.parametrize("bad", ["", "sadece-metin", "=deger; Secure"])
def test_parse_invalid_cookie(bad):
    assert parse_set_cookie(bad) is None


def test_insecure_cookies():
    cookies = ["oturum=1; Path=/", "tema=koyu; Secure; HttpOnly; SameSite=Lax",
               "sepet=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure"]
    findings = {f.id: f for f in analyze_headers(GOOD_HEADERS, set_cookies=cookies)}
    assert sorted(findings) == ["HDR-013", "HDR-014", "HDR-015"]
    assert "oturum" in findings["HDR-013"].evidence
    assert "sepet" not in findings["HDR-013"].evidence
    assert "oturum, sepet" in findings["HDR-014"].evidence
    # HttpOnly eksikliği, çerezin amacı bilinmediği için "olası"
    assert findings["HDR-014"].confidence is Confidence.PROBABLE


def test_secure_flag_not_required_over_http():
    found = ids(analyze_headers(GOOD_HEADERS, set_cookies=["a=1; HttpOnly; SameSite=Lax"],
                                is_https=False))
    assert found == []


def test_url_appears_in_evidence():
    findings = analyze_headers({}, url="https://ornek.com/")
    assert all("https://ornek.com/" in f.evidence for f in findings)


# --- check_headers (ağ, responses ile taklit) ----------------------------

BASE = "https://ornek.com/"
HTTP_BASE = "http://ornek.com/"


def make_target(**overrides):
    data = {"original": "ornek.com", "scheme": "https", "hostname": "ornek.com",
            "port": 443, "is_ip": False, "ip_addresses": ("93.184.216.34",)}
    data.update(overrides)
    return Target(**data)


def https_redirect():
    responses.get(HTTP_BASE, status=301, headers={"Location": BASE})


@responses.activate
def test_check_good_site():
    responses.get(BASE, headers={**GOOD_HEADERS, "Set-Cookie": GOOD_COOKIE})
    https_redirect()
    result = check_headers(make_target())
    assert result.status is CheckStatus.COMPLETED
    assert result.findings == []
    assert result.check_name == "headers"


@responses.activate
def test_check_reads_multiple_set_cookie_headers():
    responses.get(BASE, headers=[*GOOD_HEADERS.items(),
                                 ("Set-Cookie", GOOD_COOKIE),
                                 ("Set-Cookie", "izleme=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT")])
    https_redirect()
    findings = check_headers(make_target()).findings
    assert ids(findings) == ["HDR-013", "HDR-014", "HDR-015"]
    assert all("izleme" in f.evidence and "oturum" not in f.evidence for f in findings)


@responses.activate
def test_check_follows_same_site_redirect():
    responses.get(BASE, status=301, headers={"Location": "https://www.ornek.com/anasayfa"})
    responses.get("https://www.ornek.com/anasayfa", headers=GOOD_HEADERS)
    https_redirect()
    result = check_headers(make_target())
    assert result.findings == []
    assert len(responses.calls) == 3


@responses.activate
def test_check_does_not_follow_offsite_redirect():
    responses.get(BASE, status=302, headers={**GOOD_HEADERS, "Location": "http://169.254.169.254/"})
    https_redirect()
    result = check_headers(make_target())
    assert ids(result.findings) == ["HDR-016"]
    assert not any("169.254" in c.request.url for c in responses.calls)


@responses.activate
def test_check_https_to_http_downgrade():
    responses.get(BASE, status=301, headers={"Location": "http://ornek.com/eski"})
    responses.get("http://ornek.com/eski", headers=GOOD_HEADERS)
    https_redirect()
    found = ids(check_headers(make_target()).findings)
    assert "HDR-018" in found
    assert "HDR-001" not in found  # son yanıt HTTP: HSTS değerlendirilmez


@responses.activate
def test_check_redirect_loop_is_bounded():
    responses.get(BASE, status=302, headers={"Location": BASE})
    https_redirect()
    result = check_headers(make_target())
    assert result.status is CheckStatus.COMPLETED
    assert len(responses.calls) <= 8


@responses.activate
def test_check_http_not_redirected():
    responses.get(BASE, headers=GOOD_HEADERS)
    responses.get(HTTP_BASE, status=200)
    findings = check_headers(make_target()).findings
    assert ids(findings) == ["HDR-010"]
    assert "HTTP 200" in findings[0].evidence


@responses.activate
def test_check_http_port_closed_is_fine():
    responses.get(BASE, headers=GOOD_HEADERS)
    responses.get(HTTP_BASE, body=requests.exceptions.ConnectionError("kapalı"))
    assert check_headers(make_target()).findings == []


@responses.activate
def test_check_http_redirect_skipped_for_custom_port():
    url = "https://ornek.com:8443/"
    responses.get(url, headers=GOOD_HEADERS)
    result = check_headers(make_target(port=8443))
    assert result.findings == []
    assert len(responses.calls) == 1


@responses.activate
def test_check_error_status_is_noted():
    responses.get(BASE, status=403, headers=GOOD_HEADERS)
    https_redirect()
    result = check_headers(make_target())
    assert result.status is CheckStatus.COMPLETED
    assert "HTTP 403" in result.message


@responses.activate
@pytest.mark.parametrize(
    ("exc", "message_part"),
    [
        (requests.exceptions.SSLError("x"), "sertifikası"),
        (requests.exceptions.ReadTimeout("x"), "zamanında"),
        (requests.exceptions.ConnectionError("x"), "bağlanılamadı"),
        (requests.exceptions.InvalidURL("x"), "başarısız"),
    ],
)
def test_check_network_errors_become_error_result(exc, message_part):
    responses.get(BASE, body=exc)
    result = check_headers(make_target())
    assert result.status is CheckStatus.ERROR
    assert message_part in result.message
    assert result.findings == []


@responses.activate
def test_public_target_verifies_certificates():
    responses.get(BASE, headers=GOOD_HEADERS)
    https_redirect()
    check_headers(make_target())
    # requests, ortamda REQUESTS_CA_BUNDLE varsa True yerine CA dosya yolunu koyar
    assert responses.calls[0].request.req_kwargs["verify"] not in (False, None)


@responses.activate
def test_lab_mode_skips_certificate_verification_and_says_so():
    url = "https://localhost:18443/"
    responses.get(url, headers=GOOD_HEADERS)
    target = make_target(hostname="localhost", port=18443, ip_addresses=("127.0.0.1",), lab_mode=True)
    result = check_headers(target)
    assert result.status is CheckStatus.COMPLETED
    assert responses.calls[0].request.req_kwargs["verify"] is False
    assert "Lab modu" in result.message
