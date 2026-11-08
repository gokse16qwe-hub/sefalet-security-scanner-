"""target.py için testler.

Gerçek DNS kullanmıyoruz: `fake_resolver` fonksiyonu, socket.getaddrinfo'nun
döndürdüğü biçimde sahte sonuçlar üretir. Böylece testler internet olmadan,
her seferinde aynı sonuçla çalışır.
"""

import socket

import pytest

from sefalet.target import (
    TargetError,
    classify_ip,
    parse_target,
    resolve_target,
)


def fake_resolver(*ips: str):
    """Verilen IP'leri döndüren sahte DNS çözümleyici üretir."""

    def _resolve(host, port, type=None):  # noqa: A002  (getaddrinfo ile aynı imza)
        results = []
        for ip in ips:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            results.append((family, socket.SOCK_STREAM, 6, "", (ip, port)))
        return results

    return _resolve


def failing_resolver(host, port, type=None):  # noqa: A002
    raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")


# --- parse_target: geçerli girdiler --------------------------------------


@pytest.mark.parametrize(
    ("raw", "scheme", "host", "port"),
    [
        ("ornek.com", "https", "ornek.com", 443),
        ("  ornek.com  ", "https", "ornek.com", 443),
        ("Ornek.COM", "https", "ornek.com", 443),
        ("ornek.com.", "https", "ornek.com", 443),
        ("https://ornek.com/giris?x=1#a", "https", "ornek.com", 443),
        ("http://ornek.com", "http", "ornek.com", 80),
        ("HTTPS://alt.ornek.com:8443/", "https", "alt.ornek.com", 8443),
        ("ornek.com:8080", "https", "ornek.com", 8080),
    ],
)
def test_parse_valid_targets(raw, scheme, host, port):
    parsed = parse_target(raw)
    assert (parsed.scheme, parsed.hostname, parsed.port) == (scheme, host, port)
    assert parsed.is_ip is False


def test_parse_turkish_domain_to_punycode():
    parsed = parse_target("şirket.com.tr")
    assert parsed.hostname == "xn--irket-idb.com.tr"
    assert parsed.display_name == "şirket.com.tr"


def test_parse_ipv4():
    parsed = parse_target("93.184.216.34")
    assert parsed.is_ip and parsed.hostname == "93.184.216.34"


def test_parse_ipv6_in_brackets():
    parsed = parse_target("https://[2606:4700:4700:0::1111]:8443/")
    assert parsed.is_ip
    assert parsed.hostname == "2606:4700:4700::1111"  # kısaltılmış biçim
    assert parsed.base_url == "https://[2606:4700:4700::1111]:8443/"


@pytest.mark.parametrize("raw", ["2606:4700:4700::1111", "fe80::1", "::1"])
def test_parse_bare_ipv6_without_brackets(raw):
    parsed = parse_target(raw)
    assert parsed.is_ip
    assert parsed.port == 443


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ornek.com", "https://ornek.com/"),
        ("http://ornek.com", "http://ornek.com/"),
        ("ornek.com:8443", "https://ornek.com:8443/"),
        ("http://ornek.com:443", "http://ornek.com:443/"),
    ],
)
def test_base_url(raw, expected):
    assert parse_target(raw).base_url == expected


# --- parse_target: geçersiz girdiler -------------------------------------


@pytest.mark.parametrize(
    ("raw", "message_part"),
    [
        ("", "boş"),
        ("   ", "boş"),
        ("ftp://ornek.com", "şema"),
        ("javascript:alert(1)", "şema"),
        ("https://kullanici:parola@ornek.com", "parola"),
        ("https://", "bulunamadı"),
        ("ornek.com:99999", "Port"),
        ("ornek.com:abc", "Port"),
        ("ornek.com:0", "Port"),
        ("orn_ek.com", "Geçersiz alan adı"),
        ("-ornek.com", "Geçersiz alan adı"),
        ("ornek..com", "Geçersiz alan adı"),
        ("a" * 64 + ".com", "Geçersiz alan adı"),
        (("a" * 60 + ".") * 5 + "com", "uzunluğu"),
    ],
)
def test_parse_invalid_targets(raw, message_part):
    with pytest.raises(TargetError, match=message_part):
        parse_target(raw)


def test_parse_rejects_non_string():
    with pytest.raises(TargetError):
        parse_target(None)  # type: ignore[arg-type]


# --- classify_ip ----------------------------------------------------------


@pytest.mark.parametrize("ip", ["1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
def test_classify_public(ip):
    assert classify_ip(ip) == "public"


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",          # loopback
        "10.0.0.5",           # özel ağ
        "172.16.3.4",         # özel ağ
        "192.168.1.1",        # ev/ofis ağı
        "169.254.169.254",    # bulut metadata servisi
        "100.64.0.1",         # operatör NAT ağı
        "::1",                # IPv6 loopback
        "fc00::1",            # IPv6 özel ağ
        "fe80::1",            # IPv6 link-local
        "::ffff:127.0.0.1",   # IPv6 içine gömülü loopback
        "::ffff:10.0.0.1",    # IPv6 içine gömülü özel ağ
    ],
)
def test_classify_private(ip):
    assert classify_ip(ip) == "private"


@pytest.mark.parametrize("ip", ["0.0.0.0", "224.0.0.1", "ff02::1", "::"])
def test_classify_forbidden(ip):
    assert classify_ip(ip) == "forbidden"


# --- resolve_target -------------------------------------------------------


def test_resolve_public_target():
    target = resolve_target("ornek.com", resolver=fake_resolver("93.184.216.34"))
    assert target.ip_addresses == ("93.184.216.34",)
    assert target.primary_ip == "93.184.216.34"
    assert target.hostname == "ornek.com"
    assert target.lab_mode is False


def test_resolve_removes_duplicates_and_keeps_order():
    resolver = fake_resolver("1.1.1.1", "2606:4700:4700::1111", "1.1.1.1", "1.0.0.1")
    target = resolve_target("ornek.com", resolver=resolver)
    assert target.ip_addresses == ("1.1.1.1", "2606:4700:4700::1111", "1.0.0.1")


def test_resolve_strips_ipv6_zone_id():
    target = resolve_target("lab.local", lab_mode=True, resolver=fake_resolver("fe80::1%eth0"))
    assert target.ip_addresses == ("fe80::1",)


def test_resolve_ip_literal_does_not_call_dns():
    target = resolve_target("1.1.1.1", resolver=failing_resolver)
    assert target.ip_addresses == ("1.1.1.1",)


@pytest.mark.parametrize("raw", ["127.0.0.1", "http://192.168.1.10", "https://[::1]/"])
def test_private_ip_literal_rejected_without_lab(raw):
    with pytest.raises(TargetError, match="lab modunu"):
        resolve_target(raw, resolver=failing_resolver)


def test_domain_resolving_to_private_ip_rejected():
    # Ör. iç-ağ.ornek.com → 10.0.0.5 (SSRF girişimi)
    with pytest.raises(TargetError, match="özel/iç ağ"):
        resolve_target("ic.ornek.com", resolver=fake_resolver("10.0.0.5"))


def test_metadata_service_rejected():
    with pytest.raises(TargetError):
        resolve_target("http://169.254.169.254/latest/meta-data/")


def test_mixed_public_and_private_answer_rejected():
    # DNS rebinding belirtisi: bir genel, bir özel IP
    with pytest.raises(TargetError, match="10.0.0.5"):
        resolve_target("ornek.com", resolver=fake_resolver("93.184.216.34", "10.0.0.5"))


def test_forbidden_ip_rejected_even_in_lab_mode():
    with pytest.raises(TargetError, match="taranamaz"):
        resolve_target("0.0.0.0", lab_mode=True)


def test_lab_mode_allows_private():
    target = resolve_target("localhost", lab_mode=True, resolver=fake_resolver("127.0.0.1", "::1"))
    assert target.lab_mode is True
    assert target.ip_addresses == ("127.0.0.1", "::1")


def test_lab_mode_rejects_public_target():
    # Lab modu, internetteki bir siteyi doğrulamasız taramak için kullanılamaz
    with pytest.raises(TargetError, match="Lab modu"):
        resolve_target("ornek.com", lab_mode=True, resolver=fake_resolver("93.184.216.34"))


def test_unresolvable_domain():
    with pytest.raises(TargetError, match="çözümlenemedi"):
        resolve_target("olmayan-alan-adi.com", resolver=failing_resolver)


def test_network_error_during_resolution():
    def broken(host, port, type=None):  # noqa: A002
        raise OSError("Network is unreachable")

    with pytest.raises(TargetError, match="ağ hatası"):
        resolve_target("ornek.com", resolver=broken)


def test_empty_resolution_result():
    with pytest.raises(TargetError, match="bulunamadı"):
        resolve_target("ornek.com", resolver=fake_resolver())


def test_invalid_input_fails_before_dns():
    # Ayrıştırma hatası DNS'e hiç gitmeden yakalanmalı
    with pytest.raises(TargetError, match="şema"):
        resolve_target("ftp://ornek.com", resolver=failing_resolver)


@pytest.mark.parametrize(
    ("raw", "label"),
    [("ornek.com", "ornek.com"), ("http://ornek.com", "ornek.com"), ("ornek.com:8443", "ornek.com:8443"),
     ("şirket.com.tr", "şirket.com.tr"), ("https://[::1]:8443", "[::1]:8443")],
)
def test_label(raw, label):
    assert parse_target(raw).label == label
