"""dns_check.py için testler. Gerçek DNS yerine sözlük tabanlı sahte çözümleyici kullanılır."""

import dns.exception
import dns.resolver
import pytest

from sefalet.checks.dns_check import analyze_dmarc, analyze_spf, check_dns
from sefalet.models import CheckStatus, Confidence, Severity
from sefalet.target import Target


def ids(findings):
    return sorted(f.id for f in findings)


# --- SPF -----------------------------------------------------------------


def test_spf_good():
    assert analyze_spf("ornek.com", ["google-site-verification=x", "v=spf1 include:_spf.google.com -all"]) == []


def test_spf_softfail_is_acceptable():
    assert analyze_spf("ornek.com", ["v=spf1 mx ~all"]) == []


def test_spf_redirect_without_all_is_acceptable():
    assert analyze_spf("ornek.com", ["v=spf1 redirect=_spf.ornek.com"]) == []


def test_spf_missing():
    findings = analyze_spf("ornek.com", ["baska-kayit"])
    assert ids(findings) == ["DNS-001"]
    assert findings[0].severity is Severity.MEDIUM


def test_spf_multiple():
    assert ids(analyze_spf("ornek.com", ["v=spf1 -all", "V=SPF1 mx -all"])) == ["DNS-002"]


@pytest.mark.parametrize(
    ("record", "severity"),
    [
        ("v=spf1 +all", Severity.HIGH),
        ("v=spf1 a mx all", Severity.HIGH),
        ("v=spf1 ?all", Severity.MEDIUM),
        ("v=spf1 mx", Severity.LOW),
    ],
)
def test_spf_weak_all(record, severity):
    findings = analyze_spf("ornek.com", [record])
    assert ids(findings) == ["DNS-003"]
    assert findings[0].severity is severity


# --- DMARC ---------------------------------------------------------------


@pytest.mark.parametrize("record", ["v=DMARC1; p=reject; rua=mailto:a@ornek.com",
                                    "v=DMARC1;p=quarantine"])
def test_dmarc_good(record):
    assert analyze_dmarc("ornek.com", [record]) == []


def test_dmarc_missing():
    assert ids(analyze_dmarc("ornek.com", [])) == ["DNS-004"]


def test_dmarc_none_policy_is_low():
    findings = analyze_dmarc("ornek.com", ["v=DMARC1; p=none"])
    assert ids(findings) == ["DNS-005"]
    assert findings[0].severity is Severity.LOW


@pytest.mark.parametrize("records", [["v=DMARC1; rua=mailto:a@b.c"], ["v=DMARC1; p=yanlis"]])
def test_dmarc_invalid_policy(records):
    findings = analyze_dmarc("ornek.com", records)
    assert ids(findings) == ["DNS-005"]
    assert findings[0].severity is Severity.MEDIUM


def test_dmarc_multiple():
    assert "Birden fazla" in analyze_dmarc("ornek.com", ["v=DMARC1; p=reject", "v=DMARC1; p=none"])[0].title


# --- check_dns -----------------------------------------------------------

GOOD_ZONE = {
    ("ornek.com", "A"): ["93.184.216.34"],
    ("ornek.com", "AAAA"): [],
    ("ornek.com", "NS"): ["ns1.dns.com.", "ns2.dns.com."],
    ("ornek.com", "MX"): ["10 mail.ornek.com."],
    ("ornek.com", "TXT"): ["v=spf1 mx -all"],
    ("_dmarc.ornek.com", "TXT"): ["v=DMARC1; p=reject"],
    ("ornek.com", "CAA"): ['0 issue "letsencrypt.org"'],
    ("ornek.com", "DS"): ["12345 13 2 ABCDEF"],
}


def fake_resolve(zone):
    """Sözlükte olmayan kayıtlar için NoAnswer, değer istisna ise onu fırlatır."""
    calls = []

    def _resolve(name, rtype):
        calls.append((name, rtype))
        value = zone.get((name, rtype))
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise dns.resolver.NoAnswer()
        return list(value)

    _resolve.calls = calls
    return _resolve


def make_target(hostname="ornek.com", **overrides):
    data = {"original": hostname, "scheme": "https", "hostname": hostname, "port": 443,
            "is_ip": False, "ip_addresses": ("93.184.216.34",)}
    data.update(overrides)
    return Target(**data)


def test_good_zone_has_no_findings():
    result = check_dns(make_target(), resolve=fake_resolve(GOOD_ZONE))
    assert result.status is CheckStatus.COMPLETED
    assert result.findings == []
    assert result.message is None
    assert result.details["dnssec"] is True
    assert result.details["mx"] == ["10 mail.ornek.com."]
    assert result.details["spf"] == ["v=spf1 mx -all"]


def test_empty_zone():
    result = check_dns(make_target(), resolve=fake_resolve({}))
    assert result.status is CheckStatus.COMPLETED
    assert ids(result.findings) == ["DNS-001", "DNS-004", "DNS-006", "DNS-007"]
    dnssec = next(f for f in result.findings if f.id == "DNS-007")
    assert dnssec.confidence is Confidence.INFORMATIONAL


def test_nxdomain_treated_as_no_record():
    zone = {**GOOD_ZONE, ("_dmarc.ornek.com", "TXT"): dns.resolver.NXDOMAIN()}
    assert ids(check_dns(make_target(), resolve=fake_resolve(zone)).findings) == ["DNS-004"]


def test_timeout_does_not_create_missing_finding():
    # DMARC sorgusu zaman aşımına uğradı: "DMARC yok" DENMEMELİ
    zone = {**GOOD_ZONE, ("_dmarc.ornek.com", "TXT"): dns.exception.Timeout()}
    result = check_dns(make_target(), resolve=fake_resolve(zone))
    assert result.status is CheckStatus.COMPLETED
    assert result.findings == []
    assert "_dmarc.ornek.com TXT" in result.message
    assert "varsayılmamalıdır" in result.message


def test_all_queries_failing_is_error():
    def broken(name, rtype):
        raise dns.resolver.NoNameservers()

    result = check_dns(make_target(), resolve=broken)
    assert result.status is CheckStatus.ERROR
    assert result.findings == []


def test_single_nameserver():
    zone = {**GOOD_ZONE, ("ornek.com", "NS"): ["ns1.dns.com."]}
    assert ids(check_dns(make_target(), resolve=fake_resolve(zone)).findings) == ["DNS-009"]


def test_www_uses_parent_for_email_and_caa():
    resolver = fake_resolve({**GOOD_ZONE, ("www.ornek.com", "A"): ["93.184.216.34"]})
    result = check_dns(make_target("www.ornek.com"), resolve=resolver)
    assert result.findings == []
    assert result.details["email_domain"] == "ornek.com"
    assert ("www.ornek.com", "CAA") in resolver.calls  # önce kendisi
    assert ("ornek.com", "CAA") in resolver.calls      # sonra üst alan adı
    assert ("_dmarc.ornek.com", "TXT") in resolver.calls


def test_caa_on_host_stops_search():
    zone = {**GOOD_ZONE, ("www.ornek.com", "CAA"): ['0 issue "digicert.com"']}
    resolver = fake_resolve(zone)
    check_dns(make_target("www.ornek.com"), resolve=resolver)
    assert ("ornek.com", "CAA") not in resolver.calls


def test_ip_target_skipped():
    result = check_dns(make_target("93.184.216.34", is_ip=True), resolve=fake_resolve({}))
    assert result.status is CheckStatus.SKIPPED


def test_details_are_json_serializable():
    import json

    result = check_dns(make_target(), resolve=fake_resolve(GOOD_ZONE))
    json.loads(result.model_dump_json())
