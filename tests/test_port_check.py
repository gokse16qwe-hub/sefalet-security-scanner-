"""port_check.py için testler.

Gerçek bağlantı testleri için 127.0.0.1 üzerinde geçici dinleyici
soketler açıyoruz; internete çıkılmaz.
"""

import socket

import pytest

from sefalet.checks.port_check import (
    CLOSED,
    DEFAULT_PORTS,
    FILTERED,
    MAX_PORTS,
    OPEN,
    SERVICES,
    analyze_ports,
    check_ports,
    probe_port,
)
from sefalet.models import AuthorizationInfo, AuthorizationMethod, CheckStatus, Confidence, Severity
from sefalet.target import Target


def lab_target():
    return Target(original="localhost", scheme="https", hostname="localhost", port=443,
                  is_ip=False, ip_addresses=("127.0.0.1",), lab_mode=True)


def auth(method):
    return AuthorizationInfo(method=method, details="test")


@pytest.fixture
def listener():
    """Açık port: dinleyen bir soket."""
    sock = socket.create_server(("127.0.0.1", 0))
    yield sock.getsockname()[1]
    sock.close()


@pytest.fixture
def closed_port():
    """Kapalı port: açıp hemen kapattığımız bir soketin numarası."""
    with socket.create_server(("127.0.0.1", 0)) as sock:
        return sock.getsockname()[1]


# --- Sabit liste ---------------------------------------------------------


def test_default_list_is_small_and_fixed():
    assert len(DEFAULT_PORTS) <= MAX_PORTS
    assert 3306 in DEFAULT_PORTS and 23 in DEFAULT_PORTS


def test_finding_ids_are_unique():
    ids = [s.finding_id for s in SERVICES.values() if s.finding_id]
    assert len(ids) == len(set(ids))


# --- Güvenlik şartları ---------------------------------------------------


def test_disabled_by_default(listener):
    result = check_ports(lab_target(), auth(AuthorizationMethod.LAB), ports=(listener,))
    assert result.status is CheckStatus.SKIPPED
    assert "varsayılan olarak kapalı" in result.message


def test_declaration_is_not_enough(listener):
    result = check_ports(lab_target(), auth(AuthorizationMethod.DECLARATION), enabled=True,
                         ports=(listener,))
    assert result.status is CheckStatus.SKIPPED
    assert "teknik doğrulama" in result.message


@pytest.mark.parametrize("ports", [(), tuple(range(1000, 1000 + MAX_PORTS + 1)), (0,), (70000,)])
def test_invalid_port_lists_rejected(ports):
    result = check_ports(lab_target(), auth(AuthorizationMethod.LAB), enabled=True, ports=ports)
    assert result.status is CheckStatus.ERROR


# --- probe_port ----------------------------------------------------------


def test_probe_open(listener):
    assert probe_port("127.0.0.1", listener) == OPEN


def test_probe_closed(closed_port):
    assert probe_port("127.0.0.1", closed_port) == CLOSED


def test_probe_timeout_is_filtered(monkeypatch):
    def slow(*args, **kwargs):
        raise TimeoutError()

    monkeypatch.setattr("sefalet.checks.port_check.socket.create_connection", slow)
    assert probe_port("127.0.0.1", 1) == FILTERED


# --- analyze_ports -------------------------------------------------------


def test_analyze_risky_port_is_probable():
    findings = {f.id: f for f in analyze_ports({3306: OPEN, 443: OPEN, 23: CLOSED})}
    assert set(findings) == {"PRT-306", "PRT-001"}
    assert findings["PRT-306"].severity is Severity.HIGH
    assert findings["PRT-306"].confidence is Confidence.PROBABLE
    assert "443 (HTTPS)" in findings["PRT-001"].evidence
    assert findings["PRT-001"].confidence is Confidence.INFORMATIONAL


def test_analyze_expected_ports_only_info():
    findings = analyze_ports({80: OPEN, 443: OPEN})
    assert [f.id for f in findings] == ["PRT-001"]


def test_analyze_nothing_open():
    assert analyze_ports({80: CLOSED, 443: FILTERED}) == []


# --- check_ports (gerçek bağlantı) ---------------------------------------


@pytest.mark.parametrize("method", [AuthorizationMethod.LAB, AuthorizationMethod.DNS_TXT,
                                    AuthorizationMethod.HTTP_FILE])
def test_check_with_technical_authorization(listener, closed_port, method):
    result = check_ports(lab_target(), auth(method), enabled=True, ports=(listener, closed_port))
    assert result.status is CheckStatus.COMPLETED
    assert result.details["open"] == [listener]
    assert result.details["ports"][str(closed_port)] == CLOSED
    assert [f.id for f in result.findings] == ["PRT-001"]
    assert "bilinmiyor" in result.findings[0].evidence


def test_check_all_filtered_message(monkeypatch):
    monkeypatch.setattr("sefalet.checks.port_check.probe_port", lambda ip, p, t: FILTERED)
    result = check_ports(lab_target(), auth(AuthorizationMethod.LAB), enabled=True)
    assert result.status is CheckStatus.COMPLETED
    assert "filtrelenmiş" in result.message
    assert result.findings == []


def test_check_uses_primary_ip_only(monkeypatch):
    seen = set()
    monkeypatch.setattr("sefalet.checks.port_check.probe_port",
                        lambda ip, p, t: seen.add(ip) or CLOSED)
    target = Target(original="x", scheme="https", hostname="x.local", port=443, is_ip=False,
                    ip_addresses=("127.0.0.1", "127.0.0.2"), lab_mode=True)
    check_ports(target, auth(AuthorizationMethod.LAB), enabled=True)
    assert seen == {"127.0.0.1"}
