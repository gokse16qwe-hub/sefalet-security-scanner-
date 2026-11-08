"""tls_check.py için testler.

İki tür test var:
  1. Saf analiz testleri: `cryptography` ile istediğimiz özellikte
     (süresi dolmuş, yanlış adlı, zayıf anahtarlı...) sahte sertifikalar
     üretip analyze_certificate'e veriyoruz.
  2. Gerçek el sıkışma testleri: Test sırasında bilgisayarın kendi
     üzerinde (127.0.0.1) küçük bir TLS sunucusu açıyoruz. İnternete
     çıkılmaz, ama bağlantı kodu gerçekten çalışır.
"""

import datetime as dt
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from sefalet.checks.tls_check import (
    NOT_SUPPORTED,
    SUPPORTED,
    UNTESTED,
    analyze_certificate,
    analyze_protocols,
    check_tls,
    classify_verify_error,
    hostname_matches,
)
from sefalet.models import CheckStatus, Severity
from sefalet.target import Target

NOW = dt.datetime(2026, 11, 8, 12, 0, tzinfo=dt.timezone.utc)

# RSA anahtar üretimi yavaş olduğu için bir kez üretip tekrar kullanıyoruz
_RSA_2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_CA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_cert(
    *,
    cn="ornek.com",
    san=("ornek.com", "www.ornek.com"),
    ip_san=(),
    not_before=NOW - dt.timedelta(days=30),
    not_after=NOW + dt.timedelta(days=60),
    key=None,
    hash_alg=None,
    issuer_key=None,
    issuer_cn=None,
):
    """Test sertifikası üretir. issuer_key verilmezse kendinden imzalıdır."""
    import ipaddress

    key = key or _RSA_2048
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]) if issuer_cn else subject
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    if issuer_key:
        # Python 3.13 katı doğrulama modu bu uzantıyı zorunlu tutar
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False)
    names = [x509.DNSName(n) for n in san] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ip_san]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(issuer_key or key, hash_alg or hashes.SHA256())


def ids(findings):
    return sorted(f.id for f in findings)


# --- hostname_matches ----------------------------------------------------


@pytest.mark.parametrize(
    ("host", "pattern", "expected"),
    [
        ("ornek.com", "ornek.com", True),
        ("ORNEK.com", "ornek.COM", True),
        ("www.ornek.com", "*.ornek.com", True),
        ("ornek.com", "*.ornek.com", False),          # joker, kök alan adını kapsamaz
        ("a.b.ornek.com", "*.ornek.com", False),      # joker tek bölüm kapsar
        ("kotuornek.com", "*.ornek.com", False),
        ("baska.com", "ornek.com", False),
    ],
)
def test_hostname_matches(host, pattern, expected):
    assert hostname_matches(host, pattern) is expected


# --- analyze_certificate -------------------------------------------------


def test_good_certificate():
    findings, details = analyze_certificate(make_cert(), "ornek.com", now=NOW)
    assert findings == []
    assert details["days_left"] == 60
    assert details["key"] == "RSA 2048 bit"
    assert details["signature_algorithm"] == "sha256"
    assert "www.ornek.com" in details["san"]


def test_expired_certificate():
    cert = make_cert(not_before=NOW - dt.timedelta(days=400), not_after=NOW - dt.timedelta(days=3))
    findings, _ = analyze_certificate(cert, "ornek.com", now=NOW)
    assert ids(findings) == ["TLS-001"]
    assert findings[0].severity is Severity.HIGH
    assert "3 gün önce" in findings[0].evidence


@pytest.mark.parametrize(("days", "severity"), [(5, Severity.MEDIUM), (20, Severity.LOW)])
def test_expiring_soon(days, severity):
    cert = make_cert(not_after=NOW + dt.timedelta(days=days, hours=1))
    findings, _ = analyze_certificate(cert, "ornek.com", now=NOW)
    assert ids(findings) == ["TLS-002"]
    assert findings[0].severity is severity


def test_not_yet_valid():
    cert = make_cert(not_before=NOW + dt.timedelta(days=2))
    assert ids(analyze_certificate(cert, "ornek.com", now=NOW)[0]) == ["TLS-006"]


def test_hostname_mismatch():
    findings, _ = analyze_certificate(make_cert(san=("baska.com",)), "ornek.com", now=NOW)
    assert ids(findings) == ["TLS-003"]
    assert "baska.com" in findings[0].evidence


def test_wildcard_certificate_matches():
    cert = make_cert(cn="*.ornek.com", san=("*.ornek.com",))
    assert analyze_certificate(cert, "www.ornek.com", now=NOW)[0] == []


def test_cn_used_when_no_san():
    cert = make_cert(cn="ornek.com", san=())
    assert analyze_certificate(cert, "ornek.com", now=NOW)[0] == []


def test_ip_target_uses_ip_san():
    cert = make_cert(san=(), ip_san=("93.184.216.34",))
    assert analyze_certificate(cert, "93.184.216.34", is_ip=True, now=NOW)[0] == []
    assert ids(analyze_certificate(cert, "1.1.1.1", is_ip=True, now=NOW)[0]) == ["TLS-003"]


def test_weak_rsa_key():
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    findings, details = analyze_certificate(make_cert(key=weak), "ornek.com", now=NOW)
    assert ids(findings) == ["TLS-007"]
    assert details["key"] == "RSA 1024 bit"


def test_ec_key_ok():
    key = ec.generate_private_key(ec.SECP256R1())
    findings, details = analyze_certificate(make_cert(key=key), "ornek.com", now=NOW)
    assert findings == []
    assert "secp256r1" in details["key"]


class _Sha1Cert:
    """Gerçek sertifikayı sarar ama imza algoritmasını SHA-1 gösterir.

    Güncel OpenSSL SHA-1 ile imza atmayı reddettiği için böyle bir
    sertifikayı testte üretemiyoruz; bu sarmalayıcıyla taklit ediyoruz.
    """

    def __init__(self, cert):
        self._cert = cert

    def __getattr__(self, name):
        return getattr(self._cert, name)

    @property
    def signature_hash_algorithm(self):
        return hashes.SHA1()


def test_sha1_signature_from_ca():
    cert = _Sha1Cert(make_cert(issuer_key=_CA_KEY, issuer_cn="Test CA"))
    findings, _ = analyze_certificate(cert, "ornek.com", now=NOW)
    assert ids(findings) == ["TLS-008"]


def test_issuer_in_details():
    cert = make_cert(issuer_key=_CA_KEY, issuer_cn="Test CA")
    assert analyze_certificate(cert, "ornek.com", now=NOW)[1]["issuer"] == "Test CA"


# --- classify_verify_error / analyze_protocols ---------------------------


@pytest.mark.parametrize("code", [9, 10, 62, 64])
def test_verify_errors_handled_elsewhere(code):
    assert classify_verify_error(code, "x") is None


def test_self_signed_verify_error():
    finding = classify_verify_error(18, "self-signed certificate")
    assert finding.id == "TLS-004"
    assert "kendinden imzalı" in finding.title


def test_untrusted_chain_verify_error():
    finding = classify_verify_error(20, "unable to get local issuer certificate")
    assert finding.id == "TLS-004"
    assert "zinciri" in finding.title


def test_protocols_all_good():
    assert analyze_protocols("TLSv1.3", {"TLSv1": NOT_SUPPORTED, "TLSv1.1": NOT_SUPPORTED}) == []


def test_protocols_legacy_supported():
    findings = analyze_protocols("TLSv1.3", {"TLSv1": SUPPORTED, "TLSv1.1": SUPPORTED})
    assert ids(findings) == ["TLS-009"]
    assert "TLS 1.0, TLS 1.1" in findings[0].evidence


def test_untested_is_not_reported_as_finding():
    # "Test edilemedi" sonucu ne açık ne de güvenli sayılır: bulgu üretmez
    assert analyze_protocols("TLSv1.3", {"TLSv1": UNTESTED, "TLSv1.1": UNTESTED}) == []


def test_no_tls13_is_info():
    findings = analyze_protocols("TLSv1.2", {})
    assert ids(findings) == ["TLS-010"]
    assert findings[0].severity is Severity.INFO


# --- Gerçek el sıkışma: yerel TLS sunucusu -------------------------------


class LocalTLSServer:
    """127.0.0.1 üzerinde, verilen sertifikayla çalışan küçük TLS sunucusu."""

    def __init__(self, cert, key, tmp_path):
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert_file, key_file)
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                with self.context.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass  # İstemci el sıkışmayı reddederse sorun değil

    def close(self):
        self._stop = True
        self.thread.join(timeout=2)
        self.sock.close()


def lab_target(port, hostname="localhost"):
    return Target(original=hostname, scheme="https", hostname=hostname, port=port,
                  is_ip=False, ip_addresses=("127.0.0.1",), lab_mode=True)


@pytest.fixture
def ca_signed_server(tmp_path):
    """Kendi test CA'mızın imzaladığı 'localhost' sertifikalı sunucu."""
    now = dt.datetime.now(dt.timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sefalet Test CA")])
    ca_cert = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(_CA_KEY.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(_CA_KEY.public_key()),
                       critical=False)
        .sign(_CA_KEY, hashes.SHA256())
    )
    leaf = make_cert(cn="localhost", san=("localhost",), not_before=now - dt.timedelta(days=1),
                     not_after=now + dt.timedelta(days=90), issuer_key=_CA_KEY,
                     issuer_cn="Sefalet Test CA")
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    server = LocalTLSServer(leaf, _RSA_2048, tmp_path)
    yield server, str(ca_file)
    server.close()


@pytest.fixture
def self_signed_server(tmp_path):
    now = dt.datetime.now(dt.timezone.utc)
    cert = make_cert(cn="localhost", san=("localhost",), not_before=now - dt.timedelta(days=1),
                     not_after=now + dt.timedelta(days=90))
    server = LocalTLSServer(cert, _RSA_2048, tmp_path)
    yield server
    server.close()


def test_real_handshake_trusted_certificate(ca_signed_server):
    server, ca_file = ca_signed_server
    result = check_tls(lab_target(server.port), ca_file=ca_file)
    assert result.status is CheckStatus.COMPLETED
    assert result.findings == [] or ids(result.findings) == ["TLS-010"]
    assert result.details["subject"] == "localhost"
    assert result.details["issuer"] == "Sefalet Test CA"
    assert result.details["protocol"].startswith("TLSv1.")
    # Python'un sunucu bağlamı TLS 1.0/1.1 kabul etmez
    assert SUPPORTED not in result.details["legacy_protocols"].values()


def test_real_handshake_self_signed(self_signed_server):
    result = check_tls(lab_target(self_signed_server.port))
    assert result.status is CheckStatus.COMPLETED
    assert "TLS-004" in ids(result.findings)


def test_real_handshake_hostname_mismatch(ca_signed_server):
    server, ca_file = ca_signed_server
    target = lab_target(server.port, hostname="baska.test")
    assert "TLS-003" in ids(check_tls(target, ca_file=ca_file).findings)


def test_connection_refused():
    # Boş bir port bul: aç, numarasını al, kapat
    with socket.create_server(("127.0.0.1", 0)) as s:
        port = s.getsockname()[1]
    result = check_tls(lab_target(port))
    assert result.status is CheckStatus.ERROR
    assert "reddetti" in result.message


def test_non_tls_server_gives_error():
    # TLS konuşmayan, hemen kapatan bir sunucu
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        result = check_tls(lab_target(port))
    finally:
        t.join(timeout=2)
        srv.close()
    assert result.status is CheckStatus.ERROR


def test_http_target_is_skipped():
    target = Target(original="http://ornek.com", scheme="http", hostname="ornek.com", port=80,
                    is_ip=False, ip_addresses=("93.184.216.34",))
    result = check_tls(target)
    assert result.status is CheckStatus.SKIPPED
    assert "https://" in result.message
