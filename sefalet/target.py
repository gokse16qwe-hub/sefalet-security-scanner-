"""Hedef ayrıştırma ve güvenli IP çözümleme.

Kullanıcının yazdığı adres her zaman temiz gelmez:
    "  https://Ornek.com:8443/giris?x=1  "  →  ornek.com, port 8443
    "şirket.com.tr"                          →  xn--irket-idb.com.tr (punycode)

Bu modülün iki görevi var:

1. parse_target(): Metni temizler ve doğrular. İnternete çıkmaz.
2. resolve_target(): Alan adını IP adresine çevirir ve IP'nin taranmasına
   izin verilip verilmediğini kontrol eder.

Neden IP kontrolü yapıyoruz? (SSRF koruması)
    Bu araç ileride bir web sitesinde çalışacak. Kötü niyetli biri hedef olarak
    "127.0.0.1" ya da "169.254.169.254" (bulut sunucularının gizli bilgi
    servisi) yazarsa, tarayıcımız kendi sunucumuzun iç ağına bağlanırdı.
    Bu yüzden özel/iç ağ adresleri varsayılan olarak reddedilir.

    Lab modu yalnızca kendi yerel test ortamınız içindir ve tersini yapar:
    SADECE özel adreslere izin verir. Böylece lab modu, internetteki
    bir siteyi doğrulamasız taramak için kullanılamaz.

DNS rebinding koruması:
    Alan adı bir kez çözümlenir ve sonraki bütün kontroller bu IP'lere
    bağlanmalıdır (`Target.ip_addresses`). Aksi halde saldırgan, kontrol
    anında genel bir IP, bağlantı anında 127.0.0.1 döndürebilirdi.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

# Desteklenen adres şemaları ve varsayılan portları
DEFAULT_PORTS = {"https": 443, "http": 80}

# Alan adındaki tek bir bölüm ("ornek", "com") için kural:
# harf/rakam ile başlar ve biter, ortada tire olabilir, en fazla 63 karakter.
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAX_HOSTNAME_LENGTH = 253

# Başta "harfler:" olup ardından rakam gelmeyen yazımlar (ör. "javascript:alert(1)")
_BARE_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+-]*):(?!\d)")

# IP tipi kısaltması (IPv4 veya IPv6)
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Çözümleyici fonksiyonun tipi. Testlerde gerçek DNS yerine sahte fonksiyon veririz.
Resolver = Callable[..., list]


class TargetError(ValueError):
    """Hedef geçersiz veya taranmasına izin yok.

    Mesajı Türkçe ve kullanıcıya doğrudan gösterilebilir olmalıdır.
    """


@dataclass(frozen=True)
class ParsedTarget:
    """Temizlenmiş ama henüz IP'ye çözümlenmemiş hedef."""

    original: str          # Kullanıcının yazdığı ham metin
    scheme: str            # "https" veya "http"
    hostname: str          # Küçük harfli, ASCII (punycode) ad ya da IP
    port: int
    is_ip: bool            # Kullanıcı doğrudan IP mi yazdı?

    @property
    def display_name(self) -> str:
        """Raporda gösterilecek okunaklı ad (punycode → Türkçe karakterli)."""
        if self.is_ip:
            return self.hostname
        try:
            return self.hostname.encode("ascii").decode("idna")
        except UnicodeError:
            return self.hostname

    @property
    def base_url(self) -> str:
        """Kontrollerde kullanılacak kök adres, ör. https://ornek.com/"""
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        if self.port == DEFAULT_PORTS[self.scheme]:
            return f"{self.scheme}://{host}/"
        return f"{self.scheme}://{host}:{self.port}/"


@dataclass(frozen=True)
class Target(ParsedTarget):
    """Çözümlenmiş ve taranmasına izin verilmiş hedef."""

    ip_addresses: tuple[str, ...] = ()
    lab_mode: bool = False

    @property
    def primary_ip(self) -> str:
        """Bağlantılarda kullanılacak ilk IP adresi."""
        return self.ip_addresses[0]


# ---------------------------------------------------------------------------
# 1. Ayrıştırma (internete çıkmaz)
# ---------------------------------------------------------------------------


def parse_target(raw: str) -> ParsedTarget:
    """Kullanıcının yazdığı adresi temizler ve doğrular.

    Hata durumunda `TargetError` fırlatır.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise TargetError("Hedef adres boş olamaz.")

    text = raw.strip()

    # Köşeli parantezsiz yazılmış IPv6 ("fe80::1") URL içinde kullanılamaz;
    # önce onu "[fe80::1]" biçimine getiriyoruz.
    try:
        if isinstance(ipaddress.ip_address(text), ipaddress.IPv6Address):
            text = f"[{text}]"
    except ValueError:
        pass

    # "javascript:..." veya "mailto:..." gibi "//" içermeyen şemaları yakala.
    # ("ornek.com:8080" şema sayılmaz: iki noktadan sonra rakam geliyor.)
    bare_scheme = _BARE_SCHEME_RE.match(text)
    if "://" not in text and bare_scheme:
        raise TargetError(
            f"Desteklenmeyen adres şeması: '{bare_scheme.group(1)}'. "
            "Yalnızca http ve https kullanılabilir."
        )

    # "ornek.com" gibi şemasız yazımlarda varsayılan olarak https kabul edilir.
    if "://" not in text:
        text = "https://" + text

    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise TargetError(
            f"Desteklenmeyen adres şeması: '{parts.scheme}'. Yalnızca http ve https kullanılabilir."
        )

    # "kullanici:parola@ornek.com" biçimi reddedilir: parola içeren adresler
    # loglara ve raporlara sızabilir.
    if "@" in parts.netloc:
        raise TargetError("Adreste kullanıcı adı veya parola bulunmamalıdır.")

    hostname = parts.hostname  # urlsplit küçük harfe çevirir, IPv6 köşeli parantezini atar
    if not hostname:
        raise TargetError("Adreste bir alan adı veya IP bulunamadı.")

    # Dikkat: "parts.port or 443" yazamayız; port 0 olursa Python 0'ı "yanlış"
    # sayar ve sessizce 443 kullanılırdı. Bu yüzden açıkça None kontrolü yapıyoruz.
    try:
        port = parts.port if parts.port is not None else DEFAULT_PORTS[scheme]
    except ValueError:
        raise TargetError("Port numarası geçersiz (1-65535 arasında olmalı).") from None
    if not 1 <= port <= 65535:
        raise TargetError("Port numarası geçersiz (1-65535 arasında olmalı).")

    # Doğrudan IP mi yazıldı?
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None
    if ip is not None:
        return ParsedTarget(raw, scheme, ip.compressed, port, is_ip=True)

    hostname = _normalize_hostname(hostname)
    return ParsedTarget(raw, scheme, hostname, port, is_ip=False)


def _normalize_hostname(hostname: str) -> str:
    """Alan adını ASCII'ye çevirir ve kurallara uygunluğunu kontrol eder."""
    hostname = hostname.rstrip(".")  # "ornek.com." da geçerli bir yazımdır

    # Türkçe karakterli alan adlarını punycode'a çevir (şirket → xn--irket-idb)
    try:
        ascii_name = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        raise TargetError(f"Geçersiz alan adı: '{hostname}'.") from None

    if not ascii_name or len(ascii_name) > _MAX_HOSTNAME_LENGTH:
        raise TargetError(f"Geçersiz alan adı uzunluğu: '{hostname}'.")

    for label in ascii_name.split("."):
        if not _LABEL_RE.match(label):
            raise TargetError(f"Geçersiz alan adı: '{hostname}'.")

    return ascii_name


# ---------------------------------------------------------------------------
# 2. IP çözümleme ve izin kontrolü
# ---------------------------------------------------------------------------


def classify_ip(address: str) -> str:
    """IP adresini sınıflandırır.

    Dönüş değerleri:
        "public"    → İnternette genel erişilebilir adres
        "private"   → Özel/iç ağ adresi (loopback, 10.x, 192.168.x, 169.254.x...)
        "forbidden" → Hiçbir modda taranamaz (multicast, 0.0.0.0 vb.)
    """
    ip = ipaddress.ip_address(address)

    # "::ffff:127.0.0.1" gibi IPv6 içine gömülü IPv4 adresleri, içindeki
    # gerçek IPv4 adresine göre değerlendirilir.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    if ip.is_multicast or ip.is_unspecified:
        return "forbidden"
    if ip.is_global:
        return "public"
    return "private"


def resolve_target(
    raw: str,
    *,
    lab_mode: bool = False,
    resolver: Resolver = socket.getaddrinfo,
) -> Target:
    """Hedefi ayrıştırır, IP'ye çözümler ve taranmasına izin olup olmadığını kontrol eder.

    Args:
        raw: Kullanıcının yazdığı adres.
        lab_mode: True ise YALNIZCA özel/yerel adreslere izin verilir.
        resolver: DNS çözümleme fonksiyonu (testlerde sahtesi verilir).

    Raises:
        TargetError: Adres geçersizse, çözümlenemiyorsa veya izin verilmeyen
            bir IP'ye çıkıyorsa.
    """
    parsed = parse_target(raw)
    addresses = _resolve_addresses(parsed, resolver)

    categories = {addr: classify_ip(addr) for addr in addresses}

    forbidden = [a for a, c in categories.items() if c == "forbidden"]
    if forbidden:
        raise TargetError(f"Bu adres taranamaz: {', '.join(forbidden)}.")

    private = [a for a, c in categories.items() if c == "private"]
    public = [a for a, c in categories.items() if c == "public"]

    if lab_mode and public:
        raise TargetError(
            "Lab modu yalnızca yerel/özel ağ adresleri içindir. "
            f"Hedef genel bir IP'ye çözümlendi ({', '.join(public)}). "
            "İnternetteki siteler için sahiplik doğrulaması gereklidir."
        )
    # Tek bir özel IP bile varsa reddediyoruz: karışık yanıt, DNS rebinding
    # saldırısının tipik işaretidir.
    if not lab_mode and private:
        raise TargetError(
            f"Hedef özel/iç ağ adresine çözümlendi ({', '.join(private)}). "
            "Kendi yerel test ortamınızı taramak için lab modunu kullanın."
        )

    return Target(
        original=parsed.original,
        scheme=parsed.scheme,
        hostname=parsed.hostname,
        port=parsed.port,
        is_ip=parsed.is_ip,
        ip_addresses=tuple(addresses),
        lab_mode=lab_mode,
    )


def _resolve_addresses(parsed: ParsedTarget, resolver: Resolver) -> list[str]:
    """Alan adının IP adreslerini sırası korunarak, tekrarsız döndürür."""
    if parsed.is_ip:
        return [parsed.hostname]

    try:
        results = resolver(parsed.hostname, parsed.port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise TargetError(
            f"'{parsed.display_name}' alan adı çözümlenemedi. Adresi ve DNS ayarlarını kontrol edin."
        ) from None
    except OSError as exc:
        raise TargetError(f"DNS çözümleme sırasında ağ hatası: {exc}") from None

    # getaddrinfo her sonuç için (aile, tip, protokol, ad, (ip, port, ...)) döndürür.
    # IPv6 adreslerinde "fe80::1%eth0" gibi arayüz eki olabilir; onu atıyoruz.
    addresses: list[str] = []
    for *_, sockaddr in results:
        address = str(sockaddr[0]).split("%", 1)[0]
        address = ipaddress.ip_address(address).compressed
        if address not in addresses:
            addresses.append(address)

    if not addresses:
        raise TargetError(f"'{parsed.display_name}' için IP adresi bulunamadı.")
    return addresses
