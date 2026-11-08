"""Tarama izni doğrulama.

Kural (onaylanan politika "1-a"):
    - Pasif kontroller (TLS, HTTP başlıkları, DNS):
        teknik doğrulama VEYA kayıt altına alınan yazılı izin beyanı.
    - Aktif kontroller (TCP port):
        YALNIZCA teknik doğrulama (DNS TXT, HTTP dosyası veya lab modu).

Teknik doğrulama nasıl çalışır?
    1. Her alan adı için rastgele, tahmin edilemez bir token üretilir:
           sefalet-verify=Xk3...q9
    2. Site sahibi bu değeri iki yerden birine koyar:
         a) DNS TXT kaydı:  _sefalet-verify.ornek.com
         b) Dosya:          https://ornek.com/.well-known/sefalet-verify.txt
    3. Biz o kaydı/dosyayı okuyup token'ı bulursak hedefin sahibinin
       taramaya izin verdiğini kanıtlamış oluruz. Sadece sitenin gerçek
       yöneticisi DNS'i veya sitedeki dosyaları değiştirebilir.

Her doğrulama `AuthorizationInfo` olarak döner ve rapora yazılır (denetim izi).
"""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import dns.exception
import dns.resolver
import requests

from sefalet import config
from sefalet.models import AuthorizationInfo, AuthorizationMethod
from sefalet.target import Target

TOKEN_PREFIX = "sefalet-verify="
DNS_RECORD_PREFIX = "_sefalet-verify"
HTTP_FILE_PATH = ".well-known/sefalet-verify.txt"
# Doğrulama dosyasından en fazla bu kadar bayt okunur (dev dosyalara karşı koruma)
MAX_HTTP_FILE_BYTES = 4096

# Kullanıcının kabul etmesi gereken standart beyan metni
DECLARATION_TEXT = (
    "Tarama yapılacak hedefin sahibi olduğumu veya sahibinden bu tarama için "
    "açık yazılı izin aldığımı beyan ederim. Bu beyan yalnızca pasif "
    "yapılandırma kontrolleri (TLS, HTTP başlıkları, DNS) için geçerlidir."
)


class AuthorizationError(Exception):
    """Tarama izni doğrulanamadı. Mesaj Türkçe ve kullanıcıya gösterilebilir."""


# ---------------------------------------------------------------------------
# Token üretme ve saklama
# ---------------------------------------------------------------------------


def generate_token() -> str:
    """Tahmin edilemez rastgele bir token üretir.

    `secrets` modülü şifreleme amaçlı güvenli rastgele sayı üretir;
    `random` modülü bu iş için UYGUN DEĞİLDİR (tahmin edilebilir).
    """
    return secrets.token_urlsafe(24)


def expected_value(token: str) -> str:
    """DNS kaydına veya dosyaya yazılması gereken tam değer."""
    return f"{TOKEN_PREFIX}{token}"


class TokenStore:
    """Alan adı başına token'ları yerel bir JSON dosyasında saklar.

    Dosya biçimi:
        {"ornek.com": {"token": "...", "created_at": "2026-11-08T10:00:00+00:00"}}
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (config.DATA_DIR / "verifications.json")

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AuthorizationError(
                f"Token dosyası okunamadı ({self.path}): {exc}. "
                "Dosyayı silip yeni token üretebilirsiniz."
            ) from None
        if not isinstance(data, dict):
            raise AuthorizationError(f"Token dosyası bozuk: {self.path}")
        return data

    def _save(self, data: dict) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            # Dosyayı yalnızca sahibi okuyabilsin (rw-------)
            os.chmod(self.path, 0o600)
        except OSError as exc:
            raise AuthorizationError(f"Token dosyası yazılamadı ({self.path}): {exc}") from None

    def get(self, hostname: str) -> str | None:
        """Kayıtlı token'ı döndürür; yoksa None."""
        entry = self._load().get(hostname)
        if isinstance(entry, dict) and isinstance(entry.get("token"), str):
            return entry["token"]
        return None

    def get_or_create(self, hostname: str) -> str:
        """Kayıtlı token'ı döndürür; yoksa yenisini üretip kaydeder."""
        existing = self.get(hostname)
        if existing:
            return existing
        return self.regenerate(hostname)

    def regenerate(self, hostname: str) -> str:
        """Yeni token üretir (eskisi geçersiz olur)."""
        data = self._load()
        token = generate_token()
        data[hostname] = {"token": token, "created_at": datetime.now(timezone.utc).isoformat()}
        self._save(data)
        return token


def verification_instructions(hostname: str, token: str) -> str:
    """Kullanıcıya gösterilecek Türkçe doğrulama talimatı."""
    value = expected_value(token)
    return (
        f"'{hostname}' için tarama izninizi doğrulamak üzere aşağıdaki yöntemlerden birini uygulayın:\n"
        "\n"
        "Yöntem 1: DNS TXT kaydı\n"
        f"  Ad    : {DNS_RECORD_PREFIX}.{hostname}\n"
        f"  Tür   : TXT\n"
        f"  Değer : {value}\n"
        "  (DNS değişikliklerinin yayılması birkaç dakika ile birkaç saat sürebilir.)\n"
        "\n"
        "Yöntem 2: HTTP doğrulama dosyası\n"
        f"  Adres : https://{hostname}/{HTTP_FILE_PATH}\n"
        f"  İçerik: {value}\n"
    )


def _contains_token(candidates: list[str], token: str) -> bool:
    """Adaylardan biri beklenen değere eşit mi?

    `secrets.compare_digest`, karşılaştırma süresinden token'ın tahmin
    edilmesini engelleyen (zamanlama saldırısı) güvenli bir karşılaştırmadır.
    """
    expected = expected_value(token).encode()
    return any(secrets.compare_digest(c.strip().encode(), expected) for c in candidates)


# ---------------------------------------------------------------------------
# Yöntem 1: DNS TXT kaydı
# ---------------------------------------------------------------------------

TxtLookup = Callable[[str], list[str]]


def _default_txt_lookup(name: str) -> list[str]:
    """dnspython ile TXT kayıtlarını okur.

    Uzun TXT kayıtları DNS'te 255 baytlık parçalara bölünebilir;
    parçaları birleştirerek tam metni elde ediyoruz.
    """
    answer = dns.resolver.resolve(name, "TXT", lifetime=config.DNS_TIMEOUT)
    return [b"".join(rdata.strings).decode("utf-8", errors="replace") for rdata in answer]


def verify_dns_txt(
    target: Target, token: str, *, lookup: TxtLookup = _default_txt_lookup
) -> AuthorizationInfo:
    """_sefalet-verify.<alan-adı> TXT kaydında token'ı arar."""
    if target.is_ip:
        raise AuthorizationError(
            "IP adresleri için DNS doğrulaması yapılamaz. HTTP dosyası yöntemini kullanın."
        )

    record_name = f"{DNS_RECORD_PREFIX}.{target.hostname}"
    try:
        records = lookup(record_name)
    except dns.resolver.NXDOMAIN:
        raise AuthorizationError(
            f"DNS kaydı bulunamadı: {record_name}. Kaydı eklediyseniz yayılmasını bekleyin."
        ) from None
    except dns.resolver.NoAnswer:
        raise AuthorizationError(f"{record_name} adresinde TXT kaydı yok.") from None
    except dns.exception.Timeout:
        raise AuthorizationError("DNS sorgusu zaman aşımına uğradı. Tekrar deneyin.") from None
    except dns.exception.DNSException as exc:
        raise AuthorizationError(f"DNS sorgusu başarısız: {exc}") from None

    if not _contains_token(records, token):
        raise AuthorizationError(
            f"{record_name} TXT kaydı bulundu ancak beklenen doğrulama değeri yok."
        )

    return AuthorizationInfo(
        method=AuthorizationMethod.DNS_TXT,
        details=f"{record_name} TXT kaydında doğrulama değeri bulundu.",
    )


# ---------------------------------------------------------------------------
# Yöntem 2: HTTP doğrulama dosyası
# ---------------------------------------------------------------------------


def verify_http_file(target: Target, token: str) -> AuthorizationInfo:
    """<site>/.well-known/sefalet-verify.txt dosyasında token'ı arar.

    Güvenlik önlemleri:
      - Yönlendirmeler takip EDİLMEZ (başka bir siteye yönlendirip
        o sitenin dosyasıyla doğrulama yapılmasını engeller).
      - En fazla MAX_HTTP_FILE_BYTES bayt okunur.
    """
    url = target.base_url + HTTP_FILE_PATH
    try:
        with requests.get(
            url,
            timeout=config.HTTP_TIMEOUT,
            allow_redirects=False,
            stream=True,  # Gövdeyi bir anda değil, parça parça oku
            headers={"User-Agent": config.USER_AGENT},
        ) as response:
            if 300 <= response.status_code < 400:
                raise AuthorizationError(
                    f"Doğrulama dosyası adresi yönlendirme yapıyor (HTTP {response.status_code}). "
                    "Dosya doğrudan bu adreste sunulmalıdır."
                )
            if response.status_code != 200:
                raise AuthorizationError(
                    f"Doğrulama dosyasına erişilemedi: {url} (HTTP {response.status_code})."
                )
            body = _read_limited(response)
    except requests.exceptions.SSLError:
        raise AuthorizationError(
            "HTTPS sertifikası doğrulanamadığı için dosya okunamadı. "
            "DNS TXT yöntemini kullanabilirsiniz."
        ) from None
    except requests.exceptions.Timeout:
        raise AuthorizationError(f"Sunucu zamanında yanıt vermedi: {url}") from None
    except requests.exceptions.ConnectionError:
        raise AuthorizationError(f"Sunucuya bağlanılamadı: {url}") from None
    except requests.exceptions.RequestException as exc:
        raise AuthorizationError(f"Doğrulama dosyası okunamadı: {exc}") from None

    if not _contains_token(body.splitlines(), token):
        raise AuthorizationError(f"{url} bulundu ancak beklenen doğrulama değeri yok.")

    return AuthorizationInfo(
        method=AuthorizationMethod.HTTP_FILE,
        details=f"{url} dosyasında doğrulama değeri bulundu.",
    )


def _read_limited(response: requests.Response) -> str:
    """Yanıt gövdesinin en fazla MAX_HTTP_FILE_BYTES baytını okur."""
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=1024):
        chunks.append(chunk)
        total += len(chunk)
        if total >= MAX_HTTP_FILE_BYTES:
            break
    return b"".join(chunks)[:MAX_HTTP_FILE_BYTES].decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Yöntem 3: Yazılı izin beyanı (yalnızca pasif kontroller)
# ---------------------------------------------------------------------------


def create_declaration(target: Target, declarant: str, accepted: bool) -> AuthorizationInfo:
    """Kullanıcının izin beyanını kayıt altına alır.

    Args:
        declarant: Beyanı veren kişinin adı soyadı (ve isteğe bağlı kurumu).
        accepted: Kullanıcı DECLARATION_TEXT metnini açıkça kabul etti mi?
    """
    if not accepted:
        raise AuthorizationError("Tarama için izin beyanının kabul edilmesi gerekir.")
    name = (declarant or "").strip()
    if len(name) < 3:
        raise AuthorizationError("Beyanı veren kişinin adı soyadı girilmelidir.")

    return AuthorizationInfo(
        method=AuthorizationMethod.DECLARATION,
        details=f"Hedef: {target.display_name}. Beyan eden: {name}. Beyan: {DECLARATION_TEXT}",
    )


# ---------------------------------------------------------------------------
# Yöntem 4: Lab modu
# ---------------------------------------------------------------------------


def create_lab_authorization(target: Target) -> AuthorizationInfo:
    """Yerel test ortamı için yetki kaydı oluşturur.

    target.py, lab modunda yalnızca özel/yerel IP'lere izin verdiği için
    bu yöntem internetteki bir site için kullanılamaz.
    """
    if not target.lab_mode:
        raise AuthorizationError("Lab yetkisi yalnızca lab modunda çözümlenmiş hedefler içindir.")
    return AuthorizationInfo(
        method=AuthorizationMethod.LAB,
        details=f"Yerel lab hedefi: {target.display_name} ({', '.join(target.ip_addresses)}).",
    )


# ---------------------------------------------------------------------------
# Politika kontrolü
# ---------------------------------------------------------------------------


def ensure_allowed(authorization: AuthorizationInfo, *, active: bool) -> None:
    """Verilen yetkinin istenen kontrol türü için yeterli olup olmadığını kontrol eder.

    Args:
        active: Kontrol aktif mi (ör. port taraması)?

    Raises:
        AuthorizationError: Yetki yetersizse.
    """
    if active and not authorization.method.is_technical:
        raise AuthorizationError(
            "Port kontrolü gibi aktif kontroller için teknik doğrulama gerekir "
            "(DNS TXT kaydı veya HTTP doğrulama dosyası). İzin beyanı yeterli değildir."
        )
