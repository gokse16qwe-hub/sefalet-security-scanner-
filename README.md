# Sefalet Security Scanner

Web sitelerinin güvenlik **yapılandırmasını** analiz eden araç.
Saldırı, exploit, brute force veya parola denemesi **yapmaz**.

> **Durum:** MVP (v0.1.0.dev0). Örnek rapor: [`docs/ornek-rapor-lab.pdf`](docs/ornek-rapor-lab.pdf)

## Özellikler

| Özellik | Durum |
|---|---|
| Veri modelleri (bulgu, risk seviyesi, güven düzeyi) | ✅ |
| Hedef doğrulama ve SSRF koruması | ✅ |
| Tarama izni doğrulama (DNS TXT / HTTP dosyası / beyan) | ✅ |
| HTTP güvenlik başlıkları analizi | ✅ |
| SSL/TLS sertifika kontrolü | ✅ |
| DNS kayıt kontrolü (SPF, DMARC, CAA…) | ✅ |
| Sınırlı TCP port kontrolü (**varsayılan kapalı**) | ✅ |
| Risk puanı ve A–F not | ✅ |
| JSON çıktı | ✅ |
| Türkçe PDF rapor | ✅ |

## Ön koşullar

Bu bir **komut satırı** aracıdır. Kullanmak için temel terminal bilgisi (komut
yazma, `cd` ile klasör değiştirme, dosya düzenleme) ve Python 3.11+ gerekir.
Ayrıntılı kurulum ve sorun giderme için: [`docs/KURULUM-ve-SSS.md`](docs/KURULUM-ve-SSS.md)

Kurulumdan sonra her şeyin yolunda olduğunu doğrulamak için:

```bash
sefalet kontrol
```

## Kurulum (Kali Linux)

Kali, `pip` ile doğrudan sisteme paket kurulmasına izin vermez (PEP 668).
Bu yüzden projeye özel bir **sanal ortam** kullanıyoruz:

```bash
git clone https://github.com/gokse16qwe-hub/sefalet-security-scanner-.git
cd sefalet-security-scanner-
python3 -m venv .venv          # Sanal ortamı oluştur (bir kez)
source .venv/bin/activate      # Sanal ortamı etkinleştir (her yeni terminalde)
pip install -e ".[dev]"        # Projeyi ve geliştirme araçlarını kur
```

Gereksinim: Python 3.11 veya üzeri.

## Kullanım

### 1. Tarama izni al (bir kez)

```bash
sefalet token ornek.com
```

Ekrandaki iki yöntemden birini uygulayın:

- **DNS TXT:** `_sefalet-verify.ornek.com` adına `sefalet-verify=...` değerinde TXT kaydı
- **HTTP dosyası:** `https://ornek.com/.well-known/sefalet-verify.txt` içinde aynı değer

### 2. Tara

```bash
sefalet scan ornek.com
```

Raporlar `reports/` klasörüne yazılır (`-o klasör` ile değiştirilebilir).

### Görsel panel (neon-koyu tema)

```bash
sefalet gui
```

Tarayıcıda `http://127.0.0.1:8765/` adresinde panel açılır: güvenlik puanı, bulgu dağılımı,
modül durumu, tarama geçmişi, rapor ayrıntıları, PDF/JSON indirme ve doğrulama talimatları.
Panel yalnızca bu bilgisayardan erişilebilir (127.0.0.1, Host kontrolü, oturum anahtarı).
Tarama geçmişi `~/.sefalet/scans/` klasöründe saklanır. Port değiştirmek için `--port 9000`,
tarayıcıyı otomatik açmamak için `--no-browser`.

### Diğer seçenekler

| Komut | Açıklama |
|---|---|
| `sefalet scan ornek.com --verify dns` | Yalnızca DNS TXT ile doğrula (`http` / `auto`) |
| `sefalet scan ornek.com --declare "Ad Soyad"` | Teknik doğrulama yerine yazılı izin beyanı (yalnızca pasif kontroller) |
| `sefalet scan https://localhost:8443 --lab` | Kendi yerel test ortamınız (yalnızca özel/yerel IP'ler) |
| `sefalet scan ornek.com --enable-port-scan` | Sınırlı TCP port kontrolü (teknik doğrulama gerekir) |
| `sefalet scan ornek.com --no-pdf` | Yalnızca JSON |
| `sefalet -v scan ...` | Ayrıntılı log |
| `sefalet token ornek.com --yenile` | Yeni doğrulama token'ı üret |

Çıkış kodları: `0` başarılı · `2` geçersiz girdi · `3` yetki doğrulanamadı · `4` rapor yazılamadı

## Tarama izni politikası

| Kontrol türü | Gerekli izin |
|---|---|
| Pasif (TLS, HTTP başlıkları, DNS) | Teknik doğrulama **veya** kayıt altına alınan yazılı izin beyanı |
| Aktif (TCP port kontrolü) | **Yalnızca** teknik doğrulama (DNS TXT, HTTP dosyası veya lab modu) **ve** `--enable-port-scan` |

İzin bilgisi her raporda denetim izi olarak yer alır.

**Güvenlik önlemleri:**
- Özel/iç ağ IP'leri (127.x, 10.x, 192.168.x, 169.254.x…) lab modu dışında reddedilir (SSRF koruması).
- Lab modu yalnızca özel IP'lere izin verir; internetteki siteyi doğrulamasız taramak için kullanılamaz.
- Hedef bir kez çözümlenir; TLS ve port bağlantıları bu IP'ye yapılır (DNS rebinding koruması).
- Başka alan adlarına yönlendirmeler takip edilmez.
- Port kontrolü: 21 portluk sabit liste, yalnızca TCP connect, banner okuma yok, en fazla 10 eşzamanlı bağlantı.

## Risk seviyesi, güven düzeyi ve puan

Her bulgunun iki ayrı değeri vardır:

- **Risk seviyesi:** Kritik / Yüksek / Orta / Düşük / Bilgi. Sorun gerçekse etkisi ne kadar büyük?
- **Güven düzeyi:** Doğrulandı / Olası / Bilgi amaçlı. Sorunun var olduğundan ne kadar eminiz?

"Olası" bulgular raporda kesin açık olarak gösterilmez, manuel doğrulama önerilir.
Bir sorgu başarısız olursa (ör. DNS zaman aşımı) ilgili kayıt "yok" sayılmaz; "test edilemedi" olarak raporlanır.

**Puan:** 100'den başlar; Kritik −40, Yüksek −20, Orta −8, Düşük −3 (olası bulgular yarısı).
Not: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50. Doğrulanmış Yüksek bulgu varsa not en fazla C, Kritik varsa F.

## Bulgu kodları

| Önek | Modül | Örnekler |
|---|---|---|
| `TLS-` | SSL/TLS | 001 süresi dolmuş · 002 yakında doluyor · 003 ad uyuşmazlığı · 004 güvenilmeyen zincir · 007 zayıf anahtar · 009 TLS 1.0/1.1 |
| `HDR-` | HTTP başlıkları | 001 HSTS yok · 004 CSP yok · 006 clickjacking · 010 HTTP→HTTPS yok · 011 sürüm sızıntısı · 013–015 çerez bayrakları |
| `DNS-` | DNS | 001 SPF yok · 003 zayıf SPF · 004 DMARC yok · 005 DMARC p=none · 006 CAA yok · 007 DNSSEC yok |
| `PRT-` | Port | 001 açık port listesi · 306 MySQL · 379 Redis · 017 MongoDB · 023 Telnet … |

## Testler

```bash
pytest            # Ağ gerektirmeyen tüm testler (~330 test, birkaç saniye)
pytest -v         # Her testi ayrı ayrı göster
pytest tests/test_tls_check.py   # Tek bir modülün testleri
```

Testler internete çıkmaz: HTTP için `responses`, DNS için sahte çözümleyici,
TLS ve port için 127.0.0.1 üzerinde geçici sunucular kullanılır.

## Proje yapısı

```
sefalet/
├── cli.py             # Komut satırı arayüzü (scan, token, gui)
├── web/               # Yerel web paneli: app.py (API), jobs.py, history.py, static/
├── scanner.py         # Kontrolleri çalıştıran yönetici
├── target.py          # Hedef ayrıştırma, SSRF koruması
├── authorization.py   # Tarama izni doğrulama
├── risk.py            # Puanlama
├── models.py          # Ortak veri modelleri
├── config.py          # Zaman aşımları, User-Agent
├── checks/            # tls_check, headers_check, dns_check, port_check
└── reporting/         # json_report, pdf_report, fonts/
tests/                 # Her modülün testleri
docs/                  # Örnek raporlar
```

## Bilinen sınırlamalar / yol haritası

- Kayıtlı alan adı tespiti için Public Suffix List kullanılmıyor (yalnızca `www.` çıkarılıyor).
- HTTP isteklerinde (başlıklar, doğrulama dosyası) IP sabitleme yok; web sürümünden önce eklenmeli.
- TLS: şifre takımı (cipher suite) analizi, OCSP/CT kontrolü yok.
- Yerel OpenSSL TLS 1.0/1.1 desteklemiyorsa bu sürümler "test edilemedi" olarak raporlanır.
- Sonraki aşama: FastAPI ile web API, kullanıcı hesapları, tarama geçmişi, zamanlanmış taramalar.

## Lisans

Tüm hakları saklıdır. Ticari ürün. PDF raporlarda kullanılan DejaVu fontları kendi
lisanslarıyla dağıtılır (`sefalet/reporting/fonts/LICENSE-DejaVu.txt`).
