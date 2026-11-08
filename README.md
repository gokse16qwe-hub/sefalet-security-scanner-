# Sefalet Security Scanner

Web sitelerinin güvenlik **yapılandırmasını** analiz eden araç.
Saldırı, exploit, brute force veya parola denemesi **yapmaz**.

> **Durum:** Geliştirme aşamasında (v0.1.0.dev0). Henüz tarama yapamaz.

## Özellikler (MVP hedefi)

| Özellik | Durum |
|---|---|
| Veri modelleri (bulgu, risk seviyesi, güven düzeyi) | ✅ |
| Hedef doğrulama ve SSRF koruması | ✅ |
| Tarama izni doğrulama (DNS TXT / HTTP dosyası / beyan) | ✅ |
| HTTP güvenlik başlıkları analizi | ⏳ |
| SSL/TLS sertifika kontrolü | ⏳ |
| DNS kayıt kontrolü (SPF, DMARC, CAA…) | ⏳ |
| Sınırlı TCP port kontrolü (**varsayılan kapalı**) | ⏳ |
| JSON çıktı | ⏳ |
| Türkçe PDF rapor | ⏳ |

## Tarama izni politikası

| Kontrol türü | Gerekli izin |
|---|---|
| Pasif (TLS, HTTP başlıkları, DNS) | Teknik doğrulama **veya** kayıt altına alınan yazılı izin beyanı |
| Aktif (TCP port kontrolü) | **Yalnızca** teknik doğrulama (DNS TXT, HTTP dosyası veya lab modu) **ve** `--enable-port-scan` bayrağı |

İzin bilgisi her raporda denetim izi olarak yer alır.

## Risk seviyesi ve güven düzeyi

Her bulgunun iki ayrı değeri vardır:

- **Risk seviyesi:** Kritik / Yüksek / Orta / Düşük / Bilgi. Sorun gerçekse etkisi ne kadar büyük?
- **Güven düzeyi:** Doğrulandı / Olası / Bilgi amaçlı. Sorunun var olduğundan ne kadar eminiz?

"Olası" bulgular raporda kesin açık olarak gösterilmez, manuel doğrulama önerilir.

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

## Testler

```bash
pytest            # Ağ gerektirmeyen tüm testler
pytest -v         # Her testi ayrı ayrı göster
pytest -m network # Gerçek internete çıkan entegrasyon testleri
```

## Proje yapısı

```
sefalet/
├── models.py          # Ortak veri modelleri
├── checks/            # Kontrol modülleri (TLS, headers, DNS, port)
└── reporting/         # JSON ve PDF rapor üretimi
tests/                 # Her modülün testleri
reports/               # Üretilen raporlar (git'e eklenmez)
```

## Lisans

Tüm hakları saklıdır. Ticari ürün.
