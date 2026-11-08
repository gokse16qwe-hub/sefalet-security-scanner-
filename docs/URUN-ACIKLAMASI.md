# Sefalet Security Scanner — Ürün Açıklaması

> Bu metin, satış ilanlarında (Bionluk, kişisel site vb.) kullanmak içindir.
> İhtiyaca göre kısaltıp uzatabilirsiniz.

---

## Kısa açıklama (ilan başlığı altı)

Web sitenizin güvenlik **yapılandırmasını** saniyeler içinde analiz eden,
Türkçe PDF rapor üreten komut satırı aracı. SSL sertifikası, güvenlik
başlıkları ve DNS kayıtlarını kontrol eder.

---

## Ne yapar?

Sefalet Security Scanner, bir web sitesinin dışarıdan görünen güvenlik
ayarlarını inceler ve risk seviyesine göre sınıflandırılmış bir rapor üretir:

- **SSL/TLS sertifikası:** Süresi, alan adı eşleşmesi, güven zinciri, eski
  protokoller.
- **HTTP güvenlik başlıkları:** HSTS, CSP, clickjacking koruması, çerez
  güvenliği, sürüm bilgisi sızıntısı.
- **DNS ve e-posta güvenliği:** SPF, DMARC, CAA, DNSSEC.
- **Risk puanı:** Bulgular A–F notu ve 100 üzerinden puanla özetlenir.
- **Raporlar:** Türkçe PDF ve JSON çıktı.
- **Görsel panel:** İsteğe bağlı, tarayıcıda açılan koyu temalı arayüz.

---

## Ne yapmaz? (dürüst sınır)

Bu araç bir **yapılandırma analiz aracıdır**, bir sızma testi (pentest) aracı
değildir. Saldırı yapmaz, açık istismar etmez, parola denemez. Kapsamlı bir
sızma testinin yerini tutmaz; hızlı bir güvenlik sağlık kontrolü sunar.

Bu sınırı bilerek koyduk: araç, doğrulanmamış bulguları "kesin açık" gibi
göstermez. Böylece ürettiğiniz raporlara güvenilebilir.

---

## Kimler için uygun?

- Kendi sitesinin güvenlik ayarlarını kontrol etmek isteyen site sahipleri,
- Müşterilerine hızlı güvenlik raporu sunmak isteyen serbest çalışanlar,
- Güvenlik alanına yeni başlayıp pratik bir araçla çalışmak isteyenler.

---

## Satın alınca ne alıyorsunuz?

- Aracın tüm kaynak kodu,
- Kurulum ve sık sorulanlar kılavuzu (`docs/KURULUM-ve-SSS.md`),
- Kurulumu kendiniz denetleyebileceğiniz `sefalet kontrol` komutu,
- Örnek rapor.

---

## Çalıştırmak için gerekenler

- Linux (Kali önerilir), Python 3.11+,
- Temel terminal kullanımı (komut yazma, klasör değiştirme).

> **Not:** Bu bir komut satırı aracıdır ve temel terminal bilgisi gerektirir.
> Kurulum tek seferliktir ve adım adım anlatılmıştır. Takılırsanız `sefalet
> kontrol` komutu sorunu size söyler.

---

## Yasal uyarı

Araç yalnızca sahibi olduğunuz veya tarama için açık yazılı izin aldığınız
hedeflerde kullanılmalıdır. İzinsiz tarama yasalara aykırıdır ve sorumluluğu
kullanıcıya aittir.
