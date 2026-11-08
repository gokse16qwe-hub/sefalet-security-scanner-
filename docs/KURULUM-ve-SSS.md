# Sefalet Security Scanner — Kurulum ve Sık Sorulanlar

Bu belge, aracı ilk kez kuranlar içindir. **Bir sorunla karşılaşırsanız, soru
sormadan önce lütfen bu belgeyi ve en alttaki "Sık karşılaşılan hatalar"
bölümünü okuyun.** Çoğu sorunun cevabı burada.

---

## Önce bilmeniz gerekenler (ön koşullar)

Bu araç bir **komut satırı** aracıdır. Kullanabilmek için şunları temel düzeyde
bilmeniz beklenir:

- Terminal (komut satırı) penceresi açıp komut yazmayı,
- `cd` ile klasör değiştirmeyi,
- Bir metin dosyasını düzenlemeyi (`nano` gibi).

Bunları bilmiyorsanız, önce "Linux terminal temelleri" konusunda kısa bir
rehber izlemeniz gerekir. Bu araç, sıfırdan bilgisayar kullanmayı öğreten bir
ürün değildir; güvenlik taraması yapan bir araçtır.

**Gereksinim:** Linux (Kali önerilir) ve Python 3.11 veya üzeri.

---

## Kurulum (sadece bir kez yapılır)

Terminali açın ve komutları sırayla çalıştırın.

1. Projeyi indirin:

```bash
git clone <size-verilen-depo-adresi> sefalet-scanner
cd sefalet-scanner
```

2. Sanal ortam oluşturun ve etkinleştirin:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Aracı kurun:

```bash
pip install -e ".[dev]"
```

4. Kurulumun doğru olduğunu kontrol edin:

```bash
sefalet kontrol
```

Hepsi yeşil `✓` ise kurulum tamamdır. Kırmızı `✗` varsa, yanındaki **Çözüm**
satırını uygulayın.

---

## Her kullanımda

Her yeni terminal penceresi açtığınızda, komutları çalıştırmadan önce **önce
klasöre girip sanal ortamı etkinleştirmeniz** gerekir:

```bash
cd sefalet-scanner
source .venv/bin/activate
```

Bunu yapmazsanız `sefalet: command not found` hatası alırsınız. Bu bir arıza
değildir; sanal ortamı etkinleştirmeyi unutmuşsunuzdur.

---

## Kullanım

### 1. Tarama izni alın

```bash
sefalet token siteniz.com
```

Ekrandaki talimatla, ya bir DNS TXT kaydı ekleyin ya da sitenize bir doğrulama
dosyası koyun. (Ayrıntı ekranda yazıyor.)

### 2. Tarayın

```bash
sefalet scan siteniz.com
```

Rapor `reports/` klasörüne PDF ve JSON olarak kaydedilir.

### Görsel panel (isteğe bağlı)

```bash
sefalet gui
```

Tarayıcıda bir panel açılır; taramaları oradan da yönetebilirsiniz.

---

## Sık karşılaşılan hatalar ve çözümleri

### `sefalet: command not found`
Sanal ortamı etkinleştirmediniz. Şunu çalıştırın:
```bash
cd sefalet-scanner && source .venv/bin/activate
```

### `externally-managed-environment` (pip hatası)
Sanal ortam etkin değilken `pip install` çalıştırdınız. Önce:
```bash
source .venv/bin/activate
```
sonra kurulum komutunu tekrar deneyin.

### `No module named 'sefalet'` veya kütüphane hataları
Kurulum eksik. Sanal ortam etkinken:
```bash
pip install -e ".[dev]"
```

### "DNS kaydı bulunamadı" / "doğrulama değeri yok"
Eklediğiniz DNS kaydı henüz internete yayılmamış olabilir. 10-15 dakika bekleyip
tekrar deneyin. Yaydığını şöyle kontrol edebilirsiniz:
```bash
dig TXT _sefalet-verify.siteniz.com +short
```

### "Site başka bir alan adına yönlendiriyor"
Hedefiniz başka bir adrese yönleniyor (çoğunlukla `www` olan/olmayan hali).
Hedef olarak yönlendirmenin gittiği tam adresi yazın.

### PDF'te Türkçe karakterler bozuk
`sefalet kontrol` çalıştırın. "PDF fontları eksik" diyorsa, depoyu eksik
indirmişsiniz; `git clone` komutunu tekrar çalıştırın.

### Hiçbir şey çalışmıyor
Şu komutu çalıştırıp çıktısının tamamını saklayın; sorunun büyük ihtimalle
nerede olduğunu size söyler:
```bash
sefalet kontrol
```

---

## Destek

Bu araç "olduğu gibi" satılır. Yukarıdaki adımları ve `sefalet kontrol`
çıktısını denedikten sonra hâlâ çözülmeyen bir sorun varsa iletişime
geçebilirsiniz. Lütfen mesajınızda `sefalet kontrol` çıktısını da paylaşın;
aksi halde sorunu uzaktan anlamak mümkün olmaz.
