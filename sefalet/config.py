"""Proje genelinde kullanılan sabit ayarlar.

Sayıları kodun içine dağıtmak yerine burada topluyoruz; böylece
bir zaman aşımını değiştirmek için tek bir yere bakmak yeterli.
"""

from pathlib import Path

from sefalet import __version__

# Sunuculara kendimizi tanıtırken kullandığımız ad. Site sahipleri
# loglarında bu adı görünce trafiğin kimden geldiğini anlayabilir.
USER_AGENT = f"SefaletScanner/{__version__} (guvenlik yapilandirma analizi)"

# Ağ işlemleri için zaman aşımları (saniye)
HTTP_TIMEOUT = 10
DNS_TIMEOUT = 5
TLS_TIMEOUT = 10

# Yerel veri klasörü: doğrulama token'ları burada saklanır
DATA_DIR = Path.home() / ".sefalet"
