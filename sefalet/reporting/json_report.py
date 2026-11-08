"""Tarama sonuçlarını JSON dosyasına yazar.

JSON, başka programların (ör. ileride web paneli, müşteri sistemleri)
sonuçları okuyabilmesi için kullanılan makine-dostu formattır.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from sefalet.models import ScanResult


def default_filename(scan: ScanResult, extension: str) -> str:
    """Ör. sefalet_ornek.com_20261108-120000_1a2b3c4d.json

    Sondaki 8 karakter tarama kimliğinden gelir; aynı saniyede yapılan iki
    taramanın raporları birbirinin üzerine yazılmaz.
    """
    safe_target = re.sub(r"[^A-Za-z0-9.-]", "_", scan.target)[:80]
    stamp = scan.started_at.strftime("%Y%m%d-%H%M%S")
    short_id = re.sub(r"[^A-Za-z0-9]", "", scan.scan_id)[:8]
    return f"sefalet_{safe_target}_{stamp}_{short_id}.{extension}"


def write_json(scan: ScanResult, path: Path) -> Path:
    """Sonucu JSON olarak yazar ve dosya yolunu döndürür.

    "Atomik yazma": Önce geçici dosyaya yazıp sonra adını değiştiriyoruz.
    Böylece yazma yarıda kesilirse (disk dolu, program kapandı) yarım,
    bozuk bir JSON dosyası oluşmaz.

    Raises:
        OSError: Dosya yazılamazsa.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(scan.to_json())
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return path
