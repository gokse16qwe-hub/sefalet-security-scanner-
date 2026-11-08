"""Tarama geçmişi: her tarama sonucu ayrı bir JSON dosyası olarak saklanır.

Klasör: ~/.sefalet/scans/<tarama-kimliği>.json

Neden veritabanı değil? MVP için dosyalar yeterli ve kolay anlaşılır.
Ticari web sürümünde bu sınıfın yerine PostgreSQL kullanan bir sınıf
konulabilir; panelin geri kalanı değişmez.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path

from pydantic import ValidationError

from sefalet import config
from sefalet.models import ScanResult
from sefalet.reporting.json_report import write_json

logger = logging.getLogger(__name__)

# Tarama kimliği UUID biçiminde olmalı. Bu kontrol, "../../etc/passwd" gibi
# kimliklerle klasör dışındaki dosyalara erişilmesini (path traversal) engeller.
_SCAN_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def is_valid_scan_id(scan_id: str) -> bool:
    return bool(_SCAN_ID_RE.match(scan_id or ""))


class ScanHistory:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = Path(directory or (config.DATA_DIR / "scans"))
        self._lock = threading.Lock()

    def _path(self, scan_id: str) -> Path:
        if not is_valid_scan_id(scan_id):
            raise KeyError(scan_id)
        return self.directory / f"{scan_id}.json"

    def save(self, scan: ScanResult) -> None:
        with self._lock:
            write_json(scan, self._path(scan.scan_id))

    def get(self, scan_id: str) -> ScanResult:
        """Taramayı döndürür; yoksa KeyError."""
        path = self._path(scan_id)
        if not path.exists():
            raise KeyError(scan_id)
        return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))

    def delete(self, scan_id: str) -> None:
        path = self._path(scan_id)
        if not path.exists():
            raise KeyError(scan_id)
        with self._lock:
            path.unlink()

    def list(self) -> list[ScanResult]:
        """Tüm taramalar, en yeniden en eskiye. Bozuk dosyalar atlanır."""
        if not self.directory.exists():
            return []
        scans = []
        for path in self.directory.glob("*.json"):
            try:
                scans.append(ScanResult.model_validate_json(path.read_text(encoding="utf-8")))
            except (OSError, ValidationError, ValueError):
                logger.warning("Okunamayan tarama dosyası atlandı: %s", path)
        return sorted(scans, key=lambda s: s.started_at, reverse=True)
