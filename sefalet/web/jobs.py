"""Arka plan tarama işleri.

Bir tarama birkaç saniye ile bir dakika arası sürebilir. Web isteğini bu
kadar bekletmek yerine taramayı arka planda bir "iş" (job) olarak başlatıp
hemen bir iş kimliği döndürüyoruz. Panel, bu kimlikle birkaç saniyede bir
durumu sorar ve ilerlemeyi gösterir.
"""

from __future__ import annotations

import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from sefalet.models import AuthorizationInfo
from sefalet.scanner import run_scan
from sefalet.target import Target
from sefalet.web.history import ScanHistory

logger = logging.getLogger(__name__)

MAX_CONCURRENT_JOBS = 2  # Aynı anda en fazla bu kadar tarama


class TooManyJobs(Exception):
    """Aynı anda çalışan tarama sınırı aşıldı."""


@dataclass
class Job:
    id: str
    target: str
    enable_port_scan: bool = False
    status: str = "queued"           # queued → running → done / error
    current_step: str | None = None  # Şu an çalışan kontrol (ör. "tls")
    completed_steps: list[str] = field(default_factory=list)
    scan_id: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id, "target": self.target, "status": self.status,
            "enable_port_scan": self.enable_port_scan,
            "current_step": self.current_step, "completed_steps": list(self.completed_steps),
            "scan_id": self.scan_id, "error": self.error,
        }


class JobManager:
    def __init__(self, history: ScanHistory, *, runner=run_scan) -> None:
        self.history = history
        self._runner = runner  # Testlerde sahte tarama fonksiyonu verilebilir
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_JOBS, thread_name_prefix="tarama")

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for j in self._jobs.values() if j.status in ("queued", "running"))

    def submit(self, target: Target, authorization: AuthorizationInfo, *,
               enable_port_scan: bool) -> Job:
        with self._lock:
            active = sum(1 for j in self._jobs.values() if j.status in ("queued", "running"))
            if active >= MAX_CONCURRENT_JOBS:
                raise TooManyJobs()
            job = Job(id=str(uuid.uuid4()), target=target.label,
                      enable_port_scan=enable_port_scan)
            self._jobs[job.id] = job
        self._pool.submit(self._run, job, target, authorization, enable_port_scan)
        return job

    def get(self, job_id: str) -> Job:
        with self._lock:
            return self._jobs[job_id]

    def _run(self, job: Job, target: Target, authorization: AuthorizationInfo,
             enable_port_scan: bool) -> None:
        def progress(name: str, state: str) -> None:
            with self._lock:
                if state == "başladı":
                    job.current_step = name
                else:
                    job.completed_steps.append(name)
                    job.current_step = None

        job.status = "running"
        try:
            scan = self._runner(target, authorization, enable_port_scan=enable_port_scan,
                                progress=progress)
            self.history.save(scan)
            job.scan_id = scan.scan_id
            job.status = "done"
        except Exception as exc:  # noqa: BLE001 - iş çökse bile panel çalışmaya devam etmeli
            logger.exception("Tarama işi başarısız: %s", job.target)
            job.error = f"Tarama tamamlanamadı: {exc}"
            job.status = "error"

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
