import os
import sys
import time
import queue
import logging
import threading
from typing import Optional, Dict, Any, List

from PySide6.QtCore import QObject, Signal, QTimer, QThread

from core.monitoring.drive_manager import DriveManager
from core.database.database import DatabaseManager
from core.database.settings_repository import SettingsRepository
from core.database.history_repository import HistoryRepository
from core.scanning.scan_exclusions import ScanExclusions
from core.scanning.existing_scan_session import (
    ScanSessionStats, BatchPersistenceWriter,
    SCAN_MODE_INCREMENTAL, SCAN_MODE_FULL,
    SCAN_STATUS_IDLE, SCAN_STATUS_DISCOVERING, SCAN_STATUS_SCANNING,
    SCAN_STATUS_PAUSED, SCAN_STATUS_COMPLETED, SCAN_STATUS_CANCELLED, SCAN_STATUS_ERROR
)
from core.scanning.existing_scan_workers import (
    FileDiscoveryWorker, AnalysisWorker, DETECTION_SOURCE_EXISTING_SCAN
)

logger = logging.getLogger("RansomGuard.ExistingScanManager")

# Configurable scan frequencies mapping to interval in seconds
FREQUENCY_MAP: Dict[str, Optional[int]] = {
    "Every hour": 3600,
    "Every 4 hours": 14400,
    "Every 12 hours": 43200,
    "Every day": 86400,
    "Every 3 days": 259200,
    "Every week": 604800,
    "Manual only": None,
    "Off": None
}

DEFAULT_FREQUENCY = "Every 4 hours"


class ExistingFileScanManager(QObject):
    """
    Central controller for scheduled and on-demand Existing File Scanning.
    Coordinates asynchronous discovery, bounded multi-worker file analysis,
    batched SQLite persistence, resource throttling, and throttled UI updates.
    Guarantees the PySide6 main GUI thread never freezes or lags.
    """
    scan_started = Signal(dict)         # (session_dict)
    scan_progress = Signal(dict)        # (session_stats_dict) throttled
    scan_paused = Signal()
    scan_resumed = Signal()
    scan_completed = Signal(dict)       # (summary_dict)
    scan_cancelled = Signal(dict)       # (summary_dict)
    scan_finished = Signal(dict)        # Legacy compatibility alias
    scan_interrupted = Signal(str)      # Legacy compatibility alias
    threat_detected = Signal(dict)      # (record_dict)
    schedule_updated = Signal(str, str) # (frequency, next_scan_time)

    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls, db_manager=None):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(db_manager)
            return cls._instance

    def __init__(self, db_manager=None, parent=None):
        super(ExistingFileScanManager, self).__init__(parent)
        self.db = db_manager or DatabaseManager()
        self.settings_repo = SettingsRepository(self.db)
        self.history_repo = HistoryRepository(self.db)
        self.exclusions = ScanExclusions()

        # Active session state
        self.current_session: Optional[ScanSessionStats] = None
        self.work_queue = queue.Queue(maxsize=50000)
        self.discovery_worker: Optional[FileDiscoveryWorker] = None
        self.analysis_workers: List[AnalysisWorker] = []
        self.active_worker_ids: set = set()
        self.batch_writer: Optional[BatchPersistenceWriter] = None
        self.active_worker = None
        self.pause_event = threading.Event()
        self.pause_event.set() # Initially unpaused

        # Cached lookups loaded at scan start
        self.cached_entries: Dict[str, Dict[str, Any]] = {}

        # UI Progress Update Throttler (fires every 300ms while scanning)
        self.ui_timer = QTimer(self)
        self.ui_timer.setInterval(300)
        self.ui_timer.timeout.connect(self._emit_throttled_progress)

        # Scheduler timer (checks every 30 seconds for automated scan triggers)
        self.frequency = self.settings_repo.get_setting("existing_scan_frequency", DEFAULT_FREQUENCY)
        if self.frequency not in FREQUENCY_MAP:
            self.frequency = DEFAULT_FREQUENCY

        self.schedule_timer = QTimer(self)
        self.schedule_timer.setInterval(30000)
        self.schedule_timer.timeout.connect(self._check_schedule)
        self.schedule_timer.start()

    # -------------------------------------------------------------------------
    # Public Scan Lifecycle Controls
    # -------------------------------------------------------------------------
    def is_scanning(self) -> bool:
        """Checks if a scan session is currently active (discovering, scanning, or paused)."""
        return self.current_session is not None and self.current_session.status in (
            SCAN_STATUS_DISCOVERING, SCAN_STATUS_SCANNING, SCAN_STATUS_PAUSED
        )

    def is_paused(self) -> bool:
        """Checks if the active scan is currently paused."""
        return self.current_session is not None and self.current_session.status == SCAN_STATUS_PAUSED

    def get_status(self) -> str:
        """Returns the current operational status of the scan engine."""
        if self.current_session:
            return self.current_session.status
        if self.frequency == "Off":
            return "Off"
        if self.frequency == "Manual only":
            return "Manual only"
        return "Scheduled"

    def start_scan(self, mode: str = SCAN_MODE_INCREMENTAL, target_drives: Optional[List[str]] = None) -> bool:
        """
        Starts an asynchronous Existing File Scan session.
        Never blocks the GUI thread.
        """
        if self.is_scanning():
            logger.warning("Existing File Scan is already in progress.")
            return False

        if target_drives is None:
            target_drives = self.get_protected_drives()

        if not target_drives:
            logger.warning("No target protected drives resolved for scanning.")
            return False

        # 1. Initialize session and batch writer
        self.current_session = ScanSessionStats(
            mode=mode,
            status=SCAN_STATUS_DISCOVERING,
            protected_drives=target_drives,
            start_time=time.time()
        )
        self.batch_writer = BatchPersistenceWriter(self.db, batch_size=500, flush_interval_sec=2.0)
        self.pause_event.set()

        # 2. Shared cache map populated asynchronously by worker thread
        self.cached_entries = {}

        # 3. Clean queue
        while not self.work_queue.empty():
            try:
                self.work_queue.get_nowait()
            except queue.Empty:
                break

        # 4. Start FileDiscoveryWorker
        self.discovery_worker = FileDiscoveryWorker(
            target_drives=target_drives,
            work_queue=self.work_queue,
            exclusions=self.exclusions,
            pause_event=self.pause_event,
            parent=self
        )
        self.discovery_worker.discovery_progress.connect(self._on_discovery_progress)
        self.discovery_worker.discovery_finished.connect(self._on_discovery_finished)
        self.discovery_worker.discovery_cancelled.connect(self._on_discovery_cancelled)

        # 5. Start AnalysisWorker Pool (bounded to max 3 workers for CPU responsiveness)
        num_workers = max(1, min(3, (os.cpu_count() or 2) - 1))
        self.analysis_workers = []
        self.active_worker_ids = set(range(1, num_workers + 1))
        for i in range(num_workers):
            w = AnalysisWorker(
                worker_id=i + 1,
                work_queue=self.work_queue,
                batch_writer=self.batch_writer,
                exclusions=self.exclusions,
                mode=mode,
                db_manager=self.db,
                cached_entries=self.cached_entries,
                pause_event=self.pause_event,
                parent=self
            )
            w.batch_analyzed.connect(self._on_batch_analyzed)
            w.file_analyzed.connect(self._on_file_analyzed)
            w.threat_detected.connect(self._on_threat_detected)
            w.worker_finished.connect(self._on_worker_finished)
            self.analysis_workers.append(w)
            w.start()

        self.discovery_worker.start()
        self.active_worker = self.discovery_worker

        # 6. Start UI throttler timer
        self.ui_timer.start()

        # 7. Audit log & signal
        drive_str = ", ".join(target_drives)
        self.history_repo.insert_log(
            event_type="EXISTING_SCAN_STARTED",
            severity="LOW",
            description=f"Existing File Scan ({mode}) started on protected scope: {drive_str}",
            target=drive_str,
            action_taken="SCAN_STARTED"
        )
        self.scan_started.emit(self.current_session.to_dict())
        logger.info(f"Existing File Scan session {self.current_session.scan_id} ({mode}) launched.")
        return True

    def pause_scan(self) -> bool:
        """Pauses the active scan session."""
        if not self.is_scanning() or self.is_paused():
            return False

        logger.info("Pausing Existing File Scan session...")
        self.pause_event.clear()
        if self.current_session:
            self.current_session.status = SCAN_STATUS_PAUSED
        self.scan_paused.emit()
        return True

    def resume_scan(self) -> bool:
        """Resumes a paused scan session."""
        if not self.is_paused():
            return False

        logger.info("Resuming Existing File Scan session...")
        if self.current_session:
            self.current_session.status = SCAN_STATUS_SCANNING
        self.pause_event.set()
        self.scan_resumed.emit()
        return True

    def stop_scan(self) -> bool:
        """Gracefully halts the active scan session without blocking the UI thread."""
        if not self.is_scanning():
            return False

        logger.info("Stopping Existing File Scan session gracefully...")
        # 1. Stop discovery
        if self.discovery_worker and self.discovery_worker.isRunning():
            self.discovery_worker.stop()

        # 2. Unpause so workers can terminate loop
        self.pause_event.set()

        # 3. Stop analysis workers
        for w in self.analysis_workers:
            if w.isRunning():
                w.stop()

        # 4. Clear work queue instantaneously without per-item loop overhead
        try:
            with self.work_queue.mutex:
                unfinished_remaining = len(self.work_queue.queue)
                self.work_queue.queue.clear()
                self.work_queue.unfinished_tasks = max(0, self.work_queue.unfinished_tasks - unfinished_remaining)
                if self.work_queue.unfinished_tasks == 0:
                    self.work_queue.all_tasks_done.notify_all()
        except Exception:
            pass

        self.ui_timer.stop()

        # 5. Finalize session as CANCELLED immediately in memory
        self.active_worker = None
        if self.current_session:
            self.current_session.status = SCAN_STATUS_CANCELLED
            self.current_session.end_time = time.time()
            summary = self.current_session.to_dict()

            # 6. Flush remaining batched writes and persist session state asynchronously
            bw = self.batch_writer
            sess = self.current_session
            hist_repo = self.history_repo
            def _async_persist():
                if bw:
                    try:
                        bw.flush()
                        bw.persist_session_state(sess)
                    except Exception as e:
                        logger.error(f"Error in async persist upon scan stop: {e}")
                try:
                    hist_repo.insert_log(
                        event_type="EXISTING_SCAN_INTERRUPTED",
                        severity="LOW",
                        description=f"Existing File Scan cancelled by user. Analyzed {sess.analyzed_count} files.",
                        target=",".join(sess.protected_drives),
                        action_taken="SCAN_CANCELLED"
                    )
                except Exception as e:
                    logger.debug(f"Async log cancelled: {e}")

            threading.Thread(target=_async_persist, daemon=True).start()

            self.scan_cancelled.emit(summary)
            self.scan_interrupted.emit("Scan cancelled by user.")

        return True

    def cancel_scan(self) -> bool:
        """Alias for stop_scan."""
        return self.stop_scan()

    # -------------------------------------------------------------------------
    # Internal Signal Callbacks & Aggregation
    # -------------------------------------------------------------------------
    def _on_discovery_progress(self, count: int, current_dir: str):
        if self.current_session:
            self.current_session.discovered_count = count
            self.current_session.current_file = current_dir

    def _on_discovery_finished(self, total: int):
        logger.info(f"File discovery finished. Total files: {total}")
        if self.current_session:
            self.current_session.discovered_count = total
            if self.current_session.status == SCAN_STATUS_DISCOVERING:
                self.current_session.status = SCAN_STATUS_SCANNING

        # Notify analysis workers that queue input is complete
        for w in self.analysis_workers:
            w.set_discovery_done()

        if total == 0 and self.current_session and self.current_session.status not in (SCAN_STATUS_COMPLETED, SCAN_STATUS_CANCELLED):
            self._finalize_scan_completion()

    def _on_discovery_cancelled(self):
        logger.info("File discovery was cancelled.")
        for w in self.analysis_workers:
            w.set_discovery_done()

    def _on_batch_analyzed(self, batch: dict):
        if not self.current_session:
            return

        self.current_session.analyzed_count += batch.get("analyzed", 0)
        self.current_session.clean_count += batch.get("clean", 0)
        self.current_session.suspicious_count += batch.get("suspicious", 0)
        self.current_session.malicious_count += batch.get("malicious", 0)
        self.current_session.unknown_count += batch.get("unknown", 0)
        self.current_session.skipped_count += batch.get("skipped", 0)
        self.current_session.threat_count += (batch.get("suspicious", 0) + batch.get("malicious", 0))

        last_file = batch.get("last_file")
        if last_file:
            self.current_session.current_file = last_file

        threats = batch.get("threats")
        if threats:
            self.current_session.detected_threats.extend(threats)

        # Check if all files have been analyzed
        if self.discovery_worker and not self.discovery_worker.isRunning():
            if self.work_queue.empty() and self.current_session.analyzed_count >= self.current_session.discovered_count:
                self._finalize_scan_completion()

    def _on_file_analyzed(self, record: dict):
        if not self.current_session:
            return

        self.current_session.analyzed_count += 1
        self.current_session.current_file = record.get("file_path", "")

        v = record.get("verdict")
        if record.get("is_skipped"):
            self.current_session.skipped_count += 1
        elif v == "CLEAN":
            self.current_session.clean_count += 1
        elif v == "SUSPICIOUS":
            self.current_session.suspicious_count += 1
            self.current_session.threat_count += 1
            self.current_session.detected_threats.append(record)
        elif v == "MALICIOUS":
            self.current_session.malicious_count += 1
            self.current_session.threat_count += 1
            self.current_session.detected_threats.append(record)
        else:
            self.current_session.unknown_count += 1

        # Check if all files have been analyzed
        if self.discovery_worker and not self.discovery_worker.isRunning():
            if self.work_queue.empty() and self.current_session.analyzed_count >= self.current_session.discovered_count:
                self._finalize_scan_completion()

    def _on_threat_detected(self, record: dict):
        self.threat_detected.emit(record)

    def _on_worker_finished(self, worker_id: int):
        self.active_worker_ids.discard(worker_id)
        if len(self.active_worker_ids) == 0:
            if self.current_session and self.current_session.status not in (SCAN_STATUS_COMPLETED, SCAN_STATUS_CANCELLED):
                self._finalize_scan_completion()

    def _emit_throttled_progress(self):
        """Emits aggregated lightweight progress dictionary to the UI."""
        if self.current_session and self.current_session.status in (SCAN_STATUS_DISCOVERING, SCAN_STATUS_SCANNING, SCAN_STATUS_PAUSED):
            self.scan_progress.emit(self.current_session.to_dict())

    def _finalize_scan_completion(self):
        """Concludes scan session successfully, persists summary, and notifies UI."""
        if not self.current_session or self.current_session.status == SCAN_STATUS_COMPLETED:
            return

        self.ui_timer.stop()
        self.current_session.status = SCAN_STATUS_COMPLETED
        self.current_session.end_time = time.time()

        if self.batch_writer:
            self.batch_writer.flush()
            self.batch_writer.persist_session_state(self.current_session)

        # Update settings repository with real completion telemetry
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        now_epoch = str(time.time())
        self.settings_repo.set_setting("existing_scan_last_time", now_str)
        self.settings_repo.set_setting("existing_scan_last_epoch", now_epoch)
        self.settings_repo.set_setting("existing_scan_last_discovered", str(self.current_session.discovered_count))
        self.settings_repo.set_setting("existing_scan_last_analyzed", str(self.current_session.analyzed_count))
        self.settings_repo.set_setting("existing_scan_last_clean", str(self.current_session.clean_count))
        self.settings_repo.set_setting("existing_scan_last_suspicious", str(self.current_session.suspicious_count))
        self.settings_repo.set_setting("existing_scan_last_malicious", str(self.current_session.malicious_count))
        self.settings_repo.set_setting("existing_scan_last_unknown", str(self.current_session.unknown_count))
        self.settings_repo.set_setting("existing_scan_last_threats", str(self.current_session.threat_count))

        # Synchronize discovered files count with total_files_count
        if self.current_session.discovered_count > 0:
            self.settings_repo.set_setting("total_files_count", str(self.current_session.discovered_count))

        summary = self.current_session.to_dict()
        drive_str = ", ".join(self.current_session.protected_drives)
        sev = "CRITICAL" if self.current_session.threat_count > 0 else "LOW"
        self.history_repo.insert_log(
            event_type="EXISTING_SCAN_COMPLETED",
            severity=sev,
            description=(
                f"Existing File Scan completed on {drive_str}. "
                f"Checked {self.current_session.analyzed_count} files ({self.current_session.threat_count} threats detected)."
            ),
            target=drive_str,
            action_taken="USER_ALERTED" if self.current_session.threat_count > 0 else "NO_ACTION"
        )

        self.active_worker = None
        logger.info(f"Existing File Scan session {self.current_session.scan_id} completed successfully.")
        self.scan_completed.emit(summary)
        self.scan_finished.emit(summary)

    def _on_worker_completed(self, summary: dict):
        """Processes completion summary from a completed scan session or test worker."""
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        now_epoch = str(time.time())
        self.settings_repo.set_setting("existing_scan_last_time", now_str)
        self.settings_repo.set_setting("existing_scan_last_epoch", now_epoch)
        self.settings_repo.set_setting("existing_scan_last_discovered", str(summary.get("files_discovered", 0)))
        self.settings_repo.set_setting("existing_scan_last_analyzed", str(summary.get("files_analyzed", 0)))
        self.settings_repo.set_setting("existing_scan_last_clean", str(summary.get("clean_count", 0)))
        self.settings_repo.set_setting("existing_scan_last_suspicious", str(summary.get("suspicious_count", 0)))
        self.settings_repo.set_setting("existing_scan_last_malicious", str(summary.get("malicious_count", 0)))
        self.settings_repo.set_setting("existing_scan_last_unknown", str(summary.get("unknown_count", 0)))
        self.settings_repo.set_setting("existing_scan_last_threats", str(summary.get("threats_found", 0)))

    # -------------------------------------------------------------------------
    # Settings & Schedule Helpers
    # -------------------------------------------------------------------------
    def get_frequency(self) -> str:
        """Returns the configured scan frequency."""
        return self.frequency

    def set_frequency(self, frequency: str) -> None:
        """Updates and persists the scan frequency."""
        if frequency in FREQUENCY_MAP:
            self.frequency = frequency
            self.settings_repo.set_setting("existing_scan_frequency", frequency)
            next_scan_time = self.get_next_scan_time()
            self.schedule_updated.emit(self.frequency, next_scan_time)
            logger.info(f"Scan schedule frequency updated to: {frequency}")

    def get_last_scan_time(self) -> str:
        """Returns the authentic formatted timestamp of the last completed scan, or 'Not scanned yet'."""
        val = self.settings_repo.get_setting("existing_scan_last_time")
        if val:
            return val
        # Check last session record
        last_sess = self.get_last_session()
        if last_sess and last_sess.get("end_time"):
            return str(last_sess["end_time"])
        return "Not scanned yet"

    def get_last_session(self) -> Optional[Dict[str, Any]]:
        """Queries SQLite for the most recent completed or cancelled scan session."""
        try:
            row = self.db.execute_read_one(
                "SELECT * FROM existing_scan_sessions ORDER BY start_time DESC, scan_id DESC LIMIT 1"
            )
            return dict(row) if row else None
        except Exception:
            return None

    def get_last_scan_summary(self) -> Optional[Dict[str, Any]]:
        """Returns the stored summary counts from the last scan session."""
        sess = self.get_last_session()
        if sess:
            return sess
        disc = self.settings_repo.get_setting("existing_scan_last_discovered")
        if disc is not None:
            try:
                return {
                    "files_discovered": int(disc),
                    "files_analyzed": int(self.settings_repo.get_setting("existing_scan_last_analyzed", 0)),
                    "clean_count": int(self.settings_repo.get_setting("existing_scan_last_clean", 0)),
                    "suspicious_count": int(self.settings_repo.get_setting("existing_scan_last_suspicious", 0)),
                    "malicious_count": int(self.settings_repo.get_setting("existing_scan_last_malicious", 0)),
                    "unknown_count": int(self.settings_repo.get_setting("existing_scan_last_unknown", 0)),
                    "threats_found": int(self.settings_repo.get_setting("existing_scan_last_threats", 0)),
                }
            except Exception:
                pass
        return None

    def get_last_scan_threats(self) -> List[Dict[str, Any]]:
        """Returns the real detection records for the most recent scan session."""
        last_sess = self.get_last_session()
        if not last_sess:
            return []
        scan_id = last_sess.get("scan_id")
        return self.get_scan_threats(scan_id)

    def get_scan_threats(self, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieves authentic detection records associated with a scan session.
        Queries existing_scan_threats, falling back to active session or cache records.
        """
        if not scan_id:
            last_sess = self.get_last_session()
            if not last_sess:
                return []
            scan_id = last_sess.get("scan_id")

        try:
            rows = self.db.execute_read(
                "SELECT * FROM existing_scan_threats WHERE scan_id = ? ORDER BY id ASC",
                (scan_id,)
            )
            if rows:
                return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"Error reading existing_scan_threats for {scan_id}: {e}")

        # If current in-memory active session matches
        if self.current_session and self.current_session.scan_id == scan_id:
            if self.current_session.detected_threats:
                return list(self.current_session.detected_threats)

        # Fallback to existing_scan_cache for any suspicious/malicious records
        try:
            cache_rows = self.db.execute_read(
                "SELECT * FROM existing_scan_cache WHERE verdict IN ('SUSPICIOUS', 'MALICIOUS') ORDER BY last_scanned_at DESC"
            )
            if cache_rows:
                return [dict(r) for r in cache_rows]
        except Exception as e:
            logger.warning(f"Error reading fallback threats from existing_scan_cache: {e}")

        return []

    def get_next_scan_time(self) -> str:
        """Calculates authentic next scan timestamp based on selected frequency and last scan epoch."""
        freq_seconds = FREQUENCY_MAP.get(self.frequency)
        if freq_seconds is None:
            return self.frequency # "Manual only" or "Off"

        last_epoch_str = self.settings_repo.get_setting("existing_scan_last_epoch")
        now = time.time()

        if not last_epoch_str:
            next_epoch = now + freq_seconds
        else:
            try:
                last_epoch = float(last_epoch_str)
                next_epoch = last_epoch + freq_seconds
                if next_epoch <= now:
                    next_epoch = now + 60
            except ValueError:
                next_epoch = now + freq_seconds

        next_dt = time.localtime(next_epoch)
        today_struct = time.localtime(now)

        if next_dt.tm_yday == today_struct.tm_yday and next_dt.tm_year == today_struct.tm_year:
            return f"Today at {time.strftime('%I:%M %p', next_dt)}"
        elif next_dt.tm_yday == (today_struct.tm_yday + 1) and next_dt.tm_year == today_struct.tm_year:
            return f"Tomorrow at {time.strftime('%I:%M %p', next_dt)}"
        else:
            return time.strftime("%Y-%m-%d %I:%M %p", next_dt)

    def get_protected_drives(self) -> List[str]:
        """Resolves active protected drives configured by user in settings."""
        system_drive = os.environ.get("SystemDrive", "C:").upper()
        if not system_drive.endswith(":"):
            system_drive += ":"

        saved_drives = self.settings_repo.get_setting("protected_drives", system_drive)
        targets = []
        for d in saved_drives.split(","):
            d = d.strip()
            if d:
                let = d[0].upper()
                targets.append(f"{let}:\\")

        if not targets:
            targets = [f"{system_drive}\\"]
        return targets

    def _check_schedule(self):
        """Timer callback checking if a scheduled scan is due."""
        freq_seconds = FREQUENCY_MAP.get(self.frequency)
        if freq_seconds is None or self.is_scanning():
            return

        last_epoch_str = self.settings_repo.get_setting("existing_scan_last_epoch")
        now = time.time()
        if not last_epoch_str:
            logger.info("Executing initial scheduled Existing File Scan...")
            self.start_scan(mode=SCAN_MODE_INCREMENTAL)
            return

        try:
            last_epoch = float(last_epoch_str)
            if (now - last_epoch) >= freq_seconds:
                logger.info(f"Scan due by schedule ({self.frequency}). Starting background scan...")
                self.start_scan(mode=SCAN_MODE_INCREMENTAL)
        except ValueError:
            pass

    def _load_scan_cache(self) -> Dict[str, Dict[str, Any]]:
        """Loads existing scan cache entries into memory dictionary for fast lookups."""
        cache_map = {}
        try:
            rows = self.db.execute_read(
                "SELECT file_path, mtime_ns, ctime_ns, file_size, prefix_hash, verdict, "
                "risk_score, severity, threat_name, reason, sha256, file_type "
                "FROM existing_scan_cache"
            )
            for r in rows:
                cache_map[r["file_path"]] = dict(r)
        except Exception as e:
            logger.warning(f"Error reading existing_scan_cache: {e}")
        return cache_map


# -------------------------------------------------------------------------
# Backward Compatibility Wrapper
# -------------------------------------------------------------------------
ExistingScanManager = ExistingFileScanManager


class ExistingScanWorker(QThread):
    """
    Synchronous compatibility worker for unit tests and legacy callers.
    Wraps the unified analysis pipeline on a single thread.
    """
    progress_updated = Signal(str, int, int, int)
    scan_completed = Signal(dict)
    scan_interrupted = Signal(str)
    threat_detected = Signal(dict)

    def __init__(self, target_drives: List[str], db_manager=None, parent=None):
        super(ExistingScanWorker, self).__init__(parent)
        self.target_drives = [d.rstrip("\\") + "\\" for d in target_drives if d]
        self.db = db_manager or DatabaseManager()
        self.history_repo = HistoryRepository(self.db)
        self.exclusions = ScanExclusions()
        self.batch_writer = BatchPersistenceWriter(self.db, batch_size=20)
        self.running = True
        self.files_discovered = 0
        self.files_analyzed = 0
        self.clean_count = 0
        self.suspicious_count = 0
        self.malicious_count = 0
        self.unknown_count = 0
        self.threats_found = 0
        self.records = []

    def stop(self):
        self.running = False

    def _scan_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Scans a single file directly via UnifiedFileAnalyzer for deterministic testing."""
        worker = AnalysisWorker(
            worker_id=0,
            work_queue=queue.Queue(),
            batch_writer=self.batch_writer,
            exclusions=self.exclusions,
            mode=SCAN_MODE_FULL,
            db_manager=self.db,
            cached_entries={},
            pause_event=threading.Event()
        )
        return worker._process_single_file(file_path)

    def run(self):
        start_time = time.time()
        drive_str = ", ".join(self.target_drives)
        self.history_repo.insert_log(
            event_type="EXISTING_SCAN_STARTED",
            severity="LOW",
            description=f"Existing File Scan started on protected scope: {drive_str}",
            target=drive_str,
            action_taken="SCAN_STARTED"
        )
        discovered = []
        for d in self.target_drives:
            if not self.running:
                break
            if not os.path.exists(d):
                continue
            for root, dirs, files in os.walk(d, topdown=True):
                if not self.running:
                    break
                dirs[:] = [sub for sub in dirs if not self.exclusions.should_exclude_directory(os.path.join(root, sub))[0]]
                for f in files:
                    if not self.running:
                        break
                    discovered.append(os.path.join(root, f))

        if not self.running:
            self.history_repo.insert_log(
                event_type="EXISTING_SCAN_INTERRUPTED",
                severity="LOW",
                description=f"Existing File Scan cancelled by user. Analyzed {self.files_analyzed} files.",
                target=drive_str,
                action_taken="SCAN_CANCELLED"
            )
            self.scan_interrupted.emit("Scan cancelled by user.")
            return

        self.files_discovered = len(discovered)
        worker = AnalysisWorker(
            worker_id=0,
            work_queue=queue.Queue(),
            batch_writer=self.batch_writer,
            exclusions=self.exclusions,
            mode=SCAN_MODE_INCREMENTAL,
            db_manager=self.db,
            cached_entries={},
            pause_event=threading.Event()
        )

        for p in discovered:
            if not self.running:
                break
            rec = worker._process_single_file(p)
            if rec:
                self.records.append(rec)
                self.files_analyzed += 1
                v = rec.get("verdict")
                if v == "CLEAN":
                    self.clean_count += 1
                elif v == "SUSPICIOUS":
                    self.suspicious_count += 1
                    self.threats_found += 1
                elif v == "MALICIOUS":
                    self.malicious_count += 1
                    self.threats_found += 1
                    self.threat_detected.emit(rec)
                    worker._handle_threat(rec)
                else:
                    self.unknown_count += 1

        self.batch_writer.flush()

        if not self.running:
            self.history_repo.insert_log(
                event_type="EXISTING_SCAN_INTERRUPTED",
                severity="LOW",
                description=f"Existing File Scan cancelled by user. Analyzed {self.files_analyzed} files.",
                target=drive_str,
                action_taken="SCAN_CANCELLED"
            )
            self.scan_interrupted.emit("Scan cancelled by user.")
            return

        duration = round(time.time() - start_time, 2)
        summary = {
            "target_drives": self.target_drives,
            "duration_sec": duration,
            "files_discovered": self.files_discovered,
            "files_analyzed": self.files_analyzed,
            "clean_count": self.clean_count,
            "suspicious_count": self.suspicious_count,
            "malicious_count": self.malicious_count,
            "unknown_count": self.unknown_count,
            "threats_found": self.threats_found,
            "records": self.records,
            "interrupted": False
        }
        sev = "CRITICAL" if self.threats_found > 0 else "LOW"
        self.history_repo.insert_log(
            event_type="EXISTING_SCAN_COMPLETED",
            severity=sev,
            description=f"Existing File Scan completed on {drive_str}. Checked {self.files_analyzed} files ({self.threats_found} threats detected).",
            target=drive_str,
            action_taken="USER_ALERTED" if self.threats_found > 0 else "NO_ACTION"
        )
        self.scan_completed.emit(summary)
