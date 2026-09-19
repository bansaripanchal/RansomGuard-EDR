import os
import sys
import time
import queue
import hashlib
import logging
import threading
from typing import Optional, Dict, Any, List, Set
from PySide6.QtCore import QThread, Signal

from core.analysis.file_analyzer import UnifiedFileAnalyzer
from core.detection.risk_engine import (
    RiskEngine, VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS, VERDICT_UNKNOWN
)
from core.database.database import DatabaseManager
from core.database.incidents_repository import IncidentsRepository
from core.database.history_repository import HistoryRepository
from core.protection.alert_manager import AlertManager
from core.scanning.scan_exclusions import ScanExclusions
from core.scanning.existing_scan_session import (
    ScanSessionStats, BatchPersistenceWriter, SCAN_MODE_INCREMENTAL, SCAN_MODE_FULL
)

logger = logging.getLogger("RansomGuard.ScanWorkers")

DETECTION_SOURCE_EXISTING_SCAN = "Existing File Scan"


class FileDiscoveryWorker(QThread):
    """
    Dedicated background thread that recursively discovers files across protected drives,
    prunes safe system exclusions, and queues paths into a bounded queue for analysis.
    Runs completely off the UI thread to guarantee zero GUI freezing.
    """
    discovery_progress = Signal(int, str)  # (discovered_count, current_directory)
    discovery_finished = Signal(int)       # (total_discovered)
    discovery_cancelled = Signal()

    def __init__(self, target_drives: List[str], work_queue: queue.Queue, exclusions: ScanExclusions, pause_event: Optional[threading.Event] = None, parent=None):
        super(FileDiscoveryWorker, self).__init__(parent)
        self.target_drives = [os.path.normpath(d) for d in target_drives if d]
        self.work_queue = work_queue
        self.exclusions = exclusions
        self.pause_event = pause_event
        self.running = True
        self.discovered_count = 0

    def stop(self):
        """Requests graceful stopping of file discovery."""
        self.running = False

    def run(self):
        self.running = True
        self.discovered_count = 0
        last_progress_emit = 0.0

        for drive_root in self.target_drives:
            if not self.running:
                break
            if not os.path.exists(drive_root):
                continue

            # Ensure root trailing slash for walk
            walk_target = drive_root if drive_root.endswith(os.sep) else drive_root + os.sep

            try:
                for root, dirs, files in os.walk(walk_target, topdown=True):
                    if not self.running:
                        break

                    # Handle pause state during directory walk
                    if self.pause_event and not self.pause_event.is_set():
                        self.pause_event.wait()
                        if not self.running:
                            break

                    # 1. Prune excluded directory trees before descending
                    dirs[:] = [
                        d for d in dirs
                        if not self.exclusions.should_exclude_directory(os.path.join(root, d))[0]
                    ]

                    # 2. Queue discovered files
                    for f in files:
                        if not self.running:
                            break

                        if self.pause_event and not self.pause_event.is_set():
                            self.pause_event.wait()
                            if not self.running:
                                break

                        full_path = os.path.join(root, f)
                        
                        # Add to bounded queue with timeout to allow checking self.running
                        while self.running:
                            try:
                                self.work_queue.put(full_path, timeout=0.1)
                                self.discovered_count += 1
                                break
                            except queue.Full:
                                pass

                        now = time.time()
                        if now - last_progress_emit >= 0.25:
                            self.discovery_progress.emit(self.discovered_count, root)
                            last_progress_emit = now

            except Exception as e:
                logger.warning(f"Error during directory walk of {drive_root}: {e}")

        if not self.running:
            self.discovery_cancelled.emit()
        else:
            self.discovery_progress.emit(self.discovered_count, "Discovery completed.")
            self.discovery_finished.emit(self.discovered_count)


class AnalysisWorker(QThread):
    """
    Worker thread that reads file paths from the bounded queue,
    applies incremental cache verification or full static analysis,
    evaluates risk verdicts, integrates threat incidents, and feeds the batch persistence writer.
    """
    batch_analyzed = Signal(dict)
    file_analyzed = Signal(dict)
    threat_detected = Signal(dict)
    worker_finished = Signal(int)

    def __init__(self, worker_id: int, work_queue: queue.Queue, batch_writer: BatchPersistenceWriter,
                 exclusions: ScanExclusions, mode: str, db_manager: DatabaseManager,
                 cached_entries: Dict[str, Dict[str, Any]], pause_event: threading.Event, parent=None):
        super(AnalysisWorker, self).__init__(parent)
        self.worker_id = worker_id
        self.work_queue = work_queue
        self.batch_writer = batch_writer
        self.exclusions = exclusions
        self.mode = mode
        self.db = db_manager
        self.inc_repo = IncidentsRepository(self.db)
        self.history_repo = HistoryRepository(self.db)
        self.cached_entries = cached_entries
        self.pause_event = pause_event
        self.running = True
        self.discovery_done = False

    def stop(self):
        """Requests graceful stopping of the analysis worker."""
        self.running = False

    def set_discovery_done(self):
        """Notifies worker that no more files will be added to the queue."""
        self.discovery_done = True

    def _load_cache(self):
        """Asynchronously loads existing scan cache entries on worker thread."""
        try:
            rows = self.db.execute_read(
                "SELECT file_path, mtime_ns, ctime_ns, file_size, prefix_hash, verdict, "
                "risk_score, severity, threat_name, reason, sha256, file_type "
                "FROM existing_scan_cache"
            )
            for r in rows:
                self.cached_entries[r["file_path"]] = dict(r)
        except Exception as e:
            logger.warning(f"Error reading existing_scan_cache: {e}")

    def _flush_batch(self, batch_data: dict):
        """Emits accumulated file analysis counters to the manager thread."""
        if batch_data["analyzed"] > 0 or batch_data["threats"]:
            self.batch_analyzed.emit(dict(batch_data))
            batch_data["analyzed"] = 0
            batch_data["clean"] = 0
            batch_data["suspicious"] = 0
            batch_data["malicious"] = 0
            batch_data["unknown"] = 0
            batch_data["skipped"] = 0
            batch_data["last_file"] = ""
            batch_data["threats"] = []

    def run(self):
        self.running = True

        # Pre-load cache asynchronously on worker thread if empty
        if self.worker_id == 1 and not self.cached_entries:
            self._load_cache()

        batch_data = {
            "analyzed": 0,
            "clean": 0,
            "suspicious": 0,
            "malicious": 0,
            "unknown": 0,
            "skipped": 0,
            "last_file": "",
            "threats": []
        }
        last_emit_time = time.time()

        while self.running:
            # 1. Handle pause state
            self.pause_event.wait()
            if not self.running:
                break

            # 2. Get next file from queue
            try:
                file_path = self.work_queue.get(timeout=0.1)
            except queue.Empty:
                if self.discovery_done:
                    # All files have been discovered and processed
                    break
                continue

            if file_path is None:
                # Sentinel signaling queue termination
                self.work_queue.task_done()
                break

            # 3. Analyze file
            try:
                record = self._process_single_file(file_path)
                if record:
                    batch_data["analyzed"] += 1
                    batch_data["last_file"] = file_path
                    v = record.get("verdict")
                    if record.get("is_skipped"):
                        batch_data["skipped"] += 1
                    elif v == VERDICT_CLEAN:
                        batch_data["clean"] += 1
                    elif v == VERDICT_SUSPICIOUS:
                        batch_data["suspicious"] += 1
                        batch_data["threats"].append(record)
                        self._handle_threat(record)
                    elif v == VERDICT_MALICIOUS:
                        batch_data["malicious"] += 1
                        batch_data["threats"].append(record)
                        self._handle_threat(record)
                    else:
                        batch_data["unknown"] += 1
            except Exception as e:
                logger.error(f"Worker {self.worker_id} error processing {file_path}: {e}", exc_info=True)
                batch_data["analyzed"] += 1
                batch_data["unknown"] += 1
                batch_data["last_file"] = file_path
            finally:
                try:
                    self.work_queue.task_done()
                except Exception:
                    pass

            # Emit batch if 100 files or 0.25s elapsed
            now = time.time()
            if batch_data["analyzed"] >= 100 or (now - last_emit_time >= 0.25):
                self._flush_batch(batch_data)
                last_emit_time = now

            # 4. Cooperative CPU throttling (preserves OS/UI responsiveness)
            time.sleep(0.0005)

        # Flush any remaining items in the buffer
        self._flush_batch(batch_data)
        self.worker_finished.emit(self.worker_id)

    def _process_single_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Processes a single file with safe exclusions, incremental caching, and unified analysis."""
        # 1. Safe File Exclusion check
        is_excluded, reason = self.exclusions.should_exclude_file(file_path)
        if is_excluded:
            return {
                "file_path": file_path,
                "filename": os.path.basename(file_path),
                "extension": os.path.splitext(file_path)[1].lower(),
                "file_size": 0,
                "file_type": "Excluded",
                "sha256": "Not available",
                "verdict": "SKIPPED",
                "severity": "LOW",
                "risk_score": 0,
                "threat_name": "Excluded System File",
                "reason": reason,
                "is_skipped": True,
                "detection_source": DETECTION_SOURCE_EXISTING_SCAN
            }

        # 2. Stat check
        try:
            stat_info = os.stat(file_path)
            current_mtime_ns = stat_info.st_mtime_ns
            current_ctime_ns = getattr(stat_info, "st_ctime_ns", 0)
            current_size = stat_info.st_size
        except (PermissionError, FileNotFoundError, OSError) as e:
            return {
                "file_path": file_path,
                "filename": os.path.basename(file_path),
                "extension": os.path.splitext(file_path)[1].lower(),
                "file_size": 0,
                "file_type": "Unknown",
                "sha256": "Not available",
                "verdict": VERDICT_UNKNOWN,
                "severity": "LOW",
                "risk_score": 0,
                "threat_name": "Inaccessible File",
                "reason": f"Access restricted: {e}",
                "is_skipped": False,
                "detection_source": DETECTION_SOURCE_EXISTING_SCAN
            }

        # 3. Incremental Cache Verification (if mode == INCREMENTAL)
        if self.mode == SCAN_MODE_INCREMENTAL:
            cached = self.cached_entries.get(file_path)
            if cached:
                mtime_match = (cached.get("mtime_ns") == current_mtime_ns)
                size_match = (cached.get("file_size") == current_size)
                cached_verdict = cached.get("verdict")

                if mtime_match and size_match and cached_verdict not in (VERDICT_UNKNOWN, "SKIPPED", None):
                    # Multi-point verification with 4KB prefix hash
                    try:
                        with open(file_path, "rb") as f:
                            prefix = hashlib.sha256(f.read(4096)).hexdigest()
                        if prefix == cached.get("prefix_hash"):
                            return {
                                "file_path": file_path,
                                "filename": os.path.basename(file_path),
                                "extension": os.path.splitext(file_path)[1].lower(),
                                "file_size": current_size,
                                "file_type": cached.get("file_type", "Unknown"),
                                "sha256": cached.get("sha256", "Not available"),
                                "verdict": cached_verdict,
                                "severity": cached.get("severity", "LOW"),
                                "risk_score": cached.get("risk_score", 0),
                                "threat_name": cached.get("threat_name", "Clean File"),
                                "reason": cached.get("reason", "No security threat detected."),
                                "is_skipped": False,
                                "mtime_ns": current_mtime_ns,
                                "ctime_ns": current_ctime_ns,
                                "prefix_hash": prefix,
                                "is_cache_hit": True,
                                "detection_source": DETECTION_SOURCE_EXISTING_SCAN
                            }
                    except Exception:
                        pass # Fall through to fresh analysis if read fails

        # 4. Fresh Deep Analysis via UnifiedFileAnalyzer
        analysis_res = UnifiedFileAnalyzer.analyze_file(file_path)
        verdict = RiskEngine.determine_verdict(
            analysis_res.static_indicators,
            is_accessible=analysis_res.accessible,
            has_errors=bool(analysis_res.error)
        )
        risk_score, severity = RiskEngine.calculate_risk(analysis_res.static_indicators)

        threat_name = "Clean File"
        reason = "No security threat detected."
        if analysis_res.static_indicators:
            threat_name = analysis_res.static_indicators[0].get("threat_name", "Security Threat")
            reason = analysis_res.static_indicators[0].get("reason", "Suspicious indicator detected.")
        elif verdict == VERDICT_UNKNOWN:
            threat_name = "Unanalyzed File"
            reason = analysis_res.error or "Unable to read file content."

        # Compute prefix hash for cache persistence
        prefix_hash = ""
        try:
            with open(file_path, "rb") as f:
                prefix_hash = hashlib.sha256(f.read(4096)).hexdigest()
        except Exception:
            pass

        record = {
            "file_path": file_path,
            "filename": analysis_res.filename,
            "extension": analysis_res.extension,
            "file_size": analysis_res.size,
            "file_type": analysis_res.detected_file_type,
            "sha256": analysis_res.sha256 or "Not available",
            "verdict": verdict,
            "severity": severity if verdict != VERDICT_CLEAN else "LOW",
            "risk_score": risk_score if verdict != VERDICT_CLEAN else 0,
            "threat_name": threat_name,
            "reason": reason,
            "evidence_list": analysis_res.evidence_list,
            "mtime_ns": current_mtime_ns,
            "ctime_ns": current_ctime_ns,
            "prefix_hash": prefix_hash,
            "is_skipped": False,
            "is_cache_hit": False,
            "detection_source": DETECTION_SOURCE_EXISTING_SCAN
        }

        # 5. Queue into batch writer
        self.batch_writer.record_analyzed_file(record)
        return record

    def _handle_threat(self, record: Dict[str, Any]):
        """
        Integrates threat into Incident Repository with duplicate incident suppression,
        triggers native desktop alert, and records audit trail.
        """
        try:
            file_path = record["file_path"]
            folder = os.path.dirname(file_path)
            sha256 = record.get("sha256")
            source_tag = record.get("detection_source", DETECTION_SOURCE_EXISTING_SCAN)

            # Check for existing active incident on same path or sha256 (Duplicate suppression)
            existing_inc = self.inc_repo.get_active_incident_by_path_or_hash(file_path, sha256)
            if existing_inc:
                existing_inc = dict(existing_inc)
                # Update existing incident rather than creating a duplicate
                inc_id = existing_inc["id"]
                reason_text = record.get("reason") or record.get("threat_name") or "Threat signature identified"
                self.inc_repo.update_incident_counts(
                    incident_id=inc_id,
                    modified_add=1,
                    risk_score=max(existing_inc.get("risk_score", 0), record.get("risk_score", 0)),
                    severity=record.get("severity", existing_inc.get("severity")),
                    detection_reason=f"[{source_tag}] Re-evaluated threat: {reason_text}"
                )
                logger.info(f"Updated existing active incident {inc_id} for path {file_path}")
                return

            # Insert new incident
            reason_text = record.get("reason") or record.get("threat_name") or "Threat signature identified"
            detection_reason = f"[{source_tag}] {reason_text}"
            evidence_str = (
                f"Detection Source: {source_tag}\n"
                f"Context: Pre-existing endpoint file scan.\n"
                + "\n".join(record.get("evidence_list", []))
            )

            inc_id = self.inc_repo.insert_incident(
                threat_name=f"{record.get('threat_name', 'Unknown Threat')} ({source_tag})",
                severity=record.get("severity", "HIGH"),
                risk_score=record.get("risk_score", 80),
                affected_folder=folder,
                affected_file=record.get("filename") or os.path.basename(file_path),
                full_path=file_path,
                detection_reason=detection_reason,
                recommendation="Inspect file location. Quarantine or delete if unrecognized.",
                status="ACTIVE",
                verdict=record["verdict"],
                evidence=evidence_str,
                attribution_status="UNAVAILABLE",
                file_size=record["file_size"],
                sha256=record["sha256"],
                file_type=record["file_type"]
            )

            inc_dict = {
                "id": inc_id,
                "threat_name": f"{record['threat_name']} ({source_tag})",
                "severity": record["severity"],
                "affected_folder": folder,
                "affected_file": record["filename"],
                "verdict": record["verdict"],
                "detection_source": source_tag
            }
            AlertManager.trigger_incident_alert(inc_dict)

            self.history_repo.insert_log(
                event_type="EXISTING_THREAT_DETECTED",
                severity=record["severity"],
                description=f"[{source_tag}] {record['verdict']} file discovered in {folder}: '{record['filename']}' ({record['reason']})",
                target=file_path,
                action_taken="USER_ALERTED"
            )

            self.threat_detected.emit(record)
            logger.info(f"Created new incident {inc_id} for threat: {file_path}")
        except Exception as e:
            logger.error(f"Error handling existing threat: {e}", exc_info=True)
