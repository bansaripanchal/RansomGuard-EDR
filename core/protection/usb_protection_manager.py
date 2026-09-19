import os
import sys
import time
import hashlib
import logging
from typing import Optional, Dict, Any, List, Set
from PySide6.QtCore import QObject, QThread, Signal, QTimer

from core.monitoring.drive_manager import DriveManager
from core.analysis.file_analyzer import UnifiedFileAnalyzer
from core.detection.risk_engine import (
    RiskEngine, VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS, VERDICT_UNKNOWN
)
from core.database.database import DatabaseManager
from core.database.incidents_repository import IncidentsRepository
from core.database.history_repository import HistoryRepository
from core.protection.alert_manager import AlertManager

logger = logging.getLogger("RansomGuard.USBProtection")

DETECTION_SOURCE_INITIAL_SCAN = "USB Initial Scan"
DETECTION_SOURCE_REALTIME = "USB Real-Time Detection"


class USBDevice:
    """Represents a genuine physical removable storage device connected to the Windows endpoint."""
    def __init__(self, drive_letter: str, mount_point: str, volume_name: str,
                 file_system: str, total_bytes: int, free_bytes: int, used_percent: float):
        self.drive_letter = drive_letter.rstrip("\\")
        self.mount_point = mount_point
        self.volume_name = volume_name.strip() if volume_name else "Removable Disk"
        self.file_system = file_system.strip() if file_system else "Unknown"
        self.total_bytes = total_bytes
        self.free_bytes = free_bytes
        self.used_percent = used_percent
        self.connected_time = time.strftime("%H:%M:%S")
        # Status lifecycle: "Connected" -> "Scanning" -> "Protected" (or "Interrupted" / "Removed")
        # "Protected" is ONLY set once the initial assessment finishes and live protection is active.
        self.status = "Connected"

    @property
    def total_gb(self) -> float:
        return round(self.total_bytes / (1024 ** 3), 1) if self.total_bytes > 0 else 0.0

    @property
    def free_gb(self) -> float:
        return round(self.free_bytes / (1024 ** 3), 1) if self.free_bytes > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "drive_letter": self.drive_letter,
            "mount_point": self.mount_point,
            "volume_name": self.volume_name,
            "file_system": self.file_system,
            "total_bytes": self.total_bytes,
            "free_bytes": self.free_bytes,
            "total_gb": self.total_gb,
            "free_gb": self.free_gb,
            "used_percent": self.used_percent,
            "connected_time": self.connected_time,
            "status": self.status
        }


class USBScanWorker(QThread):
    """
    Background worker that executes the recursive initial security scan of a connected USB device.
    Uses exclusively the shared UnifiedFileAnalyzer and RiskEngine pipeline.
    """
    progress_updated = Signal(str, int, int) # (current_file_path, analyzed_count, discovered_count)
    scan_completed = Signal(dict)            # Summary dictionary
    scan_interrupted = Signal(str)          # Reason string (e.g. disconnected)
    threat_detected = Signal(dict)           # Emitted when a threat is identified

    def __init__(self, target_drive: str, scan_cache: Dict[str, Any], db_manager=None):
        super(USBScanWorker, self).__init__()
        self.target_drive = target_drive.rstrip("\\") + "\\"
        self.scan_cache = scan_cache
        self.db = db_manager or DatabaseManager()
        self.inc_repo = IncidentsRepository(self.db)
        self.history_repo = HistoryRepository(self.db)
        
        self.running = True
        self.interrupted_by_removal = False
        
        # Real statistics counters (preserved if interrupted)
        self.files_discovered = 0
        self.files_analyzed = 0
        self.clean_count = 0
        self.suspicious_count = 0
        self.malicious_count = 0
        self.unknown_count = 0
        self.records = []
        self.currently_analyzing_path: Optional[str] = None

    def stop(self, is_removal: bool = False):
        """Stops the worker safely."""
        self.running = False
        if is_removal:
            self.interrupted_by_removal = True

    def run(self):
        start_time = time.time()
        logger.info(f"USB Initial Scan starting on {self.target_drive}")

        # Check drive accessibility before beginning
        if not os.path.exists(self.target_drive):
            self.scan_interrupted.emit("Scan interrupted — USB device was disconnected.")
            return

        # Record scan started in audit history
        self.history_repo.insert_log(
            event_type="USB_SCAN_STARTED",
            severity="LOW",
            description=f"Initial security assessment started on removable drive {self.target_drive}",
            target=self.target_drive,
            action_taken="SCAN_STARTED"
        )

        # 1. Enumerate all accessible files recursively
        discovered_files: List[str] = []
        try:
            for root, dirs, files in os.walk(self.target_drive, topdown=True):
                if not self.running:
                    break
                # Prune OS volume artifact directories on USB storage
                dirs[:] = [
                    d for d in dirs
                    if d not in ("$RECYCLE.BIN", "System Volume Information", ".Spotlight-V100", ".Trashes", ".fseventsd")
                ]
                # Check drive presence continuously during directory walk
                if not os.path.exists(self.target_drive):
                    self.interrupted_by_removal = True
                    break
                for f in files:
                    if not self.running:
                        break
                    discovered_files.append(os.path.join(root, f))
        except Exception as e:
            logger.warning(f"Error enumerating files on {self.target_drive}: {e}")

        if self.interrupted_by_removal or not os.path.exists(self.target_drive):
            self._handle_removal_interruption()
            return

        if not self.running:
            return

        self.files_discovered = len(discovered_files)
        logger.info(f"Discovered {self.files_discovered} files on USB drive {self.target_drive}")

        # 2. Analyze each file through the Unified File Analyzer
        last_emit = 0.0
        for file_path in discovered_files:
            if not self.running:
                break
            
            # Continuous hardware availability check
            if not os.path.exists(self.target_drive):
                self.interrupted_by_removal = True
                break

            self.currently_analyzing_path = file_path
            record = self._analyze_usb_file(file_path, DETECTION_SOURCE_INITIAL_SCAN)
            self.currently_analyzing_path = None

            if record:
                self.records.append(record)
                self.files_analyzed += 1

                now = time.time()
                if (now - last_emit > 0.03) or (self.files_analyzed == 1) or (self.files_analyzed == self.files_discovered):
                    self.progress_updated.emit(file_path, self.files_analyzed, self.files_discovered)
                    last_emit = now

        if self.interrupted_by_removal or not os.path.exists(self.target_drive):
            self._handle_removal_interruption()
            return

        if not self.running:
            return

        duration = round(time.time() - start_time, 2)
        summary = {
            "target_drive": self.target_drive,
            "duration_sec": duration,
            "files_discovered": self.files_discovered,
            "files_analyzed": self.files_analyzed,
            "clean_count": self.clean_count,
            "suspicious_count": self.suspicious_count,
            "malicious_count": self.malicious_count,
            "unknown_count": self.unknown_count,
            "threats_found": self.suspicious_count + self.malicious_count,
            "records": self.records,
            "interrupted": False
        }

        # Log completion in history
        sev = "CRITICAL" if self.malicious_count > 0 else ("HIGH" if self.suspicious_count > 0 else "LOW")
        self.history_repo.insert_log(
            event_type="USB_SCAN_COMPLETED",
            severity=sev,
            description=(
                f"USB Initial Scan completed on {self.target_drive}. "
                f"Analyzed {self.files_analyzed} files (Clean: {self.clean_count}, "
                f"Suspicious: {self.suspicious_count}, Malicious: {self.malicious_count}, "
                f"Unknown: {self.unknown_count})."
            ),
            target=self.target_drive,
            action_taken="NO_ACTION" if (self.suspicious_count + self.malicious_count) == 0 else "USER_ALERTED"
        )

        logger.info(f"USB Initial Scan completed on {self.target_drive}. Scanned {self.files_analyzed} files.")
        self.scan_completed.emit(summary)

    def _handle_removal_interruption(self):
        """Handles graceful interruption if USB storage was unmounted during scan."""
        logger.warning(f"USB device {self.target_drive} was disconnected during scan.")
        self.history_repo.insert_log(
            event_type="USB_SCAN_INTERRUPTED",
            severity="LOW",
            description=f"USB scan on '{self.target_drive}' interrupted — device was disconnected. Discovered: {self.files_discovered}, Analyzed: {self.files_analyzed}.",
            target=self.target_drive,
            action_taken="SCAN_INTERRUPTED"
        )
        self.scan_interrupted.emit("Scan interrupted — USB device was disconnected.")

    def _analyze_usb_file(self, file_path: str, detection_source: str) -> Optional[Dict[str, Any]]:
        """
        Analyzes a single file using UnifiedFileAnalyzer + RiskEngine.
        Integrates multi-point cache validation (mtime, ctime, size, prefix hash)
        to prevent stale or invalid verdict reuse.
        """
        try:
            # File existence check
            if not os.path.exists(file_path):
                self.unknown_count += 1
                return {
                    "file_path": file_path,
                    "filename": os.path.basename(file_path),
                    "verdict": VERDICT_UNKNOWN,
                    "severity": "LOW",
                    "risk_score": 0,
                    "threat_name": "Inaccessible File",
                    "reason": "File was removed or inaccessible before analysis.",
                    "sha256": "Not available",
                    "file_type": "Unknown",
                    "file_size": 0,
                    "evidence_list": ["File not found on removable media."],
                    "detection_source": detection_source
                }

            stat_info = os.stat(file_path)
            current_mtime_ns = stat_info.st_mtime_ns
            current_ctime_ns = getattr(stat_info, "st_ctime_ns", 0)
            current_size = stat_info.st_size

            # Robust cache verification:
            # Never rely blindly on only mtime + size. Verify mtime, ctime, size, and prefix bytes.
            cached = self.scan_cache.get(file_path)
            if cached:
                mtime_match = (cached.get("mtime_ns") == current_mtime_ns)
                ctime_match = (cached.get("ctime_ns") == current_ctime_ns)
                size_match = (cached.get("size") == current_size)
                
                if mtime_match and ctime_match and size_match:
                    # Validate header chunk integrity
                    try:
                        with open(file_path, "rb") as f:
                            header_bytes = f.read(4096)
                        cur_prefix_hash = hashlib.sha256(header_bytes).hexdigest()
                        if cur_prefix_hash == cached.get("prefix_hash"):
                            rec = cached.get("record")
                            if rec:
                                v = rec.get("verdict")
                                if v == VERDICT_CLEAN:
                                    self.clean_count += 1
                                elif v == VERDICT_SUSPICIOUS:
                                    self.suspicious_count += 1
                                elif v == VERDICT_MALICIOUS:
                                    self.malicious_count += 1
                                else:
                                    self.unknown_count += 1
                                return rec
                    except Exception:
                        pass # Fall through to full re-analysis if header cannot be read

            # Run authentic static analysis via shared UnifiedFileAnalyzer
            analysis_res = UnifiedFileAnalyzer.analyze_file(file_path)

            # Determine verdict and risk score via RiskEngine
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

            if verdict == VERDICT_CLEAN:
                self.clean_count += 1
            elif verdict == VERDICT_SUSPICIOUS:
                self.suspicious_count += 1
            elif verdict == VERDICT_MALICIOUS:
                self.malicious_count += 1
            else:
                self.unknown_count += 1

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
                "static_indicators": analysis_res.static_indicators,
                "pe_info": analysis_res.pe_info,
                "detection_source": detection_source
            }

            # Calculate prefix integrity hash for cache
            try:
                with open(file_path, "rb") as f:
                    prefix_hash = hashlib.sha256(f.read(4096)).hexdigest()
            except Exception:
                prefix_hash = ""

            # Cache with complete integrity tuple
            self.scan_cache[file_path] = {
                "mtime_ns": current_mtime_ns,
                "ctime_ns": current_ctime_ns,
                "size": current_size,
                "prefix_hash": prefix_hash,
                "sha256": analysis_res.sha256,
                "verdict": verdict,
                "record": record
            }

            # If threat is detected (SUSPICIOUS or MALICIOUS), register incident & alert
            if verdict in (VERDICT_SUSPICIOUS, VERDICT_MALICIOUS):
                self._dispatch_threat_incident(record)
                self.threat_detected.emit(record)

            return record

        except Exception as e:
            logger.error(f"Error analyzing USB file '{file_path}': {e}")
            self.unknown_count += 1
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
                "threat_name": "Analysis Error",
                "reason": str(e),
                "evidence_list": [f"Analysis halted: {e}"],
                "static_indicators": [],
                "pe_info": None,
                "detection_source": detection_source
            }

    def _dispatch_threat_incident(self, record: Dict[str, Any]):
        """Dispatches genuine threat to Incident Repository and native AlertManager."""
        try:
            file_path = record["file_path"]
            folder = os.path.dirname(file_path)
            source_tag = record.get("detection_source", DETECTION_SOURCE_INITIAL_SCAN)
            
            detection_reason = (
                f"[{source_tag}] {record['reason']} "
                f"(Verdict: {record['verdict']}, SHA-256: {record['sha256'][:16]}...)"
            )
            
            evidence_str = (
                f"Detection Source: {source_tag}\n"
                f"Context: {'Pre-existing file on connected USB storage device.' if source_tag == DETECTION_SOURCE_INITIAL_SCAN else 'Real-time modification observed on USB storage.'}\n"
                + "\n".join(record["evidence_list"])
            )

            inc_id = self.inc_repo.insert_incident(
                threat_name=f"{record['threat_name']} ({source_tag})",
                severity=record["severity"],
                risk_score=record["risk_score"],
                affected_folder=folder,
                affected_file=record["filename"],
                full_path=file_path,
                detection_reason=detection_reason,
                recommendation="Inspect file signature and hash. Quarantine or remove from removable media if unrecognized.",
                status="ACTIVE",
                verdict=record["verdict"],
                evidence=evidence_str,
                attribution_status="AVAILABLE" if source_tag == DETECTION_SOURCE_REALTIME else "UNAVAILABLE",
                file_size=record["file_size"],
                sha256=record["sha256"],
                file_type=record["file_type"]
            )

            # Desktop notification
            inc_dict = {
                "id": inc_id,
                "threat_name": f"{record['threat_name']} ({source_tag})",
                "severity": record["severity"],
                "affected_folder": folder
            }
            AlertManager.trigger_incident_alert(inc_dict)

            # Audit history record
            self.history_repo.insert_log(
                event_type="USB_THREAT_DETECTED",
                severity=record["severity"],
                description=f"[{source_tag}] {record['verdict']} file on {folder}: '{record['filename']}' ({record['reason']})",
                target=file_path,
                action_taken="USER_ALERTED"
            )

            logger.info(f"Created threat incident ID {inc_id} for USB threat: {file_path}")
        except Exception as e:
            logger.error(f"Error dispatching USB threat incident: {e}", exc_info=True)


class USBProtectionManager(QObject):
    """
    Central controller for real-time USB storage detection, automatic initial scans,
    and continuous file event monitoring.
    """
    device_connected = Signal(object)      # USBDevice
    device_removed = Signal(str)           # drive_letter
    scan_started = Signal(str)             # drive_letter
    scan_progress = Signal(str, int, int)  # (current_file, analyzed_count, discovered_count)
    scan_finished = Signal(dict)           # summary
    scan_interrupted = Signal(str)         # reason
    threat_detected = Signal(dict)          # record
    _drives_discovered = Signal(list)      # Internal async dispatch

    _instance = None

    @classmethod
    def get_instance(cls, db_manager=None):
        if cls._instance is None:
            cls._instance = USBProtectionManager(db_manager)
        return cls._instance

    def __init__(self, db_manager=None, parent=None):
        super(USBProtectionManager, self).__init__(parent)
        self.db = db_manager or DatabaseManager()
        self.history_repo = HistoryRepository(self.db)
        self.inc_repo = IncidentsRepository(self.db)
        
        # State tracking
        self.connected_devices: Dict[str, USBDevice] = {}
        self.active_worker: Optional[USBScanWorker] = None
        self.scan_cache: Dict[str, Any] = {}
        self.last_scan_summary: Optional[Dict[str, Any]] = None
        self.last_scan_time: Optional[str] = None
        self.active_scan_drive: Optional[str] = None

        # Watchdog observer paths tracked for USB live monitoring
        self.monitored_usb_roots: Set[str] = set()

        # Connect internal async drive signal
        self._drives_discovered.connect(self._handle_discovered_drives)

        # Polling timer for reliable hardware device detection
        # Fires async background check without blocking GUI thread
        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(2500) # Check every 2.5 seconds
        self.poll_timer.timeout.connect(self._trigger_async_check)
        self.poll_timer.start()

        # Initial fast check from cache, then trigger background refresh
        self.check_usb_devices()

    def _trigger_async_check(self):
        """Dispatches non-blocking background drive check."""
        DriveManager.refresh_drives_async(callback=self._drives_discovered.emit)

    def check_usb_devices(self):
        """
        Fast non-blocking check using in-memory cached removable drives (<0.01 ms).
        Also dispatches an asynchronous background discovery to keep cache current.
        Never executes blocking Windows kernel APIs directly on the GUI thread.
        """
        try:
            current_removables = DriveManager.get_removable_drives_cached()
            self._handle_discovered_drives(current_removables)
            # Dispatch background refresh
            DriveManager.refresh_drives_async(callback=self._drives_discovered.emit)
        except Exception as e:
            logger.error(f"Error in fast USB device check: {e}")

    def _handle_discovered_drives(self, all_drives):
        """
        Executes on the GUI thread via queued signal.
        Processes verified removable drives and updates UI/device states.
        """
        try:
            current_removables = [d for d in all_drives if d.get("is_removable") and d.get("available")]
            current_letters = {d["letter"].upper(): d for d in current_removables}

            # 1. Check for removed devices
            removed_letters = [letter for letter in list(self.connected_devices.keys()) if letter not in current_letters]
            for letter in removed_letters:
                self._handle_device_removal(letter)

            # 2. Check for newly connected devices
            for letter, d_info in current_letters.items():
                if letter not in self.connected_devices:
                    device = USBDevice(
                        drive_letter=d_info["letter"],
                        mount_point=d_info["mount_point"],
                        volume_name=d_info["volume_name"],
                        file_system=d_info["file_system"],
                        total_bytes=d_info["total_bytes"],
                        free_bytes=d_info["free_bytes"],
                        used_percent=d_info["used_percent"]
                    )
                    self._handle_device_arrival(device)
                else:
                    # Update usage telemetry dynamically
                    dev = self.connected_devices[letter]
                    dev.free_bytes = d_info["free_bytes"]
                    dev.total_bytes = d_info["total_bytes"]
                    dev.used_percent = d_info["used_percent"]

        except Exception as e:
            logger.error(f"Error in USB device check handler: {e}")

    def on_device_change(self):
        """Slot invoked when Windows WM_DEVICECHANGE (0x0219) message fires."""
        logger.info("WM_DEVICECHANGE received. Refreshing USB devices asynchronously.")
        DriveManager.refresh_drives_async(callback=self._drives_discovered.emit)

    def _handle_device_arrival(self, device: USBDevice):
        """Executes workflow upon connection of a new USB device."""
        letter = device.drive_letter.upper()
        # Status begins as "Connected", will transition to "Scanning" and only to "Protected" on completion
        device.status = "Connected"
        self.connected_devices[letter] = device
        logger.info(f"USB device connected: {letter} ({device.volume_name})")

        # Audit log entry
        self.history_repo.insert_log(
            event_type="USB_CONNECTED",
            severity="LOW",
            description=f"Removable USB storage connected: {letter} ({device.volume_name}, {device.file_system}, {device.total_gb} GB)",
            target=letter,
            action_taken="DEVICE_MOUNTED"
        )

        self.device_connected.emit(device)

        # Trigger automatic initial security scan
        self.start_usb_scan(letter)

    def _handle_device_removal(self, letter: str):
        """Executes workflow upon disconnection of a USB device."""
        letter = letter.upper()
        device = self.connected_devices.pop(letter, None)
        logger.info(f"USB device removed: {letter}")

        # If currently scanning this drive, interrupt it immediately
        if self.active_scan_drive == letter and self.active_worker and self.active_worker.isRunning():
            logger.warning(f"Active scan drive {letter} was removed. Interrupting worker.")
            self.active_worker.stop(is_removal=True)

        # Remove live filesystem observer if bound
        self._detach_realtime_monitor(letter)

        # Invalidate scan cache for this disconnected drive
        keys_to_remove = [k for k in self.scan_cache if k.upper().startswith(letter)]
        for k in keys_to_remove:
            self.scan_cache.pop(k, None)

        if device:
            device.status = "Removed"

        # Audit log entry
        self.history_repo.insert_log(
            event_type="USB_REMOVED",
            severity="LOW",
            description=f"Removable USB storage disconnected: {letter}",
            target=letter,
            action_taken="DEVICE_UNMOUNTED"
        )

        self.device_removed.emit(letter)

    def start_usb_scan(self, drive_letter: str):
        """Starts recursive initial security scan of a connected USB device."""
        drive_letter = drive_letter.rstrip("\\")
        
        # Stop any prior scan
        if self.active_worker and self.active_worker.isRunning():
            self.active_worker.stop()
            self.active_worker.wait(1000)

        device = self.connected_devices.get(drive_letter.upper())
        if device:
            device.status = "Scanning"

        self.active_scan_drive = drive_letter.upper()
        self.active_worker = USBScanWorker(drive_letter, self.scan_cache, self.db)
        self.active_worker.progress_updated.connect(self._on_worker_progress)
        self.active_worker.scan_completed.connect(self._on_worker_completed)
        self.active_worker.scan_interrupted.connect(self._on_worker_interrupted)
        self.active_worker.threat_detected.connect(self.threat_detected)
        
        self.scan_started.emit(drive_letter)
        self.active_worker.start()

    def cancel_current_scan(self):
        """Cancels an ongoing scan requested by user."""
        if self.active_worker and self.active_worker.isRunning():
            self.active_worker.stop()
            self.active_worker.wait(1000)
            if self.active_scan_drive:
                device = self.connected_devices.get(self.active_scan_drive)
                if device:
                    device.status = "Interrupted"
            self.scan_interrupted.emit("Scan cancelled by administrator.")

    def _on_worker_progress(self, file_path, analyzed, discovered):
        self.scan_progress.emit(file_path, analyzed, discovered)

    def _on_worker_completed(self, summary):
        self.last_scan_summary = summary
        self.last_scan_time = time.strftime("%H:%M:%S")
        target_drive = summary.get("target_drive", "").rstrip("\\").upper()
        
        # Attach real-time monitoring to this USB drive
        self._attach_realtime_monitor(target_drive)

        device = self.connected_devices.get(target_drive)
        if device:
            # "Protected" is ONLY set when initial scan completed successfully AND live monitoring is active
            device.status = "Protected"

        self.scan_finished.emit(summary)
        logger.info(f"USB initial scan completed and protection active for {target_drive}")

    def _on_worker_interrupted(self, reason):
        target_drive = self.active_scan_drive
        if target_drive:
            device = self.connected_devices.get(target_drive)
            if device:
                device.status = "Interrupted"
        self.scan_interrupted.emit(reason)

    def _attach_realtime_monitor(self, drive_letter: str):
        """Hooks USB drive into MonitorManager for continuous real-time detection."""
        try:
            from core.monitoring.monitor_manager import MonitorManager
            mm = MonitorManager(self.db)
            root_path = drive_letter.rstrip("\\") + "\\"
            if os.path.exists(root_path):
                mm.file_monitor.add_path(root_path, recursive=True)
                self.monitored_usb_roots.add(root_path.upper())
                logger.info(f"Added USB drive {root_path} to real-time watchdog file monitor.")
        except Exception as e:
            logger.error(f"Failed to attach real-time monitor to USB drive {drive_letter}: {e}")

    def _detach_realtime_monitor(self, drive_letter: str):
        """Removes USB drive from MonitorManager watchdog monitor."""
        try:
            from core.monitoring.monitor_manager import MonitorManager
            mm = MonitorManager(self.db)
            root_path = drive_letter.rstrip("\\") + "\\"
            mm.file_monitor.remove_path(root_path)
            self.monitored_usb_roots.discard(root_path.upper())
            logger.info(f"Removed USB drive {root_path} from real-time watchdog file monitor.")
        except Exception as e:
            logger.debug(f"Error detaching real-time monitor for {drive_letter}: {e}")

    def analyze_realtime_event(self, file_path: str, event_type: str) -> Optional[Dict[str, Any]]:
        """
        Coordinates real-time file event analysis on a connected USB storage device:
        1. Prevents duplicate analysis while USBScanWorker is processing that exact file.
        2. Validates cache using robust integrity check (mtime, ctime, size, prefix hash).
        3. Submits uncached or modified files to UnifiedFileAnalyzer.
        4. Evaluates evidence via RiskEngine and tags verdict with USB Real-Time Detection source.
        """
        try:
            norm_path = os.path.normpath(file_path)
            drive_prefix = os.path.splitdrive(norm_path)[0].upper()
            if drive_prefix not in self.connected_devices:
                return None

            # Ignore deletions or directory notifications
            if event_type == "DELETE" or not os.path.exists(norm_path) or os.path.isdir(norm_path):
                self.scan_cache.pop(norm_path, None)
                return None

            # Coordinate with initial scan worker: prevent duplicate analysis if currently scanning
            if self.active_worker and self.active_worker.isRunning():
                if self.active_worker.currently_analyzing_path == norm_path:
                    return None # Already being analyzed by the scan worker right now

            stat_info = os.stat(norm_path)
            current_mtime_ns = stat_info.st_mtime_ns
            current_ctime_ns = getattr(stat_info, "st_ctime_ns", 0)
            current_size = stat_info.st_size

            # Robust cache verification: skip duplicate analysis if file has genuinely not changed
            cached = self.scan_cache.get(norm_path)
            if cached:
                mtime_match = (cached.get("mtime_ns") == current_mtime_ns)
                ctime_match = (cached.get("ctime_ns") == current_ctime_ns)
                size_match = (cached.get("size") == current_size)
                if mtime_match and ctime_match and size_match:
                    try:
                        with open(norm_path, "rb") as f:
                            hdr = f.read(4096)
                        if hashlib.sha256(hdr).hexdigest() == cached.get("prefix_hash"):
                            return cached.get("record")
                    except Exception:
                        pass

            # Execute unified file analysis
            analysis_res = UnifiedFileAnalyzer.analyze_file(norm_path)
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

            record = {
                "file_path": norm_path,
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
                "static_indicators": analysis_res.static_indicators,
                "pe_info": analysis_res.pe_info,
                "detection_source": DETECTION_SOURCE_REALTIME
            }

            try:
                with open(norm_path, "rb") as f:
                    pfx_hash = hashlib.sha256(f.read(4096)).hexdigest()
            except Exception:
                pfx_hash = ""

            self.scan_cache[norm_path] = {
                "mtime_ns": current_mtime_ns,
                "ctime_ns": current_ctime_ns,
                "size": current_size,
                "prefix_hash": pfx_hash,
                "sha256": analysis_res.sha256,
                "verdict": verdict,
                "record": record
            }

            if verdict in (VERDICT_SUSPICIOUS, VERDICT_MALICIOUS):
                folder = os.path.dirname(norm_path)
                inc_id = self.inc_repo.insert_incident(
                    threat_name=f"{threat_name} ({DETECTION_SOURCE_REALTIME})",
                    severity=severity,
                    risk_score=risk_score,
                    affected_folder=folder,
                    affected_file=record["filename"],
                    full_path=norm_path,
                    detection_reason=f"[{DETECTION_SOURCE_REALTIME}] {reason} (Verdict: {verdict})",
                    recommendation="Investigate suspicious file activity on removable drive.",
                    status="ACTIVE",
                    verdict=verdict,
                    evidence=f"Detection Source: {DETECTION_SOURCE_REALTIME}\n" + "\n".join(analysis_res.evidence_list),
                    attribution_status="AVAILABLE",
                    file_size=record["file_size"],
                    sha256=record["sha256"],
                    file_type=record["file_type"]
                )

                AlertManager.trigger_incident_alert({
                    "id": inc_id,
                    "threat_name": f"{threat_name} ({DETECTION_SOURCE_REALTIME})",
                    "severity": severity,
                    "affected_folder": folder
                })

                self.history_repo.insert_log(
                    event_type="USB_THREAT_DETECTED",
                    severity=severity,
                    description=f"[{DETECTION_SOURCE_REALTIME}] {verdict} file modified on {drive_prefix}: '{record['filename']}'",
                    target=norm_path,
                    action_taken="USER_ALERTED"
                )

                self.threat_detected.emit(record)

            return record

        except Exception as e:
            logger.error(f"Error analyzing real-time USB event on {file_path}: {e}")
            return None
