import os
import time
import logging
from PySide6.QtCore import QThread, Signal
from core.scanning.scan_exclusions import ScanExclusions
from core.analysis.file_analyzer import UnifiedFileAnalyzer
from core.detection.risk_engine import RiskEngine, VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS, VERDICT_UNKNOWN
from core.database.database import DatabaseManager
from core.database.history_repository import HistoryRepository
from core.database.incidents_repository import IncidentsRepository
from core.protection.alert_manager import AlertManager

logger = logging.getLogger("RansomGuard.Scanner")

class BackgroundScanner(QThread):
    # Signals
    progress_updated = Signal(str, int, int) # (current_file_path, files_scanned, threats_found)
    scan_completed = Signal(dict)            # results summary
    scan_error = Signal(str)

    def __init__(self, target_path, recursive=True, db_manager=None):
        super(BackgroundScanner, self).__init__()
        self.target_path = os.path.normpath(target_path)
        self.recursive = recursive
        self.db = db_manager or DatabaseManager()
        self.history_repo = HistoryRepository(self.db)
        self.inc_repo = IncidentsRepository(self.db)
        self.exclusions = ScanExclusions()
        
        self.running = False
        self.files_scanned = 0
        self.threats_found = 0
        self.clean_count = 0
        self.suspicious_count = 0
        self.malicious_count = 0
        self.unknown_count = 0
        self.scan_records = []

    def run(self):
        self.running = True
        self.files_scanned = 0
        self.threats_found = 0
        self.clean_count = 0
        self.suspicious_count = 0
        self.malicious_count = 0
        self.unknown_count = 0
        self.scan_records = []
        
        start_time = time.time()
        logger.info(f"Background scan started on: {self.target_path}")

        try:
            if os.path.isfile(self.target_path):
                self._scan_file(self.target_path)
            elif os.path.isdir(self.target_path):
                self._scan_directory(self.target_path)
            else:
                self.scan_error.emit(f"Invalid scan target: {self.target_path}")
                return

            duration = time.time() - start_time
            is_single = os.path.isfile(self.target_path)
            results = {
                "target_path": self.target_path,
                "is_single_file": is_single,
                "files_scanned": self.files_scanned,
                "threats_found": self.threats_found,
                "clean_count": self.clean_count,
                "suspicious_count": self.suspicious_count,
                "malicious_count": self.malicious_count,
                "unknown_count": self.unknown_count,
                "scan_records": self.scan_records,
                "detected_threats": [r for r in self.scan_records if r["verdict"] in (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS)],
                "single_file_result": self.scan_records[0] if (is_single and self.scan_records) else None,
                "duration_sec": round(duration, 2)
            }
            
            # Log scan completion in EDR history audit log (one consolidated entry per scan session)
            sev = "LOW" if self.threats_found == 0 else ("CRITICAL" if self.malicious_count > 0 else "HIGH")
            self.history_repo.insert_log(
                event_type="SECURITY_SCAN",
                severity=sev,
                description=f"[Scan Center] Scan completed \u2014 {self.files_scanned} files scanned, {self.suspicious_count} suspicious, {self.malicious_count} malicious.",
                target=self.target_path,
                action_taken="NO_ACTION" if self.threats_found == 0 else "USER_ALERTED"
            )
            
            self.scan_completed.emit(results)
            logger.info(f"Background scan completed on: {self.target_path}. Scanned: {self.files_scanned}, Threats: {self.threats_found}")
            
        except Exception as e:
            logger.error(f"Error during scanning: {e}", exc_info=True)
            self.scan_error.emit(str(e))

    def stop(self):
        self.running = False

    def _scan_directory(self, dir_path):
        last_emit_time = 0.0
        
        if self.recursive:
            for root, dirs, files in os.walk(dir_path, topdown=True):
                if not self.running:
                    break
                
                # Prune excluded directories (e.g. .git, node_modules, temp caches)
                dirs[:] = [
                    d for d in dirs
                    if not self.exclusions.should_exclude_directory(os.path.join(root, d))[0]
                ]

                for file in files:
                    if not self.running:
                        break
                    file_path = os.path.join(root, file)
                    
                    # Skip excluded system files
                    is_excl, _ = self.exclusions.should_exclude_file(file_path)
                    if is_excl:
                        continue

                    self._scan_file(file_path)
                    
                    # Throttle progress signals (max once every 100ms or on threat) to keep GUI responsive
                    now = time.time()
                    if now - last_emit_time > 0.10:
                        self.progress_updated.emit(file_path, self.files_scanned, self.threats_found)
                        last_emit_time = now
        else:
            try:
                for entry in os.scandir(dir_path):
                    if not self.running:
                        break
                    if entry.is_file():
                        file_path = entry.path
                        is_excl, _ = self.exclusions.should_exclude_file(file_path)
                        if is_excl:
                            continue

                        self._scan_file(file_path)
                        
                        now = time.time()
                        if now - last_emit_time > 0.10:
                            self.progress_updated.emit(file_path, self.files_scanned, self.threats_found)
                            last_emit_time = now
            except PermissionError as e:
                logger.error(f"Permission denied accessing directory {dir_path}: {e}")

    def _scan_file(self, file_path):
        """
        Executes genuine static file analysis using UnifiedFileAnalyzer
        and determines evidence-based verdict via RiskEngine.
        """
        try:
            self.files_scanned += 1
            
            # Central Unified File Analysis
            analysis_res = UnifiedFileAnalyzer.analyze_file(file_path)
            
            # Evaluate verdict and risk score
            verdict = RiskEngine.determine_verdict(
                analysis_res.static_indicators, 
                is_accessible=analysis_res.accessible, 
                has_errors=bool(analysis_res.error)
            )
            risk_score, severity = RiskEngine.calculate_risk(analysis_res.static_indicators)
            
            if verdict == VERDICT_CLEAN:
                self.clean_count += 1
            elif verdict == VERDICT_SUSPICIOUS:
                self.suspicious_count += 1
                self.threats_found += 1
            elif verdict == VERDICT_MALICIOUS:
                self.malicious_count += 1
                self.threats_found += 1
            else:
                self.unknown_count += 1

            threat_name = "Clean File"
            reason = "No security threat detected."
            if analysis_res.static_indicators:
                threat_name = analysis_res.static_indicators[0].get("threat_name", "Security Threat")
                reason = analysis_res.static_indicators[0].get("reason", "Suspicious indicator detected.")
            elif verdict == VERDICT_UNKNOWN:
                threat_name = "Unanalyzed File"
                reason = analysis_res.error or "Unable to read file content."

            record = {
                "file_path": file_path,
                "filename": analysis_res.filename,
                "extension": analysis_res.extension,
                "file_size": analysis_res.size,
                "file_type": analysis_res.detected_file_type,
                "sha256": analysis_res.sha256 or "N/A",
                "md5": analysis_res.md5 or "N/A",
                "verdict": verdict,
                "severity": severity if verdict != VERDICT_CLEAN else "LOW",
                "risk_score": risk_score if verdict != VERDICT_CLEAN else 0,
                "threat_name": threat_name,
                "reason": reason,
                "evidence_list": analysis_res.evidence_list,
                "static_indicators": analysis_res.static_indicators,
                "pe_info": analysis_res.pe_info,
                "yara_status": analysis_res.yara_status,
                "reputation_status": analysis_res.reputation_status,
                "detection_source": "Scan Center"
            }
            self.scan_records.append(record)

            # If threat detected during manual scan, register incident and alert
            if verdict in (VERDICT_SUSPICIOUS, VERDICT_MALICIOUS):
                try:
                    folder = os.path.dirname(file_path)
                    existing_inc = self.inc_repo.get_active_incident_by_path_or_hash(file_path, analysis_res.sha256)
                    if existing_inc:
                        existing_inc = dict(existing_inc)
                        inc_id = existing_inc["id"]
                        record["incident_id"] = inc_id
                        self.inc_repo.update_incident_counts(
                            incident_id=inc_id,
                            modified_add=1,
                            risk_score=max(existing_inc.get("risk_score", 0), record.get("risk_score", 0)),
                            severity=record.get("severity", existing_inc.get("severity")),
                            detection_reason=f"[Scan Center] Re-evaluated threat: {reason}"
                        )
                        logger.info(f"Re-used existing active incident {inc_id} for path: {file_path}")
                    else:
                        detection_reason = f"[Scan Center] {reason} (Verdict: {verdict}, SHA-256: {record['sha256'][:16]}...)"
                        evidence_str = "Detection Source: Scan Center\nContext: Manual on-demand scan via Scan Center.\n" + "\n".join(analysis_res.evidence_list)
                        inc_id = self.inc_repo.insert_incident(
                            threat_name=f"{threat_name} (Scan Center)",
                            severity=record["severity"],
                            risk_score=record["risk_score"],
                            affected_folder=folder,
                            affected_file=analysis_res.filename,
                            full_path=file_path,
                            detection_reason=detection_reason,
                            recommendation="Inspect file location and signature. Quarantine or remove if unrecognized.",
                            status="ACTIVE",
                            verdict=verdict,
                            evidence=evidence_str,
                            attribution_status="UNAVAILABLE",
                            file_size=analysis_res.size,
                            sha256=analysis_res.sha256,
                            file_type=analysis_res.detected_file_type
                        )
                        record["incident_id"] = inc_id
                        AlertManager.trigger_incident_alert({
                            "id": inc_id,
                            "threat_name": f"{threat_name} (Scan Center)",
                            "severity": record["severity"],
                            "affected_folder": folder,
                            "affected_file": analysis_res.filename,
                            "verdict": verdict,
                            "detection_source": "Scan Center",
                            "alert_title": f"RansomGuard - MANUAL SCAN THREAT DETECTED",
                            "alert_message": f"File: {analysis_res.filename}\nVerdict: {verdict}\nDetection Source: Scan Center\nTarget: {folder}",
                            "scan_target": self.target_path
                        })
                except Exception as ex:
                    logger.error(f"Error dispatching manual scan threat: {ex}")

        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            self.unknown_count += 1
            self.scan_records.append({
                "file_path": file_path,
                "filename": os.path.basename(file_path),
                "extension": os.path.splitext(file_path)[1].lower(),
                "file_size": 0,
                "file_type": "Unknown",
                "sha256": "N/A",
                "md5": "N/A",
                "verdict": VERDICT_UNKNOWN,
                "severity": "LOW",
                "risk_score": 0,
                "threat_name": "Analysis Error",
                "reason": str(e),
                "evidence_list": [f"Error: {e}"],
                "static_indicators": [],
                "pe_info": None,
                "yara_status": "NOT_CONFIGURED",
                "reputation_status": "NOT_AVAILABLE"
            })
