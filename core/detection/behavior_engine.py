import os
import time
import hashlib
import collections
import logging
from config import (
    DETECTION_WINDOW_SEC, SUSPICIOUS_EXTENSIONS, CANARY_PATTERNS, SUSPICIOUS_NOTE_PATTERNS
)
from core.analysis.file_analyzer import UnifiedFileAnalyzer, KNOWN_MALICIOUS_HASHES
from core.detection.rules import DetectionRules
from core.detection.risk_engine import (
    RiskEngine, VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS, VERDICT_UNKNOWN
)
from core.database.incidents_repository import IncidentsRepository
from core.database.events_repository import EventsRepository

logger = logging.getLogger("RansomGuard.BehaviorEngine")

class BehaviorEngine:
    def __init__(self, db_manager=None, process_monitor=None):
        self.incidents_repo = IncidentsRepository(db_manager)
        self.events_repo = EventsRepository(db_manager)
        self.process_monitor = process_monitor

        # Sliding window of events: tuples with timestamp and event metadata
        self.event_window = collections.deque()

    def _analyze_file_for_threat(self, event_type, src_path, dest_path, extension, file_size):
        """
        Analyzes a single file event using real evidence and malware indicators.
        Returns a dict of rule info if threat detected, else None.
        Does NOT hardcode static risk scores.
        """
        if event_type not in ("CREATE", "MODIFY", "RENAME", "DELETE"):
            return None

        target_path = dest_path if (event_type == "RENAME" and dest_path) else src_path
        if not target_path:
            return None

        target_path = os.path.normpath(os.path.abspath(target_path))
        filename = os.path.basename(target_path)
        fname_lower = filename.lower()
        ext = extension.lower() if extension else ""

        # 1. Behavioral Canary / Decoy Tripwire Tampering
        if event_type in ("MODIFY", "DELETE", "RENAME"):
            if any(pat in fname_lower for pat in CANARY_PATTERNS):
                return {
                    "rule_name": "CANARY_FILE_TAMPERING",
                    "severity": "CRITICAL",
                    "reason": f"Unauthorized {event_type.lower()} operation on EDR canary tripwire file '{filename}'.",
                    "recommendation": f"Inspect active processes. Verify integrity of '{filename}' and isolate suspicious host activity.",
                    "threat_name": "Canary / Tripwire File Tampering",
                    "evidence_type": "BEHAVIORAL_TRIPWIRE",
                    "filename": filename,
                    "op": event_type,
                    "target_path": target_path
                }

        # 2. Suspicious executable naming heuristics
        is_script = ext in (".ps1", ".bat", ".vbs", ".js", ".cmd")
        is_executable = ext in (".exe", ".scr", ".dll", ".sys")
        if (is_executable or is_script) and event_type in ("CREATE", "MODIFY", "RENAME"):
            if any(k in fname_lower for k in ("malware", "ransom", "wannacry", "cryptor", "payload")):
                return {
                    "rule_name": "SUSPICIOUS_EXECUTABLE_NAME",
                    "severity": "HIGH",
                    "reason": f"File '{filename}' matches known malicious naming patterns.",
                    "recommendation": f"Scan the host system. Terminate unauthorized executions of '{filename}'.",
                    "threat_name": "Suspicious Executable File",
                    "evidence_type": "STATIC_INDICATOR",
                    "filename": filename,
                    "target_path": target_path
                }

        # Check canary header marker in file content if file exists
        if os.path.exists(target_path) and not os.path.isdir(target_path):
            try:
                with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                    header_snippet = f.read(512).lower()
                if "ransomguard_canary" in header_snippet or "canary_tripwire" in header_snippet or "tampered_by_simulator" in header_snippet:
                    if event_type in ("MODIFY", "RENAME", "DELETE"):
                        return {
                            "rule_name": "CANARY_FILE_TAMPERING",
                            "severity": "CRITICAL",
                            "reason": f"Tampering detected on file containing EDR canary tripwire signatures: '{filename}'.",
                            "recommendation": f"Inspect active processes touching canary files. Isolate suspicious host activity.",
                            "threat_name": "Canary / Tripwire File Tampering",
                            "evidence_type": "BEHAVIORAL_TRIPWIRE",
                            "filename": filename,
                            "op": event_type,
                            "target_path": target_path
                        }
            except Exception:
                pass

            # 3. Perform Deep Static Analysis via Central UnifiedFileAnalyzer
            static_res = UnifiedFileAnalyzer.analyze_file(target_path)
            if static_res.static_indicators:
                primary_ind = static_res.static_indicators[0]
                primary_ind["sha256"] = static_res.sha256
                primary_ind["evidence_list"] = static_res.evidence_list
                primary_ind["file_type"] = static_res.detected_file_type
                primary_ind["file_size"] = static_res.size
                primary_ind["target_path"] = target_path
                return primary_ind

        # 4. Ransomware-related extensions
        if ext in SUSPICIOUS_EXTENSIONS and event_type in ("CREATE", "MODIFY", "RENAME"):
            return {
                "rule_name": "RANSOMWARE_EXTENSION_DETECTED",
                "severity": "HIGH",
                "reason": f"File '{filename}' matches known ransomware extension '{ext}'.",
                "recommendation": f"Inspect active processes. Restore '{filename}' from a verified backup.",
                "threat_name": "Ransomware Encrypted File",
                "evidence_type": "STATIC_INDICATOR",
                "filename": filename,
                "target_path": target_path
            }

        return None

    def process_new_events(self, events):
        """
        Processes incoming file events using real evidence correlation:
        1. Groups events by directory hierarchy over sliding time window.
        2. Gathers concrete behavioral telemetry counts and static file indicators.
        3. Evaluates evidence deterministically via RiskEngine.
        4. Correlates real Windows processes using ProcessMonitor without guessing.
        5. Preserves full canonical absolute paths and authentic file sizes.
        """
        now = time.time()
        for event in events:
            # event is 6-tuple or 10-tuple
            self.event_window.append((now, *event))

        # Evict events outside detection window
        while self.event_window and (now - self.event_window[0][0]) > DETECTION_WINDOW_SEC:
            self.event_window.popleft()

        if not self.event_window:
            return []

        # Group events by canonical parent directory
        folder_groups = collections.defaultdict(list)
        for ev in self.event_window:
            src_path = ev[2]
            parent_dir = os.path.normpath(os.path.abspath(os.path.dirname(src_path)))
            folder_groups[parent_dir].append(ev)

        detected_incidents = []

        for folder, folder_events in folder_groups.items():
            # 1. Gather Concrete Behavioral Telemetry Evidence
            created_count = sum(1 for e in folder_events if e[2] == "CREATE" or (len(e) > 1 and e[1] == "CREATE"))
            # Correct event index unpacking: (timestamp, event_type, src_path, dest_path, extension, file_size, ...)
            created_count = 0
            modified_count = 0
            renamed_count = 0
            deleted_count = 0
            ext_changes = 0
            sus_ext_count = 0
            canary_events = []
            ransom_notes = []
            static_indicators = []
            individual_threat = None
            is_known_hash = False

            oldest_ts = folder_events[0][0]
            newest_ts = folder_events[-1][0]
            duration_sec = max(0.1, newest_ts - oldest_ts)

            for ev_wrapper in folder_events:
                ev_ts = ev_wrapper[0]
                ev_type = ev_wrapper[1]
                s_path = ev_wrapper[2]
                d_path = ev_wrapper[3]
                ext = (ev_wrapper[4] or "").lower()
                f_size = ev_wrapper[5]

                target = d_path if (ev_type == "RENAME" and d_path) else s_path
                fname = os.path.basename(target).lower()

                if ev_type == "CREATE":
                    created_count += 1
                elif ev_type == "MODIFY":
                    modified_count += 1
                elif ev_type == "RENAME":
                    renamed_count += 1
                    if d_path:
                        _, old_ext = os.path.splitext(s_path)
                        _, new_ext = os.path.splitext(d_path)
                        if old_ext.lower() != new_ext.lower():
                            ext_changes += 1
                elif ev_type == "DELETE":
                    deleted_count += 1

                # Check suspicious extension
                if ext in SUSPICIOUS_EXTENSIONS:
                    sus_ext_count += 1

                # Check canary pattern
                if any(p in fname for p in CANARY_PATTERNS):
                    if ev_type in ("MODIFY", "DELETE", "RENAME"):
                        canary_events.append((ev_type, os.path.basename(target)))

                # Check ransom note pattern
                if any(p in fname for p in SUSPICIOUS_NOTE_PATTERNS):
                    ransom_notes.append(os.path.basename(target))

                # Analyze individual threat
                th = self._analyze_file_for_threat(ev_type, s_path, d_path, ext, f_size)
                if th:
                    if th.get("rule_name") == "KNOWN_MALWARE_HASH_MATCH":
                        is_known_hash = True
                    static_indicators.append(th)
                    if not individual_threat:
                        individual_threat = (th, os.path.normpath(os.path.abspath(target)))

            # Build Evidence Dictionary
            evidence_data = {
                "created_count": created_count,
                "modified_count": modified_count,
                "renamed_count": renamed_count,
                "deleted_count": deleted_count,
                "duration_sec": duration_sec,
                "extension_changes": ext_changes,
                "suspicious_extensions_count": sus_ext_count,
                "canary_events": canary_events,
                "ransom_notes": list(set(ransom_notes)),
                "static_indicators": static_indicators,
                "is_known_hash": is_known_hash,
                "is_accessible": True,
                "has_errors": False
            }

            # 2. Evaluate Evidence via RiskEngine
            eval_res = RiskEngine.evaluate_evidence(evidence_data)
            risk_score = eval_res["risk_score"]
            severity = eval_res["severity"]
            verdict = eval_res["verdict"]
            threat_name = eval_res["primary_threat_name"]
            detection_reason = eval_res["detection_reason"]
            evidence_text = "\n".join(eval_res["evidence_lines"])

            # 3. Filter out clean or ordinary filesystem events
            if verdict == VERDICT_CLEAN and risk_score < 35:
                continue

            # Determine affected file and canonical full absolute path
            if len(folder_events) == 1 and individual_threat:
                _, full_path = individual_threat
                affected_file = os.path.basename(full_path)
            elif len(folder_events) > 1:
                affected_file = "Multiple Files"
                full_path = folder
            else:
                full_path = os.path.normpath(os.path.abspath(folder_events[0][2]))
                affected_file = os.path.basename(full_path)

            # 4. Genuine Process Attribution (No fake names or fabricated PIDs)
            process_pid = None
            process_name = "Unknown"
            attribution_status = "UNAVAILABLE"

            # Check if any event in this folder had process attribution attached
            for ev_wrapper in folder_events:
                if len(ev_wrapper) >= 11:
                    p_name = ev_wrapper[8]
                    p_pid = ev_wrapper[9]
                    p_status = ev_wrapper[10]
                    if p_name and p_name != "Unknown":
                        process_name = p_name
                        process_pid = p_pid
                        attribution_status = p_status or "CORRELATED"
                        break

            # If still Unknown, query live ProcessMonitor for open handles / working directory
            if process_name == "Unknown" and self.process_monitor:
                try:
                    pinfo = self.process_monitor.find_process_accessing_path(full_path)
                    if pinfo:
                        process_name = pinfo.get("name") or "Unknown"
                        process_pid = pinfo.get("pid")
                        attribution_status = pinfo.get("attribution_status") or "CORRELATED"
                except Exception as e:
                    logger.debug(f"Process attribution query error: {e}")

            # 5. Real File Size, SHA-256, and File Type
            file_size = None
            sha256 = None
            file_type = None

            if individual_threat:
                file_size = individual_threat[0].get("file_size")
                sha256 = individual_threat[0].get("sha256")
                file_type = individual_threat[0].get("file_type")

            if file_size is None and full_path and os.path.exists(full_path) and not os.path.isdir(full_path):
                try:
                    file_size = os.path.getsize(full_path)
                except Exception:
                    file_size = None

            recommendation = (
                "Investigate recently executed applications, batch files, or background tasks in the directory. "
                "Review affected files and restore uncorrupted copies from verified backup."
            )

            # Check if active incident already exists for this folder
            existing_incident = self.incidents_repo.get_active_incident_by_folder(folder, age_seconds=60)
            
            if existing_incident:
                incident_id = existing_incident["id"]
                self.incidents_repo.update_incident_counts(
                    incident_id=incident_id,
                    created_add=created_count,
                    modified_add=modified_count,
                    renamed_add=renamed_count,
                    deleted_add=deleted_count,
                    risk_score=max(existing_incident["risk_score"], risk_score),
                    severity=severity if RiskEngine.RULE_RISKS.get(severity, 0) > RiskEngine.RULE_RISKS.get(existing_incident["severity"], 0) else None,
                    detection_reason=detection_reason,
                    verdict=verdict,
                    evidence=evidence_text,
                    attribution_status=attribution_status if process_name != "Unknown" else None,
                    file_size=file_size,
                    sha256=sha256,
                    file_type=file_type,
                    process_name=process_name if process_name != "Unknown" else None,
                    process_pid=process_pid if process_name != "Unknown" else None
                )
                logger.info(f"Coalesced events in {folder} to active incident ID {incident_id} (Score: {risk_score}, Verdict: {verdict})")
                updated_inc = self.incidents_repo.get_incident(incident_id)
                detected_incidents.append((updated_inc, False))
            else:
                incident_id = self.incidents_repo.insert_incident(
                    threat_name=threat_name,
                    severity=severity,
                    risk_score=risk_score,
                    affected_folder=folder,
                    affected_file=affected_file,
                    full_path=full_path,
                    detection_reason=detection_reason,
                    created_count=created_count,
                    modified_count=modified_count,
                    renamed_count=renamed_count,
                    deleted_count=deleted_count,
                    process_pid=process_pid,
                    process_name=process_name,
                    recommendation=recommendation,
                    verdict=verdict,
                    evidence=evidence_text,
                    attribution_status=attribution_status,
                    file_size=file_size,
                    sha256=sha256,
                    file_type=file_type
                )
                logger.info(f"Created new incident ID {incident_id} for {folder} (Score: {risk_score}, Verdict: {verdict})")
                new_inc = self.incidents_repo.get_incident(incident_id)
                detected_incidents.append((new_inc, True))

        return detected_incidents
