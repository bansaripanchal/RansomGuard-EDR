import logging
from config import (
    SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
    SUSPICIOUS_EXTENSIONS, CANARY_PATTERNS
)

logger = logging.getLogger("RansomGuard.RiskEngine")

VERDICT_CLEAN = "CLEAN"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_MALICIOUS = "MALICIOUS"
VERDICT_UNKNOWN = "UNKNOWN / UNABLE TO DETERMINE"


class RiskEngine:
    """
    Evidence-derived, deterministic risk assessment engine.
    Calculates numerical risk scores (0-100), severity levels, and verdicts
    strictly from observed static file characteristics and behavioral telemetry.
    No hardcoded or random scores; every point is backed by concrete evidence.
    """

    # Baseline guide weights for individual static rule indicators
    RULE_RISKS = {
        "KNOWN_MALWARE_HASH_MATCH": 95,
        "COMBINED_RANSOMWARE_BEHAVIOR": 90,
        "CANARY_FILE_TAMPERING": 50,
        "SUSPICIOUS_SCRIPT_HEURISTICS": 15,
        "RANSOM_NOTE_CREATION": 30,
        "MASS_RENAME_AND_MODIFY": 25,
        "MASS_FILE_RENAME": 20,
        "SUSPICIOUS_PE_CHARACTERISTICS": 20,
        "SUSPICIOUS_EXTENSION": 15,
        "MASS_FILE_MODIFICATION": 15,
        "RANSOM_NOTE_PATTERN": 30,
        "MASS_FILE_DELETION": 10,
        "MASS_FILE_CREATION": 5,
        "SUSPICIOUS_EXECUTABLE_NAME": 10
    }

    @classmethod
    def evaluate_evidence(cls, evidence_data: dict) -> dict:
        """
        Pure evidence-derived risk calculation function.
        Takes structured evidence telemetry and returns:
        - risk_score (int, 0-100)
        - severity (LOW, MEDIUM, HIGH, CRITICAL)
        - verdict (CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN)
        - evidence_lines (list of str, detailed audit trail)
        - primary_threat_name (str)
        - detection_reason (str)
        """
        created = int(evidence_data.get("created_count", 0))
        modified = int(evidence_data.get("modified_count", 0))
        renamed = int(evidence_data.get("renamed_count", 0))
        deleted = int(evidence_data.get("deleted_count", 0))
        duration_sec = max(0.1, float(evidence_data.get("duration_sec", 1.0)))

        ext_changes = int(evidence_data.get("extension_changes", 0))
        sus_exts = int(evidence_data.get("suspicious_extensions_count", 0))
        canary_events = evidence_data.get("canary_events", [])
        ransom_notes = evidence_data.get("ransom_notes", [])
        static_indicators = evidence_data.get("static_indicators", [])
        is_known_hash = bool(evidence_data.get("is_known_hash", False))
        is_accessible = bool(evidence_data.get("is_accessible", True))
        has_errors = bool(evidence_data.get("has_errors", False))

        evidence_lines = []
        score_points = 0
        threat_candidates = []

        # Inaccessible file / OS error handling
        if not is_accessible or has_errors:
            return {
                "risk_score": 0,
                "severity": SEVERITY_LOW,
                "verdict": VERDICT_UNKNOWN,
                "evidence_lines": ["• [ANALYSIS] File was inaccessible or locked during inspection (Verdict: UNKNOWN)"],
                "primary_threat_name": "Inaccessible / Unanalyzed File",
                "detection_reason": "File could not be opened or accessed for telemetry inspection."
            }

        # 1. Definitive Known Malware Hash Match (Cryptographic SHA-256)
        if is_known_hash:
            score_points += 95
            threat_name = evidence_data.get("threat_name", "Known Malware Hash Match")
            evidence_lines.append(f"• [STATIC_SIGNATURE] Known malicious SHA-256 hash match: '{threat_name}' (+95 risk)")
            threat_candidates.append(("Known Malicious Binary", 95, f"Known malware SHA-256 hash match: '{threat_name}'"))

        # 2. Canary / Tripwire Honeypot Tampering
        if canary_events:
            first_op, first_name = canary_events[0]
            score_points += 50
            evidence_lines.append(f"• [TRIPWIRE] Unauthorized {first_op.lower()} on registered EDR canary tripwire file '{first_name}' (+50 risk)")
            threat_candidates.append(("Canary / Tripwire File Tampering", 50, f"Unauthorized {first_op.lower()} on registered canary file '{first_name}'"))

            # Additional canary file interactions
            if len(canary_events) > 1:
                extra_pts = min(15, (len(canary_events) - 1) * 5)
                score_points += extra_pts
                evidence_lines.append(f"• [TRIPWIRE] Multiple canary files manipulated ({len(canary_events)} operations) (+{extra_pts} risk)")

            # Canary tampering occurring with concurrent background file operations
            total_ops = created + modified + renamed + deleted
            if total_ops >= 5:
                score_points += 15
                evidence_lines.append(f"• [CORRELATION] Canary tampering occurring alongside active burst activity ({total_ops} total operations) (+15 risk)")

        # 3. Mass File Modifications
        if modified >= 50:
            score_points += 35
            evidence_lines.append(f"• [BEHAVIORAL] Mass modification burst: {modified} files modified in {duration_sec:.1f}s (+35 risk)")
            threat_candidates.append(("Mass File Modification", 35, f"Mass modification of {modified} files in {duration_sec:.1f}s"))
        elif modified >= 20:
            score_points += 25
            evidence_lines.append(f"• [BEHAVIORAL] High modification volume: {modified} files modified in {duration_sec:.1f}s (+25 risk)")
            threat_candidates.append(("Mass File Modification", 25, f"High rate of file edits: {modified} files modified"))
        elif modified >= 5:
            score_points += 15
            evidence_lines.append(f"• [BEHAVIORAL] Elevated modification rate: {modified} files modified in {duration_sec:.1f}s (+15 risk)")

        # Modification speed booster
        if modified >= 10 and (modified / duration_sec) >= 5.0:
            score_points += 10
            evidence_lines.append(f"• [BEHAVIORAL] High-speed modification burst ({modified / duration_sec:.1f} files/sec) (+10 risk)")

        # 4. Renames & Extension Alterations
        if renamed >= 20:
            score_points += 35
            evidence_lines.append(f"• [BEHAVIORAL] Mass file rename burst: {renamed} files renamed in {duration_sec:.1f}s (+35 risk)")
            threat_candidates.append(("Rapid File Renaming", 35, f"Mass file renames: {renamed} files in {duration_sec:.1f}s"))
        elif renamed >= 5:
            score_points += 20
            evidence_lines.append(f"• [BEHAVIORAL] Rapid file renaming: {renamed} files renamed in {duration_sec:.1f}s (+20 risk)")
            threat_candidates.append(("Rapid File Renaming", 20, f"Rapid file renames: {renamed} files in {duration_sec:.1f}s"))
        elif renamed >= 2:
            score_points += 5
            evidence_lines.append(f"• [BEHAVIORAL] Minor rename activity: {renamed} files renamed (+5 risk)")

        # Extension mutations (e.g., .docx -> .locked, .xlsx -> .enc)
        if ext_changes >= 10:
            score_points += 25
            evidence_lines.append(f"• [BEHAVIORAL] Mass extension mutation storm: {ext_changes} files altered extensions (+25 risk)")
        elif ext_changes >= 3:
            score_points += 15
            evidence_lines.append(f"• [BEHAVIORAL] Extension mutation pattern detected on {ext_changes} files (+15 risk)")

        # Suspicious ransomware extensions
        if sus_exts >= 5:
            score_points += 25
            evidence_lines.append(f"• [STATIC_INDICATOR] Widespread known ransomware extensions ({sus_exts} files) (+25 risk)")
            threat_candidates.append(("Ransomware Encrypted Files", 25, f"Known ransomware extensions observed on {sus_exts} files"))
        elif sus_exts >= 1:
            score_points += 15
            evidence_lines.append(f"• [STATIC_INDICATOR] File matches known ransomware extension pattern (+15 risk)")
            threat_candidates.append(("Ransomware Extension Pattern", 15, "File matches known ransomware extension pattern"))

        # 5. Burst Deletions (Inhibiting file recovery)
        if deleted >= 20:
            score_points += 20
            evidence_lines.append(f"• [BEHAVIORAL] Burst file deletion storm: {deleted} files deleted in {duration_sec:.1f}s (+20 risk)")
            threat_candidates.append(("Burst File Deletion", 20, f"Burst deletion of {deleted} files"))
        elif deleted >= 5:
            score_points += 10
            evidence_lines.append(f"• [BEHAVIORAL] Elevated file deletion activity: {deleted} files deleted in {duration_sec:.1f}s (+10 risk)")

        # 6. Ransom Notes Creation
        if len(ransom_notes) >= 2:
            score_points += 40
            evidence_lines.append(f"• [HEURISTIC] Multiple ransom note files generated ({len(ransom_notes)} notes) (+40 risk)")
            threat_candidates.append(("Ransom Note Creation", 40, f"Multiple ransom notes detected: {', '.join(ransom_notes[:3])}"))
        elif len(ransom_notes) == 1:
            note_name = ransom_notes[0]
            score_points += 30
            evidence_lines.append(f"• [HEURISTIC] Potential ransom note creation pattern detected: '{note_name}' (+30 risk)")
            threat_candidates.append(("Ransom Note Creation", 30, f"Ransom note pattern detected: '{note_name}'"))

        # Correlated note with mass modifications/renames
        if ransom_notes and (modified >= 5 or renamed >= 5):
            score_points += 15
            evidence_lines.append("• [CORRELATION] Ransom note correlated with concurrent mass file edits/renames (+15 risk)")

        # 7. Multi-Vector Correlation Booster (Mass Renames + Mass Edits)
        if renamed >= 5 and modified >= 5:
            score_points += 15
            evidence_lines.append("• [CORRELATION] Multi-vector correlation: Rapid renaming occurring with mass edits (+15 risk)")
            if sus_exts >= 1 or ext_changes >= 3:
                threat_candidates.append(("Combined Ransomware Behavior", 90, "Simultaneous mass modifications, renaming, and extension alterations"))

        # 8. Static File Indicators (from UnifiedFileAnalyzer)
        for ind in static_indicators:
            r_name = ind.get("rule_name", "")
            reason = ind.get("reason", "")
            if r_name == "SUSPICIOUS_PE_CHARACTERISTICS":
                score_points += 20
                evidence_lines.append(f"• [STATIC_PE] {reason} (+20 risk)")
                threat_candidates.append(("Suspicious Executable Characteristics", 20, reason))
            elif r_name == "SUSPICIOUS_SCRIPT_HEURISTICS":
                score_points += 15
                evidence_lines.append(f"• [STATIC_SCRIPT] {reason} (+15 risk)")
                threat_candidates.append(("Suspicious Script Heuristics", 15, reason))
            elif r_name == "SUSPICIOUS_EXECUTABLE_NAME":
                score_points += 10
                evidence_lines.append(f"• [STATIC_INDICATOR] {reason} (+10 risk)")
                threat_candidates.append(("Suspicious Executable File", 10, reason))

        # Clamp deterministic score to [0, 100]
        final_score = min(100, max(0, score_points))

        # Severity Mapping
        if final_score >= 85:
            severity = SEVERITY_CRITICAL
        elif final_score >= 60:
            severity = SEVERITY_HIGH
        elif final_score >= 35:
            severity = SEVERITY_MEDIUM
        else:
            severity = SEVERITY_LOW

        # Deterministic Verdict Derivation
        # MALICIOUS: Known hash, canary tampering with burst activity or multiple canaries, or multi-vector mass corruption
        if is_known_hash:
            verdict = VERDICT_MALICIOUS
        elif canary_events and (len(canary_events) > 1 or (created + modified + renamed + deleted) >= 5):
            verdict = VERDICT_MALICIOUS
        elif renamed >= 5 and modified >= 5 and (sus_exts >= 1 or ext_changes >= 3):
            verdict = VERDICT_MALICIOUS
        elif final_score >= 80:
            verdict = VERDICT_MALICIOUS
        elif final_score >= 30:
            verdict = VERDICT_SUSPICIOUS
        else:
            verdict = VERDICT_CLEAN

        # Select primary threat name and detection reason
        threat_candidates.sort(key=lambda t: t[1], reverse=True)
        if threat_candidates:
            primary_threat_name = threat_candidates[0][0]
            detection_reason = threat_candidates[0][2]
        elif final_score >= 35:
            primary_threat_name = "Suspicious Filesystem Activity"
            detection_reason = f"Elevated activity observed ({created} creates, {modified} modifies, {renamed} renames, {deleted} deletes)."
        else:
            primary_threat_name = "Normal Filesystem Activity"
            detection_reason = "No anomalous or malicious indicators detected."

        if not evidence_lines:
            evidence_lines.append("• [BASELINE] Telemetry shows standard filesystem operations with no security anomalies.")

        return {
            "risk_score": final_score,
            "severity": severity,
            "verdict": verdict,
            "evidence_lines": evidence_lines,
            "primary_threat_name": primary_threat_name,
            "detection_reason": detection_reason
        }

    @classmethod
    def calculate_risk(cls, triggered_rules):
        """
        Backwards-compatible wrapper that translates triggered rule dicts into
        evidence points deterministically.
        """
        if not triggered_rules:
            return 0, SEVERITY_LOW

        # Extract telemetry counts if embedded in triggered_rules
        evidence = {
            "created_count": 0,
            "modified_count": 0,
            "renamed_count": 0,
            "deleted_count": 0,
            "canary_events": [],
            "ransom_notes": [],
            "static_indicators": [],
            "suspicious_extensions_count": 0,
            "is_known_hash": False
        }

        for r in triggered_rules:
            r_name = r.get("rule_name", "")
            if r_name == "KNOWN_MALWARE_HASH_MATCH":
                evidence["is_known_hash"] = True
                evidence["threat_name"] = r.get("threat_name", "Known Malware Hash")
            elif r_name == "CANARY_FILE_TAMPERING":
                evidence["canary_events"].append(("MODIFY", r.get("filename", "canary_decoy")))
                if r.get("canary_count", 0) > 1:
                    evidence["canary_events"].extend([("MODIFY", "extra_canary")] * (r.get("canary_count") - 1))
            elif r_name in ("RANSOM_NOTE_CREATION", "RANSOM_NOTE_PATTERN"):
                evidence["ransom_notes"].append(r.get("filename", "readme.txt"))
            elif r_name == "MASS_FILE_RENAME":
                evidence["renamed_count"] = max(evidence["renamed_count"], 20)
            elif r_name == "MASS_FILE_MODIFICATION":
                evidence["modified_count"] = max(evidence["modified_count"], 25)
            elif r_name == "MASS_FILE_DELETION":
                evidence["deleted_count"] = max(evidence["deleted_count"], 15)
            elif r_name == "MASS_FILE_CREATION":
                evidence["created_count"] = max(evidence["created_count"], 20)
            elif r_name in ("SUSPICIOUS_EXTENSION", "RANSOMWARE_EXTENSION_DETECTED"):
                evidence["suspicious_extensions_count"] = max(evidence["suspicious_extensions_count"], 1)
                evidence["extension_changes"] = max(evidence.get("extension_changes", 0), 1)
            elif r_name in ("SUSPICIOUS_PE_CHARACTERISTICS", "SUSPICIOUS_SCRIPT_HEURISTICS", "SUSPICIOUS_EXECUTABLE_NAME"):
                evidence["static_indicators"].append(r)

        res = cls.evaluate_evidence(evidence)
        score = res["risk_score"]
        if evidence["is_known_hash"]:
            score = 100
        return score, res["severity"]

    @classmethod
    def determine_verdict(cls, triggered_rules, is_accessible=True, has_errors=False):
        """
        Backwards-compatible wrapper to compute evidence-based verdict.
        """
        if not is_accessible or has_errors:
            return VERDICT_UNKNOWN

        if not triggered_rules:
            return VERDICT_CLEAN

        score, _ = cls.calculate_risk(triggered_rules)
        rule_names = {r.get("rule_name") for r in triggered_rules if r.get("rule_name")}

        if "KNOWN_MALWARE_HASH_MATCH" in rule_names:
            return VERDICT_MALICIOUS

        if "CANARY_FILE_TAMPERING" in rule_names:
            return VERDICT_MALICIOUS

        if "COMBINED_RANSOMWARE_BEHAVIOR" in rule_names:
            return VERDICT_MALICIOUS

        if "MASS_RENAME_AND_MODIFY" in rule_names and ("SUSPICIOUS_EXTENSION" in rule_names or "RANSOM_NOTE_CREATION" in rule_names):
            return VERDICT_MALICIOUS

        if score >= 80:
            return VERDICT_MALICIOUS

        if score >= 30 or any(r in rule_names for r in (
            "SUSPICIOUS_SCRIPT_HEURISTICS", "SUSPICIOUS_PE_CHARACTERISTICS",
            "SUSPICIOUS_EXTENSION", "RANSOMWARE_EXTENSION_DETECTED", "RANSOM_NOTE_PATTERN"
        )):
            return VERDICT_SUSPICIOUS

        return VERDICT_CLEAN
