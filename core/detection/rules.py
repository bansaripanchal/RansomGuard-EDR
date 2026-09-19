import os
from config import (
    THRESHOLD_MASS_CREATE, THRESHOLD_MASS_MODIFY, THRESHOLD_MASS_RENAME, THRESHOLD_MASS_DELETE,
    SUSPICIOUS_EXTENSIONS, SUSPICIOUS_NOTE_PATTERNS, CANARY_PATTERNS
)

class DetectionRules:
    @staticmethod
    def evaluate_directory_activity(events, duration_sec):
        """
        Analyzes a set of events occurring in a folder tree over duration_sec.
        Returns a list of triggered behavioral rules.
        """
        triggered = []
        
        # Count operations
        created = 0
        modified = 0
        renamed = 0
        deleted = 0
        suspicious_ext_count = 0
        ransom_notes = 0
        canary_tampered = []

        for event in events:
            # event is: (timestamp, event_type, src_path, dest_path, extension, file_size)
            _, event_type, src_path, dest_path, ext, _ = event
            
            if event_type == "CREATE":
                created += 1
            elif event_type == "MODIFY":
                modified += 1
            elif event_type == "RENAME":
                renamed += 1
            elif event_type == "DELETE":
                deleted += 1

            # Check for suspicious extensions
            if ext in SUSPICIOUS_EXTENSIONS:
                suspicious_ext_count += 1

            # Check for ransom note creation
            target_path = dest_path if dest_path else src_path
            filename = os.path.basename(target_path).lower() if target_path else ""
            for pattern in SUSPICIOUS_NOTE_PATTERNS:
                if pattern in filename:
                    ransom_notes += 1
                    break

            # Check for Canary / Decoy Tripwire tampering
            if any(p in filename for p in CANARY_PATTERNS):
                if event_type in ("MODIFY", "DELETE", "RENAME"):
                    canary_tampered.append((event_type, os.path.basename(target_path)))

        # Apply thresholds
        if created >= THRESHOLD_MASS_CREATE:
            triggered.append({
                "rule_name": "MASS_FILE_CREATION",
                "severity": "MEDIUM",
                "reason": f"High rate of file creations: {created} files in {duration_sec:.1f}s"
            })
            
        if modified >= THRESHOLD_MASS_MODIFY:
            triggered.append({
                "rule_name": "MASS_FILE_MODIFICATION",
                "severity": "MEDIUM",
                "reason": f"High rate of file modifications: {modified} files in {duration_sec:.1f}s"
            })
            
        if renamed >= THRESHOLD_MASS_RENAME:
            triggered.append({
                "rule_name": "MASS_FILE_RENAME",
                "severity": "HIGH",
                "reason": f"High rate of file renames: {renamed} files in {duration_sec:.1f}s"
            })
            
        if deleted >= THRESHOLD_MASS_DELETE:
            triggered.append({
                "rule_name": "MASS_FILE_DELETION",
                "severity": "MEDIUM",
                "reason": f"High rate of file deletions: {deleted} files in {duration_sec:.1f}s"
            })

        if suspicious_ext_count > 0:
            severity = "HIGH" if suspicious_ext_count >= 5 else "MEDIUM"
            triggered.append({
                "rule_name": "SUSPICIOUS_EXTENSION",
                "severity": severity,
                "reason": f"Files matching ransomware extension list: {suspicious_ext_count} files"
            })

        if ransom_notes > 0:
            triggered.append({
                "rule_name": "RANSOM_NOTE_CREATION",
                "severity": "HIGH",
                "reason": f"Potential ransomware instructions note detected: '{filename}'"
            })

        if canary_tampered:
            first_op, first_name = canary_tampered[0]
            triggered.append({
                "rule_name": "CANARY_FILE_TAMPERING",
                "severity": "HIGH",
                "reason": f"Unauthorized {first_op.lower()} on registered EDR canary tripwire file '{first_name}'.",
                "threat_name": "Canary / Tripwire File Tampering",
                "filename": first_name,
                "canary_count": len(canary_tampered),
                "canary_events": canary_tampered
            })

        # Combined Rule Correlators
        has_rename = any(r["rule_name"] == "MASS_FILE_RENAME" for r in triggered)
        has_modify = any(r["rule_name"] == "MASS_FILE_MODIFICATION" for r in triggered)
        has_sus_ext = any(r["rule_name"] == "SUSPICIOUS_EXTENSION" for r in triggered)

        if has_rename and has_modify and has_sus_ext:
            triggered.append({
                "rule_name": "COMBINED_RANSOMWARE_BEHAVIOR",
                "severity": "CRITICAL",
                "reason": "Simultaneous mass modifications, file renaming, and encryption-like extensions detected."
            })
        elif has_rename and has_modify:
            triggered.append({
                "rule_name": "MASS_RENAME_AND_MODIFY",
                "severity": "HIGH",
                "reason": "Mass file renaming occurring in conjunction with mass edits."
            })

        return triggered
