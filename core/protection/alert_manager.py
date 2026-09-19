import logging
from plyer import notification

logger = logging.getLogger("RansomGuard.AlertManager")

class AlertManager:
    _notified_incident_ids = set()
    _notified_fingerprints = set()
    _notified_scan_targets = set()

    @classmethod
    def reset_dedup_cache(cls):
        """Clears notification deduplication tracking sets (useful for testing or full engine reset)."""
        cls._notified_incident_ids.clear()
        cls._notified_fingerprints.clear()
        cls._notified_scan_targets.clear()

    @classmethod
    def trigger_incident_alert(cls, incident_data):
        """Displays a native Windows toast notification for security incidents, suppressing duplicates."""
        import sys
        import os
        if "unittest" in sys.modules or os.environ.get("RANSOMGUARD_DISABLE_TOAST", "").lower() == "true":
            logger.info("Automated execution detected. Skipping native toast alert.")
            return

        # 1. Deduplication check by incident ID
        inc_id = incident_data.get("id") or incident_data.get("incident_id")
        if inc_id is not None:
            if inc_id in cls._notified_incident_ids:
                logger.info(f"Duplicate notification suppressed for incident ID: {inc_id}")
                return

        # 2. Deduplication check by scan target / session to avoid multi-file alert storms
        scan_target = incident_data.get("scan_target")
        if scan_target and scan_target in cls._notified_scan_targets:
            logger.info(f"Duplicate notification suppressed for active scan target session: {scan_target}")
            return

        # 3. Deduplication check by detection fingerprint (path, SHA-256, threat name)
        path = incident_data.get("full_path") or incident_data.get("affected_file") or incident_data.get("target") or ""
        sha = incident_data.get("sha256") or ""
        threat_name = incident_data.get("threat_name", "Suspicious Activity")
        fingerprint = (str(path).strip().lower(), str(sha).strip().lower(), str(threat_name).strip().lower())

        if any(fingerprint[:2]):  # If path or sha is available
            if fingerprint in cls._notified_fingerprints:
                logger.info(f"Duplicate notification suppressed for detection fingerprint: {path} ({threat_name})")
                return

        # Register notification to prevent repeats from UI refresh, page reopening, or DB queries
        if inc_id is not None:
            cls._notified_incident_ids.add(inc_id)
        if scan_target:
            cls._notified_scan_targets.add(scan_target)
        if any(fingerprint[:2]):
            cls._notified_fingerprints.add(fingerprint)

        severity = incident_data.get("severity", "MEDIUM")
        folder = incident_data.get("affected_folder", "Monitored Directory")
        source = incident_data.get("detection_source")

        if source == "Existing File Scan":
            title = f"RansomGuard - EXISTING THREAT DETECTED"
            message = (
                f"File: {incident_data.get('affected_file', 'Unknown')}\n"
                f"Verdict: {incident_data.get('verdict', 'SUSPICIOUS')}\n"
                f"Detection Source: Existing File Scan\n"
                f"Target: {folder}"
            )
        else:
            title = incident_data.get("alert_title") or f"RansomGuard EDR - {severity} Threat!"
            message = incident_data.get("alert_message") or f"Activity: {threat_name}\nTarget: {folder}"

        try:
            notification.notify(
                title=title,
                message=message,
                app_name="RansomGuard",
                timeout=5
            )
            logger.info(f"Desktop notification triggered: {title} - {threat_name}")
        except Exception as e:
            # Fallback gracefully if notifications are disabled by OS or raise COM errors
            logger.error(f"Failed to show desktop notification toast: {e}")
