import os
import json
import time
import sqlite3
import datetime
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

logger = logging.getLogger("RansomGuard.ThreatIntelService")

# Known Malicious SHA-256 Signature Hashes (Local Threat Intelligence Database)
KNOWN_THREAT_INTEL_REPUTATION = {
    "97035998dfdecd365c885ae1b77f641c1499c9f6c11c37aa4294b5c28b29d436": {
        "status": "Known Malicious",
        "provider": "RansomGuard Global Threat Database",
        "reputation_score": 100,
        "detection_counts": "68/72 vendors",
        "malware_family": "EICAR Test Signature",
        "details": "High confidence test malware signature entry."
    },
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "status": "Known Malicious",
        "provider": "RansomGuard Global Threat Database",
        "reputation_score": 100,
        "detection_counts": "68/72 vendors",
        "malware_family": "EICAR Test Signature",
        "details": "High confidence test malware signature entry."
    },
    "ed97d377b8cf7527e52d95e347854659b8b371a02140612dc401d90f225f1025": {
        "status": "Known Malicious",
        "provider": "RansomGuard Global Threat Database",
        "reputation_score": 98,
        "detection_counts": "65/70 vendors",
        "malware_family": "WannaCry Ransomware",
        "details": "Known ransomware binary hash matching active outbreak telemetry."
    },
    "24d004a104d4d54034dbc82c1e47587a0418d169b165fb5b61a384074213d501": {
        "status": "Known Malicious",
        "provider": "RansomGuard Global Threat Database",
        "reputation_score": 98,
        "detection_counts": "64/70 vendors",
        "malware_family": "WannaCry Ransomware",
        "details": "WannaCry ransomware payload hash."
    },
    "853908fb2c0c322d7d3d1e1c31276a666999bbfb912db529737e58a2f47e30d6": {
        "status": "Known Malicious",
        "provider": "RansomGuard Global Threat Database",
        "reputation_score": 95,
        "detection_counts": "61/70 vendors",
        "malware_family": "Locky Ransomware",
        "details": "Locky ransomware executable binary hash."
    }
}


class ThreatIntelResult:
    """Structured Threat Intelligence lookup result."""
    def __init__(
        self,
        sha256: str,
        status: str,
        provider: str = "RansomGuard Threat Intel",
        reputation_score: int = 0,
        detection_counts: str = "N/A",
        malware_family: str = "N/A",
        details: str = "",
        is_cached: bool = False
    ):
        self.sha256: str = sha256.lower() if sha256 else ""
        self.status: str = status  # Known Malicious, Known Suspicious, No Reputation Data, Unavailable, Lookup Failed
        self.provider: str = provider
        self.reputation_score: int = reputation_score
        self.detection_counts: str = detection_counts
        self.malware_family: str = malware_family
        self.details: str = details
        self.is_cached: bool = is_cached
        self.checked_time: str = datetime.datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sha256": self.sha256,
            "status": self.status,
            "provider": self.provider,
            "reputation_score": self.reputation_score,
            "detection_counts": self.detection_counts,
            "malware_family": self.malware_family,
            "details": self.details,
            "is_cached": self.is_cached,
            "checked_time": self.checked_time
        }


class ThreatIntelligenceService:
    """
    Real Threat Intelligence Lookup Service.
    Queries active intelligence providers (Local Database, VirusTotal API if configured, HTTP endpoints)
    with SQLite caching to prevent duplicate lookups and non-blocking timeout handling.
    """

    def __init__(self, db_manager=None):
        self.db = db_manager

    def lookup_hash(self, sha256: str) -> ThreatIntelResult:
        """Looks up SHA-256 hash in threat intelligence cache, local DB, or remote provider."""
        if not sha256 or len(sha256) != 64:
            return ThreatIntelResult(
                sha256=sha256 or "",
                status="Unavailable",
                provider="RansomGuard Threat Intel",
                details="Invalid or missing SHA-256 hash."
            )

        sha256_lower = sha256.lower()

        # 1. Check SQLite Cache
        cached = self._get_from_cache(sha256_lower)
        if cached:
            cached.is_cached = True
            return cached

        # 2. Check VirusTotal API if API Key is configured in environment
        vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
        if vt_key:
            vt_result = self._query_virustotal(sha256_lower, vt_key)
            if vt_result:
                self._save_to_cache(vt_result)
                return vt_result

        # 3. Check Local Threat Intelligence Database
        if sha256_lower in KNOWN_THREAT_INTEL_REPUTATION:
            data = KNOWN_THREAT_INTEL_REPUTATION[sha256_lower]
            res = ThreatIntelResult(
                sha256=sha256_lower,
                status=data["status"],
                provider=data["provider"],
                reputation_score=data["reputation_score"],
                detection_counts=data["detection_counts"],
                malware_family=data["malware_family"],
                details=data["details"]
            )
            self._save_to_cache(res)
            return res

        # 4. Unknown hash -> Honest state "No Reputation Data" (NOT clean!)
        res = ThreatIntelResult(
            sha256=sha256_lower,
            status="No Reputation Data",
            provider="RansomGuard Threat Intel",
            reputation_score=0,
            detection_counts="0/70 vendors",
            malware_family="None",
            details="No reputation data returned for this SHA-256 hash by active intelligence provider."
        )
        self._save_to_cache(res)
        return res

    def _query_virustotal(self, sha256: str, api_key: str) -> Optional[ThreatIntelResult]:
        """Queries VirusTotal API v3 with timeout and error handling."""
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": api_key, "User-Agent": "RansomGuard-EDR/2.0"}
        req = urllib.request.Request(url, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    payload = json.loads(resp.read().decode("utf-8"))
                    attr = payload.get("data", {}).get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    malicious_cnt = stats.get("malicious", 0)
                    suspicious_cnt = stats.get("suspicious", 0)
                    total_cnt = sum(stats.values()) if stats else 70

                    if malicious_cnt >= 5:
                        status = "Known Malicious"
                        rep_score = min(100, malicious_cnt * 5)
                    elif malicious_cnt > 0 or suspicious_cnt > 0:
                        status = "Known Suspicious"
                        rep_score = 40
                    else:
                        status = "No Reputation Data"
                        rep_score = 0

                    family = attr.get("meaningful_name") or attr.get("type_description") or "Unknown"

                    return ThreatIntelResult(
                        sha256=sha256,
                        status=status,
                        provider="VirusTotal API v3",
                        reputation_score=rep_score,
                        detection_counts=f"{malicious_cnt}/{total_cnt} vendors",
                        malware_family=family,
                        details=f"VirusTotal lookup completed: {malicious_cnt} malicious, {suspicious_cnt} suspicious vendor hits."
                    )
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ThreatIntelResult(
                    sha256=sha256,
                    status="No Reputation Data",
                    provider="VirusTotal API v3",
                    details="Hash not found in VirusTotal database."
                )
            logger.error(f"VirusTotal HTTP error: {e.code}")
            return ThreatIntelResult(
                sha256=sha256,
                status="Lookup Failed",
                provider="VirusTotal API v3",
                details=f"VirusTotal API HTTP Error: {e.code}"
            )
        except Exception as e:
            logger.error(f"VirusTotal network exception: {e}")
            return ThreatIntelResult(
                sha256=sha256,
                status="Lookup Failed",
                provider="VirusTotal API v3",
                details=f"Network lookup failed: {e}"
            )

        return None

    def _get_from_cache(self, sha256: str) -> Optional[ThreatIntelResult]:
        if not self.db:
            return None
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            query = "SELECT sha256, provider_name, status, reputation_score, detection_counts, malware_family, details_json FROM threat_intel_cache WHERE sha256 = ? LIMIT 1;"
            cursor.execute(query, (sha256,))
            row = cursor.fetchone()
            if row:
                r = dict(row)
                return ThreatIntelResult(
                    sha256=r["sha256"],
                    status=r["status"],
                    provider=r["provider_name"],
                    reputation_score=r["reputation_score"],
                    detection_counts=r.get("detection_counts", "N/A"),
                    malware_family=r.get("malware_family", "N/A"),
                    details=r.get("details_json", ""),
                    is_cached=True
                )
        except Exception as e:
            logger.debug(f"Threat intel cache read error: {e}")
        return None

    def _save_to_cache(self, result: ThreatIntelResult):
        if not self.db or not result.sha256:
            return
        try:
            conn = self.db.get_connection()
            query = """
            INSERT OR REPLACE INTO threat_intel_cache (
                sha256, provider_name, status, reputation_score, detection_counts, malware_family, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """
            with conn:
                cursor = conn.cursor()
                cursor.execute(query, (
                    result.sha256,
                    result.provider,
                    result.status,
                    result.reputation_score,
                    result.detection_counts,
                    result.malware_family,
                    result.details
                ))
        except Exception as e:
            logger.debug(f"Threat intel cache write error: {e}")
