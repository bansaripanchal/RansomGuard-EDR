import uuid
import datetime
from typing import Dict, Any, List, Optional


class DetectionResult:
    """
    Normalized, evidence-based DetectionResult representation used application-wide.
    Replaces obsolete 'verdict' fields with authentic telemetry, observed evidence,
    applied rules, YARA rule scan results, and threat intelligence.
    """

    def __init__(
        self,
        detection_id: Optional[str] = None,
        timestamp: Optional[str] = None,
        source: str = "Scan Center",
        artifact_type: str = "FILE",  # "FILE", "PROCESS", "NETWORK"
        artifact_path: str = "",
        detection_type: str = "Suspicious Indicator",
        severity: str = "LOW",        # "LOW", "MEDIUM", "HIGH", "CRITICAL"
        risk_score: int = 0,          # 0 - 100
        evidence: Optional[List[str]] = None,
        applied_rules: Optional[List[Dict[str, Any]]] = None,
        yara_results: Optional[Dict[str, Any]] = None,
        threat_intelligence: Optional[Dict[str, Any]] = None,
        file_telemetry: Optional[Dict[str, Any]] = None,
        process_telemetry: Optional[Dict[str, Any]] = None,
        network_telemetry: Optional[Dict[str, Any]] = None
    ):
        self.detection_id = detection_id or f"DET-{uuid.uuid4().hex[:8].upper()}"
        self.timestamp = timestamp or datetime.datetime.now().isoformat()
        self.source = source
        self.artifact_type = artifact_type.upper()
        self.artifact_path = artifact_path
        self.detection_type = detection_type
        self.severity = severity.upper()
        self.risk_score = max(0, min(100, int(risk_score)))
        self.evidence = evidence or []
        self.applied_rules = applied_rules or []
        
        # Default YARA structure if omitted
        self.yara_results = yara_results or {
            "status": "No Match",
            "matches_count": 0,
            "matched_rules": [],
            "matches": [],
            "details": "No YARA rules matched this file."
        }
        
        # Default Threat Intelligence structure if omitted
        self.threat_intelligence = threat_intelligence or {
            "provider": "RansomGuard Threat Intel",
            "indicator": file_telemetry.get("sha256") if file_telemetry else "",
            "status": "Not Checked",
            "confidence": "N/A",
            "first_seen": "N/A",
            "last_seen": "N/A",
            "details": "No threat intelligence lookup requested."
        }

        self.file_telemetry = file_telemetry or {}
        self.process_telemetry = process_telemetry or {}
        self.network_telemetry = network_telemetry or {}

    def to_dict(self) -> Dict[str, Any]:
        """Serializes normalized DetectionResult into a python dictionary."""
        return {
            "detection_id": self.detection_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "artifact_type": self.artifact_type,
            "artifact_path": self.artifact_path,
            "detection_type": self.detection_type,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "evidence": self.evidence,
            "applied_rules": self.applied_rules,
            "yara_results": self.yara_results,
            "threat_intelligence": self.threat_intelligence,
            "file_telemetry": self.file_telemetry,
            "process_telemetry": self.process_telemetry,
            "network_telemetry": self.network_telemetry
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectionResult":
        """Constructs a DetectionResult instance from a raw dictionary."""
        if not data:
            return cls()

        return cls(
            detection_id=data.get("detection_id"),
            timestamp=data.get("timestamp") or data.get("detection_time"),
            source=data.get("source") or data.get("detection_source", "Scan Center"),
            artifact_type=data.get("artifact_type", "FILE"),
            artifact_path=data.get("artifact_path") or data.get("full_path") or data.get("file_path", ""),
            detection_type=data.get("detection_type") or data.get("threat_name", "Suspicious Finding"),
            severity=data.get("severity", "LOW"),
            risk_score=data.get("risk_score", 0),
            evidence=data.get("evidence") if isinstance(data.get("evidence"), list) else [str(data.get("evidence"))] if data.get("evidence") else [],
            applied_rules=data.get("applied_rules") or data.get("static_indicators") or [],
            yara_results=data.get("yara_results") or data.get("yara_matches"),
            threat_intelligence=data.get("threat_intelligence") or data.get("reputation_result"),
            file_telemetry=data.get("file_telemetry") or {
                "file_name": data.get("filename") or data.get("name"),
                "full_path": data.get("full_path") or data.get("file_path"),
                "sha256": data.get("sha256"),
                "file_size": data.get("file_size"),
                "file_type": data.get("file_type")
            },
            process_telemetry=data.get("process_telemetry") or {
                "process_name": data.get("process_name"),
                "process_pid": data.get("process_pid"),
                "attribution_status": data.get("attribution_status")
            },
            network_telemetry=data.get("network_telemetry") or {}
        )
