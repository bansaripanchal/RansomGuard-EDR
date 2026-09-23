import os
import re
import math
import time
import logging
import datetime
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("RansomGuard.YaraEngine")

class YaraMatch:
    """Represents a genuine YARA rule match."""
    def __init__(self, rule_name: str, namespace: str, matched_file: str, evidence: str, severity: str = "MEDIUM"):
        self.rule_name = rule_name
        self.namespace = namespace
        self.matched_file = matched_file
        self.evidence = evidence
        self.severity = severity
        self.timestamp = datetime.datetime.now().isoformat()
        self.rule_source = "RansomGuard YARA Rules Database v2.4"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "namespace": self.namespace,
            "matched_file": self.matched_file,
            "evidence": self.evidence,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "rule_source": self.rule_source
        }


class YaraAnalysisResult:
    """Structured container for YARA analysis outcome."""
    def __init__(self, status: str = "No Match", matches: List[YaraMatch] = None, details: str = ""):
        self.status: str = status  # "Matched", "No Match", "Unavailable", "Error"
        self.matches: List[YaraMatch] = matches or []
        self.details: str = details or ("No YARA rules matched this file." if status == "No Match" else "")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "matches_count": len(self.matches),
            "matched_rules": [m.rule_name for m in self.matches],
            "matches": [m.to_dict() for m in self.matches],
            "details": self.details
        }


class YaraRuleEngine:
    """
    Python-native YARA Rule Analysis Engine.
    Parses and evaluates real YARA rule files against file contents.
    Never fabricates fake matches.
    """

    _rules_cache = None

    @classmethod
    def get_rules_dir(cls) -> str:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return os.path.join(base_dir, "rules", "yara")

    @classmethod
    def load_rules(cls) -> List[Dict[str, Any]]:
        """Loads and parses all .yar rules in the rules/yara directory."""
        rules_dir = cls.get_rules_dir()
        if not os.path.exists(rules_dir):
            return []

        parsed_rules = []
        try:
            for root, _, files in os.walk(rules_dir):
                for f in files:
                    if f.endswith((".yar", ".yara")):
                        path = os.path.join(root, f)
                        file_rules = cls._parse_yara_file(path)
                        parsed_rules.extend(file_rules)
        except Exception as e:
            logger.error(f"Error loading YARA rules from {rules_dir}: {e}")

        return parsed_rules

    @classmethod
    def scan_file(cls, file_path: str) -> YaraAnalysisResult:
        """Executes real YARA rule scanning on a file."""
        if not file_path or not os.path.exists(file_path) or os.path.isdir(file_path):
            return YaraAnalysisResult(status="Error", details="File does not exist or is inaccessible.")

        rules = cls.load_rules()
        if not rules:
            return YaraAnalysisResult(status="Unavailable", details="YARA signature rules database is unavailable or not configured.")

        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            return YaraAnalysisResult(status="Error", details=f"Unable to read file bytes: {e}")

        matches: List[YaraMatch] = []

        for r in rules:
            match_obj = cls._evaluate_rule(r, data, file_path)
            if match_obj:
                matches.append(match_obj)

        if matches:
            rule_names = ", ".join([m.rule_name for m in matches])
            details = f"YARA scan matched {len(matches)} rule(s): {rule_names}"
            return YaraAnalysisResult(status="Matched", matches=matches, details=details)
        else:
            return YaraAnalysisResult(status="No Match", details="No YARA rules matched this file.")

    @classmethod
    def _parse_yara_file(cls, filepath: str) -> List[Dict[str, Any]]:
        rules = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Extract rule blocks
            rule_blocks = re.findall(r"rule\s+([A-Za-z0-9_]+)\s*\{([^}]+)\}", content, re.DOTALL)
            for rule_name, body in rule_blocks:
                # Parse meta
                meta = {}
                meta_match = re.search(r"meta:\s*(.*?)(strings:|condition:|\})", body, re.DOTALL)
                if meta_match:
                    meta_text = meta_match.group(1)
                    for m_line in meta_text.strip().split("\n"):
                        m_line = m_line.strip()
                        if "=" in m_line:
                            k, v = m_line.split("=", 1)
                            meta[k.strip()] = v.strip().strip('"')

                # Parse strings
                strings = []
                strings_match = re.search(r"strings:\s*(.*?)(condition:|\})", body, re.DOTALL)
                if strings_match:
                    str_text = strings_match.group(1)
                    for s_line in str_text.strip().split("\n"):
                        s_line = s_line.strip()
                        if s_line.startswith("$"):
                            m = re.match(r"(\$[A-Za-z0-9_]*)\s*=\s*\"([^\"]+)\"", s_line)
                            if m:
                                s_id, s_val = m.groups()
                                is_nocase = "nocase" in s_line.lower()
                                is_wide = "wide" in s_line.lower()
                                strings.append({"id": s_id, "val": s_val, "nocase": is_nocase, "wide": is_wide})

                # Parse condition count required
                cond_match = re.search(r"condition:\s*(.*)", body, re.DOTALL)
                cond_text = cond_match.group(1).strip() if cond_match else "any of them"

                rules.append({
                    "rule_name": rule_name,
                    "filepath": filepath,
                    "namespace": meta.get("category", "threat.signatures"),
                    "severity": meta.get("severity", "MEDIUM"),
                    "description": meta.get("description", f"Rule {rule_name}"),
                    "meta": meta,
                    "strings": strings,
                    "condition": cond_text
                })
        except Exception as e:
            logger.error(f"Error parsing YARA file {filepath}: {e}")

        return rules

    @classmethod
    def _evaluate_rule(cls, rule: Dict[str, Any], data: bytes, file_path: str) -> Optional[YaraMatch]:
        rule_name = rule["rule_name"]
        strings = rule["strings"]
        cond = rule["condition"].lower()

        # Check special header condition e.g. uint16(0) == 0x5A4D
        is_pe = data.startswith(b"MZ")
        if "uint16(0) == 0x5a4d" in cond and not is_pe:
            return None

        # Custom logic for EICAR test string
        if rule_name == "EICAR_Test_File":
            eicar_seq = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
            pos = data.find(eicar_seq)
            if pos != -1:
                return YaraMatch(
                    rule_name=rule_name,
                    namespace=rule["namespace"],
                    matched_file=file_path,
                    evidence=f"Matched EICAR test pattern string at offset 0x{pos:X}",
                    severity=rule["severity"]
                )

        # Match strings
        hits = []
        data_lower = data.lower()

        for s in strings:
            s_val = s["val"]
            b_val = s_val.encode("utf-8")
            
            if s["nocase"]:
                pos = data_lower.find(b_val.lower())
            else:
                pos = data.find(b_val)

            if pos != -1:
                hits.append((s["id"], s_val, pos))

        # Check condition threshold
        required_hits = 1
        if "2 of" in cond:
            required_hits = 2
        elif "3 of" in cond:
            required_hits = 3
        elif "all of" in cond:
            required_hits = len(strings)

        if len(hits) >= required_hits and required_hits > 0:
            ev_parts = [f"Matched '{h[1]}' at offset 0x{h[2]:X}" for h in hits[:3]]
            evidence_str = f"Rule '{rule_name}' matched {len(hits)} pattern(s): " + "; ".join(ev_parts)
            return YaraMatch(
                rule_name=rule_name,
                namespace=rule["namespace"],
                matched_file=file_path,
                evidence=evidence_str,
                severity=rule["severity"]
            )

        return None
