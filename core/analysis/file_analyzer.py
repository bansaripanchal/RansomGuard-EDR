import os
import math
import hashlib
import logging
import collections
from typing import Optional, Dict, Any, List

logger = logging.getLogger("RansomGuard.FileAnalyzer")

# Known Malicious SHA-256 Hashes
KNOWN_MALICIOUS_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR Standard Test Antivirus File",
    "13db60afb914a2ee9b3649d1947d58046d1a9e9b8e4114d80b1d5c142b4ed7fa": "EICAR Standard Test Antivirus File",
    "ed97d377b8cf7527e52d95e347854659b8b371a02140612dc401d90f225f1025": "WannaCry Ransomware Sample",
    "24d004a104d4d54034dbc82c1e47587a0418d169b165fb5b61a384074213d501": "WannaCry Ransomware Sample",
    "853908fb2c0c322d7d3d1e1c31276a666999bbfb912db529737e58a2f47e30d6": "Locky Ransomware Bin",
    "7bfe973be6f82fccbda5b6364d96edef45aaaac705ad0dbd4e02644404123168": "Simulated Ransomware Test Signature"
}

# Known script extensions
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".vbs", ".js", ".cmd", ".wsf", ".hta", ".sh", ".py"}

# Executable extensions
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"}

# Common standard PE section names
STANDARD_PE_SECTIONS = {
    ".text", ".data", ".rdata", ".idata", ".edata", ".pdata", 
    ".rsrc", ".reloc", ".bss", ".tls", ".debug", ".gfids", ".00cfg"
}

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy (0.0 to 8.0) of a byte array."""
    if not data:
        return 0.0
    length = len(data)
    counts = collections.Counter(data)
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)


class FileAnalysisResult:
    """
    Structured, evidence-based container representing the complete static analysis of a file.
    Does NOT fabricate unperformed checks; explicitly reports unavailable capabilities.
    """
    def __init__(self, path: str):
        self.path: str = os.path.normpath(path)
        self.filename: str = os.path.basename(self.path)
        self.size: int = 0
        self.extension: str = ""
        self.detected_file_type: str = "Unknown"
        self.sha256: Optional[str] = None
        self.md5: Optional[str] = None
        self.pe_info: Optional[Dict[str, Any]] = None
        
        # Capability statuses (Explicitly reports real capability state)
        self.yara_status: str = "NOT_CONFIGURED"
        self.yara_matches: List[str] = []
        self.reputation_status: str = "NOT_AVAILABLE"
        self.reputation_result: Optional[Dict[str, Any]] = None
        
        # Static indicators and evidence
        self.static_indicators: List[Dict[str, Any]] = []
        self.evidence_list: List[str] = []
        self.error: Optional[str] = None
        self.accessible: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "filename": self.filename,
            "size": self.size,
            "extension": self.extension,
            "detected_file_type": self.detected_file_type,
            "sha256": self.sha256,
            "md5": self.md5,
            "pe_info": self.pe_info,
            "yara_status": self.yara_status,
            "yara_matches": self.yara_matches,
            "reputation_status": self.reputation_status,
            "reputation_result": self.reputation_result,
            "static_indicators": self.static_indicators,
            "evidence_list": self.evidence_list,
            "error": self.error,
            "accessible": self.accessible
        }

    def to_detection_result(self, source: str = "Scan Center") -> Dict[str, Any]:
        """Converts FileAnalysisResult into normalized DetectionResult format."""
        from core.detection.detection_result import DetectionResult
        from core.detection.risk_engine import RiskEngine

        risk_eval = RiskEngine.evaluate_evidence({
            "static_indicators": self.static_indicators,
            "is_known_hash": self.reputation_status == "Known Malicious",
            "is_accessible": self.accessible,
            "has_errors": bool(self.error)
        })

        # Process YARA results
        if isinstance(self.yara_matches, dict):
            yara_data = self.yara_matches
        else:
            yara_data = {
                "status": self.yara_status,
                "matches_count": len(self.yara_matches) if isinstance(self.yara_matches, list) else 0,
                "matched_rules": self.yara_matches if isinstance(self.yara_matches, list) else [],
                "details": f"YARA Analysis: {self.yara_status}"
            }

        # Process Threat Intel results
        intel_data = self.reputation_result or {
            "provider": "RansomGuard Threat Intel",
            "indicator": self.sha256 or "",
            "status": self.reputation_status or "Not Checked",
            "confidence": "N/A",
            "first_seen": "N/A",
            "last_seen": "N/A",
            "details": "No threat intelligence lookup performed."
        }

        det_res = DetectionResult(
            source=source,
            artifact_type="FILE",
            artifact_path=self.path,
            detection_type=risk_eval.get("detection_type", "Static File Finding"),
            severity=risk_eval.get("severity", "LOW"),
            risk_score=risk_eval.get("risk_score", 0),
            evidence=self.evidence_list,
            applied_rules=self.static_indicators,
            yara_results=yara_data,
            threat_intelligence=intel_data,
            file_telemetry={
                "file_name": self.filename,
                "full_path": self.path,
                "sha256": self.sha256,
                "md5": self.md5,
                "file_size": self.size,
                "file_type": self.detected_file_type,
                "pe_info": self.pe_info
            }
        )
        return det_res.to_dict()


class UnifiedFileAnalyzer:
    """
    Central, evidence-based file analysis service.
    Examines genuine file bytes, computes cryptographic hashes, identifies file types,
    and performs deep PE inspections where applicable.
    
    Reused identically by:
    - Manual File/Folder Scans (Scan Center)
    - Live Protection File Analysis (Behavior Engine)
    - Removable USB Drive Storage Analysis (Future USB Protection)
    """

    @classmethod
    def analyze_file(cls, file_path: str) -> FileAnalysisResult:
        """
        Executes genuine static analysis on a single real file.
        Returns structured FileAnalysisResult without fabricating data.
        """
        result = FileAnalysisResult(file_path)

        # 1. Validation & Access Check
        if not file_path:
            result.error = "Empty file path provided."
            return result

        if not os.path.exists(file_path):
            result.error = f"File does not exist: {file_path}"
            result.evidence_list.append(f"Validation failed: File not found on filesystem ({file_path})")
            return result

        if os.path.isdir(file_path):
            result.error = f"Target is a directory, not a file: {file_path}"
            return result

        try:
            stat_info = os.stat(file_path)
            result.size = stat_info.st_size
            _, ext = os.path.splitext(result.filename)
            result.extension = ext.lower()
            result.accessible = True
            result.evidence_list.append(f"File verified on filesystem (Size: {result.size:,} bytes, Extension: '{result.extension}')")
        except PermissionError:
            result.error = f"Access denied (PermissionError) reading {file_path}"
            result.evidence_list.append("Validation failed: Permission denied by operating system.")
            return result
        except Exception as e:
            result.error = f"Access error: {e}"
            result.evidence_list.append(f"Validation failed: {e}")
            return result

        # 2. Cryptographic Hash Calculation (SHA-256 & MD5)
        try:
            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5()
            first_chunk = b""
            with open(file_path, "rb") as f:
                chunk = f.read(131072)
                first_chunk = chunk[:4096]
                while chunk:
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
                    chunk = f.read(131072)
            result.sha256 = sha256_hash.hexdigest().lower()
            result.md5 = md5_hash.hexdigest().lower()
            result.evidence_list.append(f"SHA-256 calculated: {result.sha256}")
        except PermissionError:
            result.error = "Permission denied while computing file hash."
            result.evidence_list.append("Cryptographic hashing halted: Permission denied.")
            return result
        except Exception as e:
            result.error = f"Error computing hash: {e}"
            result.evidence_list.append(f"Cryptographic hashing error: {e}")
            return result

        # 3. File Type Identification via Magic Bytes & Structure
        result.detected_file_type = cls._identify_file_type(first_chunk, result.extension)
        result.evidence_list.append(f"File type identified: {result.detected_file_type}")

        # 4. Known Malicious Hash Signature Matching
        if result.sha256 in KNOWN_MALICIOUS_HASHES:
            threat_name = KNOWN_MALICIOUS_HASHES[result.sha256]
            result.static_indicators.append({
                "rule_name": "KNOWN_MALWARE_HASH_MATCH",
                "severity": "CRITICAL",
                "threat_name": threat_name,
                "reason": f"Known malicious SHA-256 hash match: '{threat_name}' (Hash: {result.sha256[:16]}...).",
                "evidence_type": "STATIC_SIGNATURE"
            })
            result.evidence_list.append(f"CRITICAL MATCH: SHA-256 matches known malicious signature database: '{threat_name}'")

        # 5. PE Analysis (For Windows Executables & DLLs)
        if result.extension in EXECUTABLE_EXTENSIONS or first_chunk.startswith(b"MZ"):
            cls._analyze_pe_file(file_path, result)

        # 6. Script & Content Heuristic Analysis
        if result.extension in SCRIPT_EXTENSIONS:
            cls._analyze_script_content(file_path, result)

        # 7. Suspicious Extension Indicator (Evidence only, not automatic malware)
        from config import SUSPICIOUS_EXTENSIONS, SUSPICIOUS_NOTE_PATTERNS
        if result.extension in SUSPICIOUS_EXTENSIONS:
            result.static_indicators.append({
                "rule_name": "SUSPICIOUS_EXTENSION",
                "severity": "LOW",
                "threat_name": "Ransomware Extension Pattern",
                "reason": f"File extension '{result.extension}' matches known ransomware encryption pattern.",
                "evidence_type": "STATIC_INDICATOR"
            })
            result.evidence_list.append(f"Indicator observed: File extension '{result.extension}' matches ransomware extension pattern.")

        # 8. Ransom Note Naming Indicator (Evidence only, not automatic malware)
        fn_lower = result.filename.lower()
        for pat in SUSPICIOUS_NOTE_PATTERNS:
            if pat in fn_lower:
                result.static_indicators.append({
                    "rule_name": "RANSOM_NOTE_PATTERN",
                    "severity": "LOW",
                    "threat_name": "Potential Ransom Note Pattern",
                    "reason": f"File name matches typical decryption instructions naming: '{result.filename}'",
                    "evidence_type": "STATIC_INDICATOR"
                })
                result.evidence_list.append(f"Indicator observed: Filename '{result.filename}' matches typical ransom note naming pattern.")
                break

        # 9. YARA Rule Analysis
        try:
            from core.analysis.yara_engine import YaraRuleEngine
            yara_res = YaraRuleEngine.scan_file(file_path)
            result.yara_status = yara_res.status
            result.yara_matches = yara_res.to_dict()

            if yara_res.status == "Matched":
                for m in yara_res.matches:
                    result.static_indicators.append({
                        "rule_name": f"YARA_{m.rule_name.upper()}",
                        "severity": m.severity,
                        "threat_name": f"YARA Match: {m.rule_name}",
                        "reason": f"YARA signature rule '{m.rule_name}' matched file contents: {m.evidence}",
                        "evidence_type": "STATIC_YARA_MATCH"
                    })
                    result.evidence_list.append(f"YARA Match: Rule '{m.rule_name}' matched file ({m.evidence})")
            else:
                result.evidence_list.append(f"YARA Rule Analysis: {yara_res.details}")
        except Exception as e:
            result.yara_status = "Error"
            result.evidence_list.append(f"YARA signature analysis error: {e}")

        # 10. Threat Intelligence Lookup
        try:
            from core.analysis.threat_intel_service import ThreatIntelligenceService
            intel_service = ThreatIntelligenceService()
            intel_res = intel_service.lookup_hash(result.sha256)
            result.reputation_status = intel_res.status
            result.reputation_result = intel_res.to_dict()

            if intel_res.status == "Known Malicious":
                result.static_indicators.append({
                    "rule_name": "KNOWN_MALICIOUS_REPUTATION",
                    "severity": "CRITICAL",
                    "threat_name": intel_res.malware_family,
                    "reason": f"Threat Intelligence ({intel_res.provider}): Known Malicious — {intel_res.details}",
                    "evidence_type": "THREAT_INTEL_REPUTATION"
                })
                result.evidence_list.append(f"Threat Intelligence CRITICAL: Known Malicious ({intel_res.provider}) — {intel_res.details}")
            elif intel_res.status == "Known Suspicious":
                result.static_indicators.append({
                    "rule_name": "KNOWN_SUSPICIOUS_REPUTATION",
                    "severity": "MEDIUM",
                    "threat_name": intel_res.malware_family,
                    "reason": f"Threat Intelligence ({intel_res.provider}): Known Suspicious — {intel_res.details}",
                    "evidence_type": "THREAT_INTEL_REPUTATION"
                })
                result.evidence_list.append(f"Threat Intelligence INDICATOR: Known Suspicious ({intel_res.provider}) — {intel_res.details}")
            else:
                result.evidence_list.append(f"Threat Intelligence ({intel_res.provider}): {intel_res.status} — {intel_res.details}")
        except Exception as e:
            result.reputation_status = "Lookup Failed"
            result.evidence_list.append(f"Threat Intelligence lookup error: {e}")

        return result

    @classmethod
    def _identify_file_type(cls, header: bytes, ext: str) -> str:
        """Determines authentic file type from magic bytes and structure."""
        if not header:
            return "Empty File"

        if header.startswith(b"MZ"):
            return "Windows Portable Executable (PE32/PE64)"
        elif header.startswith(b"%PDF-"):
            return "PDF Document"
        elif header.startswith(b"PK\x03\x04"):
            if ext in (".docx", ".xlsx", ".pptx"):
                return f"Office OpenXML Document ({ext[1:].upper()})"
            return "ZIP Archive / Compressed Container"
        elif header.startswith(b"\x89PNG\r\n\x1a\n"):
            return "PNG Image"
        elif header.startswith(b"\xff\xd8\xff"):
            return "JPEG Image"
        elif header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
            return "GIF Image"
        elif header.startswith(b"Rar!\x1a\x07"):
            return "RAR Archive"
        elif header.startswith(b"7z\xbc\xaf\x27\x1c"):
            return "7-Zip Archive"
        elif header.startswith(b"\x7fELF"):
            return "Linux ELF Executable"

        # Check for scripts and text
        if ext == ".ps1":
            return "PowerShell Script"
        elif ext in (".bat", ".cmd"):
            return "Windows Command Script"
        elif ext == ".vbs":
            return "VBScript"
        elif ext == ".js":
            return "JavaScript Source"
        elif ext == ".py":
            return "Python Script"

        # Check if plain text
        try:
            header.decode("utf-8")
            return "Plain Text Document"
        except UnicodeDecodeError:
            return "Binary Data"

    @classmethod
    def _analyze_pe_file(cls, file_path: str, result: FileAnalysisResult):
        """Extracts genuine PE metadata using pefile."""
        try:
            import pefile
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories()

            machine_type = hex(pe.FILE_HEADER.Machine)
            num_sections = len(pe.sections)
            subsystem_id = pe.OPTIONAL_HEADER.Subsystem if hasattr(pe, 'OPTIONAL_HEADER') else 0
            
            subsystem_map = {
                1: "NATIVE",
                2: "WINDOWS_GUI",
                3: "WINDOWS_CUI (Console)",
                7: "POSIX_CUI",
                9: "WINDOWS_CE_GUI",
                10: "EFI_APPLICATION"
            }
            subsystem_name = subsystem_map.get(subsystem_id, f"UNKNOWN ({subsystem_id})")

            sections_info = []
            max_entropy = 0.0
            suspicious_chars = []

            for section in pe.sections:
                s_name = section.Name.decode("latin-1", errors="ignore").strip("\x00")
                raw_data = section.get_data()
                s_entropy = calculate_shannon_entropy(raw_data)
                max_entropy = max(max_entropy, s_entropy)

                if s_name not in STANDARD_PE_SECTIONS and not s_name.startswith("/"):
                    suspicious_chars.append(f"Non-standard section name: '{s_name}'")

                if s_entropy >= 7.2:
                    suspicious_chars.append(f"High-entropy packed section: '{s_name}' (Entropy: {s_entropy:.2f})")

                sections_info.append({
                    "name": s_name,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": s_entropy
                })

            # Check imports
            imported_dlls = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('latin-1', errors='ignore') if entry.dll else "Unknown"
                    imported_dlls.append(dll_name)

            if num_sections > 0 and len(imported_dlls) == 0:
                suspicious_chars.append("Zero imported DLLs (Possible packed or anomalous binary)")

            result.pe_info = {
                "is_pe": True,
                "machine": machine_type,
                "subsystem": subsystem_name,
                "number_of_sections": num_sections,
                "sections": sections_info,
                "max_section_entropy": max_entropy,
                "imported_dlls_count": len(imported_dlls),
                "imported_dlls": imported_dlls[:10],
                "suspicious_characteristics": suspicious_chars
            }

            result.evidence_list.append(
                f"PE Analysis: {num_sections} sections, Subsystem: {subsystem_name}, Max entropy: {max_entropy:.2f}"
            )

            # Record static indicator if suspicious characteristics found
            if suspicious_chars:
                result.static_indicators.append({
                    "rule_name": "SUSPICIOUS_PE_CHARACTERISTICS",
                    "severity": "MEDIUM",
                    "threat_name": "Suspicious PE File Characteristics",
                    "reason": f"PE binary exhibits anomalous characteristics: {'; '.join(suspicious_chars[:3])}",
                    "evidence_type": "STATIC_PE_HEURISTIC"
                })
                result.evidence_list.append(f"Suspicious PE indicator: {'; '.join(suspicious_chars[:2])}")

        except ImportError:
            result.pe_info = {"is_pe": True, "error": "pefile library not installed"}
            result.evidence_list.append("PE deep analysis: Library unavailable")
        except Exception as e:
            # Corrupted or malformed PE
            result.pe_info = {"is_pe": True, "error": f"Failed to parse PE: {e}"}
            result.evidence_list.append(f"PE header inspection error: {e}")

    @classmethod
    def _analyze_script_content(cls, file_path: str, result: FileAnalysisResult):
        """Inspects script content for suspicious execution and evasion keywords."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(65536).lower()

            script_keywords = [
                "wscript.shell", "shell.application", "invoke-expression", "iex",
                "windowstyle hidden", "-nop", "-w hidden", "sarmat", "wannacry", 
                "cryptor", "bypass", "downloadstring", "downloadfile"
            ]
            hits = [k for k in script_keywords if k in content]
            if len(hits) >= 2:
                result.static_indicators.append({
                    "rule_name": "SUSPICIOUS_SCRIPT_HEURISTICS",
                    "severity": "MEDIUM",
                    "threat_name": "Suspicious Script Execution",
                    "reason": f"Script '{result.filename}' contains suspicious administrative/execution keywords: {', '.join(hits)}.",
                    "evidence_type": "STATIC_CONTENT_HEURISTIC"
                })
                result.evidence_list.append(f"Content inspection: Found suspicious script keywords: {', '.join(hits[:4])}")
            else:
                result.evidence_list.append("Content inspection: No suspicious administrative keywords detected.")
        except Exception as e:
            result.evidence_list.append(f"Content inspection failed: {e}")
