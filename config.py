import os
import sys

# Paths
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "ransomguard.db")
LOG_PATH = os.path.join(APP_DIR, "ransomguard.log")

# Database Configuration
SQLITE_WAL_MODE = True
SQLITE_BUSY_TIMEOUT_MS = 10000

# Event Queue & Processing
EVENT_QUEUE_MAX_SIZE = 50000
BATCH_SIZE_LIMIT = 200
BATCH_INTERVAL_SEC = 0.2  # Process events every 200ms

# System Telemetry Throttling (UI Update Intervals)
UI_STATS_REFRESH_MS = 500
UI_PERF_REFRESH_MS = 1000

# Detection Engine Thresholds (Sliding window of 5 seconds)
DETECTION_WINDOW_SEC = 5.0
THRESHOLD_MASS_CREATE = 30      # Over 30 creations in 5s
THRESHOLD_MASS_MODIFY = 20      # Over 20 modifications in 5s
THRESHOLD_MASS_RENAME = 20      # Over 20 renames in 5s
THRESHOLD_MASS_DELETE = 30      # Over 30 deletions in 5s

# Ransomware extensions to watch
SUSPICIOUS_EXTENSIONS = {
    ".locked", ".crypto", ".crypt", ".enc", ".crypted", ".ransom",
    ".adame", ".phobos", ".wannacry", ".locky", ".ryuk", ".coot",
    ".makop", ".help", ".lck", ".pay", ".dec", ".decrypted"
}

# Ransomware Note Filename Patterns (lowercase check)
SUSPICIOUS_NOTE_PATTERNS = {
    "read_me", "readme", "decrypt", "instruction", "recover", " ransom"
}

# Canary & Decoy Tripwire Patterns (lowercase check)
CANARY_PATTERNS = {
    "canary", "honeypot", "tripwire", "!000_", "!0_system", "aaa_important_do_not_delete", "__vault_tripwire"
}

# Styles & Themes (True Black / Dark Cybersecurity Palette)
COLOR_BACKGROUND = "#05070A"
COLOR_SECONDARY = "#090D12"
COLOR_PANEL = "#0D1218"
COLOR_CARD = "#10161D"
COLOR_BORDER = "#1C2630"
COLOR_TEXT = "#E6EDF3"
COLOR_TEXT_SECONDARY = "#8B98A8"
COLOR_BLUE = "#3B82F6"
COLOR_GREEN = "#22C55E"
COLOR_ORANGE = "#F59E0B"
COLOR_RED = "#EF4444"
COLOR_CYAN = "#06B6D4"
COLOR_WHITE = "#FFFFFF"
COLOR_GRAY = "#8B98A8"
COLOR_LIGHT_GRAY = "#E6EDF3"

# Severity labels
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"
