import os
import sys
import logging
from typing import Tuple, Set

from config import APP_DIR, DB_PATH, LOG_PATH

logger = logging.getLogger("RansomGuard.ScanExclusions")

# Standard Windows system directories that cause excessive I/O, locked file errors,
# or contain Windows component stores. User files (Documents, Desktop, Downloads, Data partitions) are never excluded.
DEFAULT_EXCLUDED_DIR_NAMES: Set[str] = {
    "$recycle.bin",
    "recycler",
    "$recycled",
    "system volume information",
    "recovery",
    "$windows.~bt",
    "$windows.~ws",
}

# Directory path suffixes (case-insensitive) to skip Windows internal component stores
DEFAULT_EXCLUDED_DIR_SUBSTRINGS: Set[str] = {
    os.path.normpath(r"windows\winsxs").lower(),
    os.path.normpath(r"windows\servicing").lower(),
    os.path.normpath(r"windows\softwaredistribution").lower(),
    os.path.normpath(r"windows\installer").lower(),
    os.path.normpath(r"system32\catroot").lower(),
    os.path.normpath(r"system32\catroot2").lower(),
}

# Windows virtual memory / kernel dump files that cannot be opened for reading
DEFAULT_EXCLUDED_FILE_NAMES: Set[str] = {
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "dumpstack.log",
    "dumpstack.log.tmp",
    "memory.dmp",
    "bootmgr",
    "bootnxt",
    "ntuser.dat.log1",
    "ntuser.dat.log2",
}


class ScanExclusions:
    """
    Centralized exclusion mechanism for Existing File Scan.
    Prevents scanning locked operating system stores, virtual memory files,
    and RansomGuard's internal database/log files.
    """

    def __init__(self):
        self.excluded_dir_names: Set[str] = set(DEFAULT_EXCLUDED_DIR_NAMES)
        self.excluded_dir_substrings: Set[str] = set(DEFAULT_EXCLUDED_DIR_SUBSTRINGS)
        self.excluded_file_names: Set[str] = set(DEFAULT_EXCLUDED_FILE_NAMES)

        # Normalize RansomGuard's application paths
        self.app_dir = os.path.normpath(os.path.abspath(APP_DIR)).lower()
        self.db_path = os.path.normpath(os.path.abspath(DB_PATH)).lower()
        self.log_path = os.path.normpath(os.path.abspath(LOG_PATH)).lower()

    def should_exclude_directory(self, dir_path: str) -> Tuple[bool, str]:
        """
        Determines whether an enumerated directory tree should be pruned from scanning.
        Returns (is_excluded, reason).
        """
        if not dir_path:
            return False, ""

        norm_path = os.path.normpath(dir_path).lower()
        base_name = os.path.basename(norm_path)

        # 1. Exact directory name match (e.g. $Recycle.Bin, System Volume Information)
        if base_name in self.excluded_dir_names:
            return True, f"System/Recycle directory: {base_name}"

        # 2. Windows system store path substrings
        for sub in self.excluded_dir_substrings:
            if sub in norm_path:
                return True, f"Windows internal store: {sub}"

        # 3. RansomGuard's own application root (avoid scanning our own active SQLite WAL and log files)
        if norm_path == self.app_dir or norm_path.startswith(self.app_dir + os.sep):
            # Allow scanning subdirectories of app_dir only if explicitly outside internal db/logs
            if "ransomguard.db" in norm_path or "logs" in norm_path:
                return True, "RansomGuard internal storage"

        # 4. Directory junctions and symlinks (prevents recursive traversal loops)
        try:
            if os.path.islink(dir_path):
                return True, "Filesystem junction/reparse point"
        except Exception:
            pass

        return False, ""

    def should_exclude_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Determines whether a specific file should be skipped from deep analysis.
        Returns (is_excluded, reason).
        """
        if not file_path:
            return False, ""

        norm_path = os.path.normpath(file_path).lower()
        base_name = os.path.basename(norm_path)

        # 1. System virtual memory / lock files
        if base_name in self.excluded_file_names:
            return True, f"OS virtual memory file: {base_name}"

        # 2. RansomGuard DB and log files
        if norm_path.startswith(self.db_path) or norm_path.startswith(self.log_path):
            return True, "RansomGuard database/log file"

        # 3. SQLite journal / WAL / SHM files
        if base_name.endswith(".db-wal") or base_name.endswith(".db-shm") or base_name.endswith(".db-journal"):
            return True, "Active SQLite transaction journal"

        return False, ""
