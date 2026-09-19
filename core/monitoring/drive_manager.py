import os
import sys
import ctypes
import threading
import psutil
import logging

logger = logging.getLogger("RansomGuard.DriveManager")

class DriveManager:
    # Windows Drive Types
    DRIVE_UNKNOWN = 0
    DRIVE_NO_ROOT_DIR = 1
    DRIVE_REMOVABLE = 2
    DRIVE_FIXED = 3
    DRIVE_REMOTE = 4
    DRIVE_CDROM = 5
    DRIVE_RAMDISK = 6

    # Thread-safe in-memory cache
    _cache_lock = threading.Lock()
    _cached_drives = []
    _is_refreshing = False
    _last_refresh_time = 0.0

    @staticmethod
    def get_drive_type_windows(drive_letter):
        """Calls the Windows API to determine the drive type."""
        if not sys.platform.startswith("win"):
            # Fallback for testing on other platforms
            return DriveManager.DRIVE_FIXED
            
        # Ensure format is e.g. "C:\\" or "D:\\"
        root_path = drive_letter.rstrip("\\") + "\\\\"
        try:
            return ctypes.windll.kernel32.GetDriveTypeW(root_path)
        except Exception as e:
            logger.error(f"Error calling GetDriveTypeW for {drive_letter}: {e}")
            return DriveManager.DRIVE_UNKNOWN

    @staticmethod
    def get_volume_info(drive_letter):
        """
        Retrieves authentic Windows volume label and filesystem name (e.g. NTFS, FAT32, exFAT).
        Returns tuple of (volume_name, file_system).
        """
        if not sys.platform.startswith("win"):
            return ("", "Unknown")
        root_path = drive_letter.rstrip("\\") + "\\\\"
        try:
            volume_name_buf = ctypes.create_unicode_buffer(261)
            fs_name_buf = ctypes.create_unicode_buffer(261)
            res = ctypes.windll.kernel32.GetVolumeInformationW(
                root_path,
                volume_name_buf,
                261,
                None,
                None,
                None,
                fs_name_buf,
                261
            )
            if res:
                return (volume_name_buf.value or "", fs_name_buf.value or "Unknown")
        except Exception as e:
            logger.debug(f"Error querying volume info for {drive_letter}: {e}")
        return ("", "Unknown")

    @classmethod
    def get_active_drives(cls):
        """
        Queries all active partitions on the system, gathers volume info,
        and determines which are fixed vs removable.
        Updates the in-memory cache with genuine Windows volume information.
        """
        drives = []
        try:
            partitions = psutil.disk_partitions(all=False)
            for part in partitions:
                drive_letter = part.mountpoint
                if not drive_letter:
                    continue
                
                type_code = cls.get_drive_type_windows(drive_letter)
                type_name = "Fixed"
                is_removable = False
                
                # Check removable via GetDriveTypeW or partition opts
                part_opts = (part.opts or "").lower()
                if type_code == cls.DRIVE_REMOVABLE or "removable" in part_opts:
                    type_name = "Removable"
                    is_removable = True
                elif type_code == cls.DRIVE_FIXED:
                    type_name = "Fixed"
                elif type_code == cls.DRIVE_REMOTE:
                    type_name = "Network"
                elif type_code == cls.DRIVE_CDROM:
                    type_name = "CD-ROM"
                elif type_code == cls.DRIVE_RAMDISK:
                    type_name = "RAM Disk"
                else:
                    type_name = "Unknown"
                    
                # Skip optical drives to prevent UI hangs or popup prompts
                if type_code == cls.DRIVE_CDROM:
                    continue

                # Query drive usage details
                try:
                    usage = psutil.disk_usage(drive_letter)
                    total_gb = round(usage.total / (1024 ** 3), 1)
                    free_gb = round(usage.free / (1024 ** 3), 1)
                    used_percent = usage.percent
                    total_bytes = usage.total
                    free_bytes = usage.free
                except (PermissionError, FileNotFoundError):
                    # Drive is connected but inaccessible (e.g. unformatted card or card reader empty)
                    total_gb = 0.0
                    free_gb = 0.0
                    used_percent = 0.0
                    total_bytes = 0
                    free_bytes = 0

                vol_name, fs_name = cls.get_volume_info(drive_letter)

                drives.append({
                    "letter": drive_letter.rstrip("\\"),
                    "mount_point": drive_letter,
                    "volume_name": vol_name,
                    "file_system": fs_name,
                    "type_code": type_code,
                    "type_name": type_name,
                    "is_removable": is_removable,
                    "total_gb": total_gb,
                    "free_gb": free_gb,
                    "total_bytes": total_bytes,
                    "free_bytes": free_bytes,
                    "used_percent": used_percent,
                    "available": total_gb > 0
                })
        except Exception as e:
            logger.error(f"Error enumerating disk partitions: {e}")

        # Update cache safely
        with cls._cache_lock:
            cls._cached_drives = list(drives)
            import time
            cls._last_refresh_time = time.time()
            
        return drives

    @classmethod
    def get_removable_drives(cls):
        """Returns list of all active drives identified as removable / USB storage."""
        return [d for d in cls.get_active_drives() if d["is_removable"] and d["available"]]

    @classmethod
    def get_active_drives_cached(cls):
        """
        Returns cached drive list immediately (<0.01 ms).
        Never performs blocking Windows kernel or disk I/O queries on caller thread.
        If cache is completely empty, performs an initial population.
        """
        with cls._cache_lock:
            if cls._cached_drives:
                return list(cls._cached_drives)
        # Only if uninitialized, query once to prime cache
        return cls.get_active_drives()

    @classmethod
    def get_removable_drives_cached(cls):
        """Returns cached removable drives immediately without blocking kernel calls."""
        cached = cls.get_active_drives_cached()
        return [d for d in cached if d.get("is_removable") and d.get("available")]

    @classmethod
    def refresh_drives_async(cls, callback=None):
        """
        Spawns a background thread to discover drives via Windows APIs asynchronously.
        Calls optional callback(drives) on completion.
        Guarantees caller (e.g. Qt GUI thread) never blocks on disk I/O.
        """
        with cls._cache_lock:
            if cls._is_refreshing:
                return # Already refreshing in background
            cls._is_refreshing = True

        def _worker():
            try:
                drives = cls.get_active_drives()
                if callback:
                    callback(drives)
            except Exception as e:
                logger.error(f"Error in async drive discovery: {e}")
            finally:
                with cls._cache_lock:
                    cls._is_refreshing = False

        t = threading.Thread(target=_worker, name="DriveDiscoveryWorker", daemon=True)
        t.start()

