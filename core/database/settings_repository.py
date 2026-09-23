from core.database.database import DatabaseManager

class SettingsRepository:
    def __init__(self, db_manager=None):
        self.db = db_manager or DatabaseManager()

    def get_setting(self, key, default=None):
        """Retrieves a persistent setting value."""
        row = self.db.execute_read_one("SELECT value FROM settings WHERE key = ?", (key,))
        return row["value"] if row else default

    def set_setting(self, key, value):
        """Saves a key-value pair to settings."""
        self.db.execute_write(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value))
        )
        if key == "protected_drives" and hasattr(self.db, "invalidate_active_drives_cache"):
            self.db.invalidate_active_drives_cache()

    def get_protected_drives(self) -> list:
        """
        Retrieves user-configured protected drives from settings repository.
        Falls back dynamically to actual Windows system drive if unconfigured.
        """
        import os
        system_drive = os.environ.get("SystemDrive", "C:").upper()
        if not system_drive.endswith(":"):
            system_drive += ":"
        val = self.get_setting("protected_drives", system_drive)
        if not val:
            return [f"{system_drive}\\"]
        drives = []
        for d in str(val).split(","):
            d = d.strip()
            if d:
                let = d[0].upper()
                drives.append(f"{let}:\\")
        return drives or [f"{system_drive}\\"]

    def set_protected_drives(self, drives_list: list):
        """Sets and persists the atomic protected drives list."""
        clean_drives = []
        for d in drives_list:
            if d and isinstance(d, str):
                let = d.strip()[0].upper()
                clean_drives.append(f"{let}:")
        drives_str = ",".join(clean_drives)
        self.set_setting("protected_drives", drives_str)

    def get_monitored_paths(self):
        """Returns a list of all monitored folder paths."""
        rows = self.db.execute_read("SELECT path, recursive FROM monitored_paths")
        return [{"path": r["path"], "recursive": bool(r["recursive"])} for r in rows]

    def add_monitored_path(self, path, recursive=True):
        """Adds a path to the filesystem monitoring list."""
        self.db.execute_write(
            "INSERT OR IGNORE INTO monitored_paths (path, recursive) VALUES (?, ?)",
            (path, 1 if recursive else 0)
        )

    def remove_monitored_path(self, path):
        """Removes a path from the filesystem monitoring list."""
        self.db.execute_write("DELETE FROM monitored_paths WHERE path = ?", (path,))
