import os
import sys
import logging
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QFile, QTextStream

from config import DB_PATH, LOG_PATH
from core.database.database import DatabaseManager
from core.database.settings_repository import SettingsRepository
from ui.main_window import MainWindow

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("RansomGuard.App")

def initialize_default_monitored_paths(db_manager):
    """
    Ensures the persistent monitored_paths table matches the configured
    protected drive scope (e.g. E:\ or system drive) recursively.
    """
    settings_repo = SettingsRepository(db_manager)
    current_paths = settings_repo.get_monitored_paths()
    
    if not current_paths:
        system_drive = os.environ.get("SystemDrive", "C:").upper()
        if not system_drive.endswith(":"):
            system_drive += ":"
        drives_str = settings_repo.get_setting("protected_drives", "E:")
        for d in drives_str.split(","):
            d_clean = d.strip().rstrip("\\")
            if d_clean:
                if not d_clean.endswith(":"):
                    d_clean += ":"
                settings_repo.add_monitored_path(f"{d_clean}\\", recursive=True)
                logger.info(f"Registered default monitored drive root: {d_clean}\\")

def main():
    logger.info("Starting RansomGuard EDR Agent...")
    
    # 1. Initialize SQLite Database & Schema
    db_manager = DatabaseManager(DB_PATH)
    
    # 2. Pre-populate default monitored test path
    initialize_default_monitored_paths(db_manager)

    # 3. Create Qt Application & Apply Master RansomGuard Theme
    app = QApplication(sys.argv)
    
    from ui.theme import apply_theme
    apply_theme(app)
    logger.info("Loaded master global RansomGuard EDR design system theme")

    # 4. Display Main Window
    window = MainWindow(db_manager)
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
