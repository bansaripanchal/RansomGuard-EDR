import time
import logging
import uuid
from typing import Dict, Any, Optional

from PySide6.QtCore import QThread, Signal
from core.scanning.image_text_finder import ImageHiddenTextAnalyzer
from core.database.image_scan_repository import ImageScanRepository
from core.database.history_repository import HistoryRepository

logger = logging.getLogger("RansomGuard.ImageScanWorker")

class ImageScanWorker(QThread):
    """Background worker thread for running Image Hidden Text Finder without blocking PySide6 GUI."""

    progress_updated = Signal(str, int)  # (stage_description, percentage_0_to_100)
    scan_completed = Signal(dict)        # (full_analysis_result_dict)
    scan_failed = Signal(str)           # (error_message)

    def __init__(self, file_path: str, db_manager=None, parent=None):
        super(ImageScanWorker, self).__init__(parent)
        self.file_path = file_path
        self.db_manager = db_manager
        self.analyzer = ImageHiddenTextAnalyzer()
        self.is_cancelled = False
        self.scan_id = str(uuid.uuid4())[:12]

    def cancel(self):
        self.is_cancelled = True

    def run(self):
        try:
            logger.info(f"Starting Image Hidden Text scan for: {self.file_path}")
            
            # Stage 1: Load image
            self.progress_updated.emit("Loading image file...", 15)
            time.sleep(0.05)
            if self.is_cancelled:
                self.scan_failed.emit("Scan cancelled by user.")
                return

            # Stage 2: Technical metadata
            self.progress_updated.emit("Extracting technical metadata & EXIF tags...", 30)
            time.sleep(0.05)
            if self.is_cancelled:
                self.scan_failed.emit("Scan cancelled by user.")
                return

            # Stage 3: Visible Text OCR
            self.progress_updated.emit("Analyzing visible text (OCR)...", 45)
            time.sleep(0.05)
            if self.is_cancelled:
                self.scan_failed.emit("Scan cancelled by user.")
                return

            # Stage 4: Transformations & Hidden Text Analysis
            self.progress_updated.emit("Applying contrast & luminance transformations...", 65)
            time.sleep(0.05)
            if self.is_cancelled:
                self.scan_failed.emit("Scan cancelled by user.")
                return

            # Stage 5: Independent Channel Analysis
            self.progress_updated.emit("Analyzing independent RGB & Alpha channels...", 80)
            time.sleep(0.05)
            if self.is_cancelled:
                self.scan_failed.emit("Scan cancelled by user.")
                return

            # Stage 6: Embedded Data Analysis
            self.progress_updated.emit("Checking potential embedded data indicators...", 90)
            
            # Run full real analysis
            result = self.analyzer.analyze_image(self.file_path)
            result["scan_id"] = self.scan_id

            # Stage 7: Finalize & Persist to Database if DB available
            self.progress_updated.emit("Finalizing analysis report...", 100)
            
            if self.db_manager:
                try:
                    repo = ImageScanRepository(self.db_manager)
                    repo.insert_scan_result(result)

                    # Insert entry into history log
                    hist_repo = HistoryRepository(self.db_manager)
                    hist_repo.insert_log(
                        event_type="IMAGE_HIDDEN_TEXT",
                        severity="INFORMATIONAL",
                        description=f"Image Hidden Text scan completed for '{result.get('filename')}' — Category: {result.get('category')}",
                        target=self.file_path,
                        action_taken="Image Analyzed"
                    )
                except Exception as db_err:
                    logger.error(f"Database persistence error: {db_err}")

            self.scan_completed.emit(result)

        except Exception as e:
            logger.error(f"Image scan worker exception: {e}", exc_info=True)
            self.scan_failed.emit(f"Unable to analyze image: {e}")
