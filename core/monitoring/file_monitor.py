import os
import logging
import threading
from watchdog.observers import Observer
from core.monitoring.event_handler import FileSystemEventHandlerImpl

logger = logging.getLogger("RansomGuard.FileMonitor")

class FileMonitor:
    def __init__(self, event_handler=None):
        self.observer = None
        self.watches = {}  # Map path -> watch_descriptor
        self.event_handler = event_handler or FileSystemEventHandlerImpl()

    def start(self):
        """Starts the background watchdog observer thread."""
        if self.observer is None:
            self.observer = Observer()
            self.observer.start()
            logger.info("Watchdog Observer thread started.")

    def stop(self):
        """Stops the watchdog observer safely without blocking the main GUI thread."""
        if self.observer is not None:
            obs = self.observer
            self.observer = None
            def _shutdown():
                try:
                    obs.stop()
                    obs.join(timeout=0.5)
                except Exception as e:
                    logger.debug(f"Observer shutdown: {e}")
            t = threading.Thread(target=_shutdown, daemon=True)
            t.start()
            t.join(timeout=0.5)
        self.watches.clear()
        logger.info("Watchdog Observer stopped.")

    def add_path(self, path, recursive=True):
        """Adds a path to be monitored in real-time."""
        if not os.path.exists(path):
            logger.error(f"Cannot monitor non-existent path: {path}")
            return False
        
        # Standardise path format
        path = os.path.normpath(path)
        if path in self.watches:
            return True

        if self.observer is not None:
            try:
                watch = self.observer.schedule(self.event_handler, path, recursive=recursive)
                self.watches[path] = watch
                logger.info(f"Started monitoring directory: {path} (recursive={recursive})")
                return True
            except Exception as e:
                logger.error(f"Failed to schedule path {path}: {e}")
                return False
        else:
            logger.warning(f"Attempted to monitor path {path} but file monitor is stopped.")
            return False

    def remove_path(self, path):
        """Stops monitoring a specific path."""
        path = os.path.normpath(path)
        if path not in self.watches:
            return False

        watch = self.watches.pop(path)
        if self.observer is not None:
            try:
                self.observer.unschedule(watch)
                logger.info(f"Stopped monitoring directory: {path}")
                return True
            except Exception as e:
                logger.error(f"Failed to unschedule path {path}: {e}")
                # Put it back since unschedule failed
                self.watches[path] = watch
                return False
        return False

    def get_monitored_paths(self):
        """Returns list of currently active directory watches."""
        return list(self.watches.keys())
