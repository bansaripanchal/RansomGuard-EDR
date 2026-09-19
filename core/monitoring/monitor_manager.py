import os
import time
import logging
from PySide6.QtCore import QThread, Signal

from config import BATCH_SIZE_LIMIT, BATCH_INTERVAL_SEC, UI_STATS_REFRESH_MS
from core.monitoring.event_queue import EventQueue
from core.monitoring.file_monitor import FileMonitor
from core.monitoring.process_monitor import ProcessMonitor
from core.database.database import DatabaseManager
from core.database.settings_repository import SettingsRepository
from core.database.events_repository import EventsRepository
from core.database.incidents_repository import IncidentsRepository
from core.database.statistics_repository import StatisticsRepository
from core.database.history_repository import HistoryRepository
from core.detection.behavior_engine import BehaviorEngine
from core.protection.alert_manager import AlertManager

logger = logging.getLogger("RansomGuard.MonitorManager")

class BatchProcessor(QThread):
    # Signals to communicate with PySide6 UI thread
    events_processed = Signal(list)        # Normalized events processed in the batch
    incident_detected = Signal(dict, bool) # (Incident dict, is_new_flag)
    stats_updated = Signal(dict)           # Aggregated statistics dictionary

    def __init__(self, event_queue, behavior_engine, db_manager):
        super(BatchProcessor, self).__init__()
        self.queue = event_queue
        self.engine = behavior_engine
        self.db = db_manager
        
        self.events_repo = EventsRepository(self.db)
        self.incidents_repo = IncidentsRepository(self.db)
        self.stats_repo = StatisticsRepository(self.db)
        self.history_repo = HistoryRepository(self.db)
        self.settings_repo = SettingsRepository(self.db)
        
        self.running = False
        self.last_stats_emit = 0

    def run(self):
        self.running = True
        logger.info("Batch Processor thread running.")
        
        while self.running:
            # Retrieve a batch of events from the queue
            batch = self.queue.get_batch(batch_size=BATCH_SIZE_LIMIT, timeout=BATCH_INTERVAL_SEC)
            
            if batch:
                try:
                    self._process_batch(batch)
                except Exception as e:
                    logger.error(f"Error processing batch: {e}", exc_info=True)
            
            # Periodically emit updated stats to throttle UI updates
            now_ms = time.time() * 1000
            if now_ms - self.last_stats_emit >= UI_STATS_REFRESH_MS:
                try:
                    stats = self.stats_repo.get_dashboard_summary()
                    stats["weekly_activity"] = self.stats_repo.get_weekly_activity()
                    stats["monthly_activity"] = self.stats_repo.get_monthly_activity()
                    self.stats_updated.emit(stats)
                    self.last_stats_emit = now_ms
                except Exception as e:
                    logger.error(f"Error querying dashboard statistics: {e}")

    def stop(self):
        self.running = False
        self.wait(200) # Wait up to 200ms for thread to finish
        logger.info("Batch Processor thread stopped.")

    def _process_batch(self, batch):
        # 1. Feed events to the behavior detection engine
        detected_incidents = self.engine.process_new_events(batch)

        # 2. Insert the events into the database and audit history
        db_events = []
        created_count = 0
        deleted_count = 0
        for ev in batch:
            if len(ev) >= 10:
                event_type, src_path, dest_path, extension, file_size, _, sha256, proc_name, proc_pid, attr_status = ev[:10]
            else:
                event_type, src_path, dest_path, extension, file_size, _ = ev[:6]
                sha256 = None
                proc_name = "Unknown"
                proc_pid = None
                attr_status = "UNAVAILABLE"

            src_path = os.path.normpath(os.path.abspath(src_path))
            if dest_path:
                dest_path = os.path.normpath(os.path.abspath(dest_path))

            target_path = dest_path if (event_type == "RENAME" and dest_path) else src_path

            # Late size check for newly flushed files if size is unknown / unavailable
            if (file_size is None or file_size == -2) and event_type != "DELETE":
                if os.path.exists(target_path):
                    if not os.path.isdir(target_path):
                        try:
                            file_size = os.path.getsize(target_path)
                        except (PermissionError, OSError):
                            file_size = -2
                        except Exception:
                            pass
                else:
                    file_size = -1  # File was removed before late capture completed

            # Late process correlation if currently unknown
            if proc_name in ("Unknown", None) and self.engine.process_monitor:
                try:
                    pinfo = self.engine.process_monitor.find_process_accessing_path(target_path)
                    if pinfo:
                        proc_name = pinfo.get("name") or "Unknown"
                        proc_pid = pinfo.get("pid")
                        attr_status = pinfo.get("attribution_status") or "CORRELATED"
                except Exception:
                    pass

            if event_type == "CREATE":
                created_count += 1
            elif event_type == "DELETE":
                deleted_count += 1
            
            parent_dir = os.path.normpath(os.path.dirname(src_path))
            inc_row = self.incidents_repo.get_active_incident_by_folder(parent_dir, age_seconds=60)
            incident_id = inc_row["id"] if inc_row else None
            
            db_events.append((
                event_type, src_path, dest_path, extension, file_size, incident_id,
                sha256, proc_name, proc_pid, attr_status
            ))
            
            # If event occurred on a connected USB storage device, evaluate real-time USB protection
            try:
                from core.protection.usb_protection_manager import USBProtectionManager
                usb_mgr = USBProtectionManager.get_instance(self.db)
                if usb_mgr.connected_devices:
                    usb_mgr.analyze_realtime_event(target_path, event_type)
            except Exception as e:
                logger.debug(f"USB real-time event check: {e}")
            # Note: Routine filesystem activity is recorded into file_events for telemetry and detection.
            # Administrative audit history is reserved strictly for real application/security milestones.
            
        self.events_repo.insert_events_batch(db_events)
        
        # 3. Synchronize incident event counts and notify alerts
        for inc_dict, is_new in detected_incidents:
            inc_id = inc_dict["id"]
            if is_new:
                # Retroactively link any earlier unlinked events in this folder from the last 10 seconds
                try:
                    folder_norm = os.path.normpath(inc_dict["affected_folder"])
                    conn = self.db.get_connection()
                    with conn:
                        cursor = conn.cursor()
                        cursor.execute("""
                            UPDATE file_events 
                            SET incident_id = ? 
                            WHERE incident_id IS NULL 
                              AND (src_path LIKE ? OR src_path = ?)
                              AND timestamp >= datetime('now', '-10 seconds')
                        """, (inc_id, f"{folder_norm}\\%", folder_norm))
                except Exception as e:
                    logger.error(f"Error retroactively linking events: {e}")

                self.history_repo.insert_log(
                    event_type="THREAT_DETECTED",
                    severity=inc_dict["severity"],
                    description=f"Security incident '{inc_dict['threat_name']}' detected in {inc_dict['affected_folder']}",
                    target=inc_dict.get("full_path") or inc_dict["affected_folder"],
                    action_taken="ALERT_GENERATED"
                )
                AlertManager.trigger_incident_alert(inc_dict)

            # Sync accurate counts directly from file_events
            self.incidents_repo.sync_incident_counts(inc_id)
            updated_inc = self.incidents_repo.get_incident(inc_id)
            if updated_inc:
                self.incident_detected.emit(updated_inc, is_new)
        
        # Incremental file count update in SQLite settings
        if created_count > 0 or deleted_count > 0:
            try:
                current_count_str = self.settings_repo.get_setting("total_files_count", "0")
                current_count = int(current_count_str) if current_count_str else 0
                new_count = max(0, current_count + created_count - deleted_count)
                self.settings_repo.set_setting("total_files_count", new_count)
            except Exception as e:
                logger.error(f"Error updating total file count: {e}")
        
        # 3. Emit processed events to the Live Protection log page
        # Map back to dict/readable structure for the table view
        live_events_batch = []
        for dev in db_events:
            live_events_batch.append({
                "timestamp": datetime_to_str(time.time()),
                "event_type": dev[0],
                "src_path": dev[1],
                "dest_path": dev[2],
                "extension": dev[3],
                "file_size": dev[4],
                "incident_id": dev[5],
                "sha256": dev[6],
                "process_name": dev[7],
                "process_pid": dev[8],
                "attribution_status": dev[9]
            })
        self.events_processed.emit(live_events_batch)

        # 4. Periodically emit updated stats to throttle UI updates if interval elapsed
        now_ms = time.time() * 1000
        if now_ms - self.last_stats_emit >= UI_STATS_REFRESH_MS:
            try:
                stats = self.stats_repo.get_dashboard_summary()
                stats["weekly_activity"] = self.stats_repo.get_weekly_activity()
                stats["monthly_activity"] = self.stats_repo.get_monthly_activity()
                self.stats_updated.emit(stats)
                self.last_stats_emit = now_ms
            except Exception as e:
                logger.error(f"Error querying dashboard statistics in batch processor: {e}")


def datetime_to_str(timestamp):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


class FileCounterThread(QThread):
    count_updated = Signal(int, str) # (count, status)
    
    def __init__(self, monitored_paths, db_manager):
        super(FileCounterThread, self).__init__()
        self.paths = monitored_paths
        self.db = db_manager
        self.settings_repo = SettingsRepository(self.db)
        self.running = False

    def run(self):
        self.running = True
        logger.info("File Counter background thread started.")
        self.settings_repo.set_setting("total_files_status", "calculating")
        self.count_updated.emit(0, "calculating")
        
        total_files = 0
        last_emitted_count = 0
        last_emit_time = time.time()
        for mp in self.paths:
            if not self.running:
                break
                
            path = mp["path"]
            recursive = mp["recursive"]
            
            if not os.path.exists(path):
                continue
                
            if os.path.isfile(path):
                total_files += 1
                if (total_files - last_emitted_count >= 1000) or (time.time() - last_emit_time >= 0.5):
                    self.settings_repo.set_setting("total_files_count", total_files)
                    self.count_updated.emit(total_files, "calculating")
                    last_emitted_count = total_files
                    last_emit_time = time.time()
                continue
                
            # Walk directory recursively
            if recursive:
                try:
                    for root, dirs, files in os.walk(path):
                        if not self.running:
                            break
                        total_files += len(files)
                        
                        # Yield to prevent high CPU usage
                        time.sleep(0.001)
                        
                        # Save intermediate count periodically (every 1,000 files or 500ms)
                        if (total_files - last_emitted_count >= 1000) or (time.time() - last_emit_time >= 0.5 and total_files != last_emitted_count):
                            self.settings_repo.set_setting("total_files_count", total_files)
                            self.count_updated.emit(total_files, "calculating")
                            last_emitted_count = total_files
                            last_emit_time = time.time()
                except Exception as e:
                    logger.error(f"Error walking directory {path}: {e}")
            else:
                try:
                    entries = os.listdir(path)
                    files_only = [f for f in entries if os.path.isfile(os.path.join(path, f))]
                    total_files += len(files_only)
                    if (total_files - last_emitted_count >= 1000) or (time.time() - last_emit_time >= 0.5 and total_files != last_emitted_count):
                        self.settings_repo.set_setting("total_files_count", total_files)
                        self.count_updated.emit(total_files, "calculating")
                        last_emitted_count = total_files
                        last_emit_time = time.time()
                except Exception as e:
                    logger.error(f"Error listing directory {path}: {e}")
                    
        if self.running:
            self.settings_repo.set_setting("total_files_count", total_files)
            self.settings_repo.set_setting("total_files_status", "done")
            self.count_updated.emit(total_files, "done")
            logger.info(f"File Counter background thread completed. Total files: {total_files}")
            
    def stop(self):
        self.running = False
        self.wait(100)


class MonitorManager:
    _instance = None
    _lock = os.sys.modules['threading'].Lock() # Get threading lock dynamically

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(MonitorManager, cls).__new__(cls)
            return cls._instance

    def __init__(self, db_manager=None):
        if not hasattr(self, "initialized"):
            self.db = db_manager or DatabaseManager()
            self.settings_repo = SettingsRepository(self.db)
            
            # Setup Queue and Monitors
            self.queue = EventQueue()
            self.process_monitor = ProcessMonitor()
            self.behavior_engine = BehaviorEngine(self.db, self.process_monitor)
            from core.monitoring.event_handler import FileSystemEventHandlerImpl
            self.file_monitor = FileMonitor(FileSystemEventHandlerImpl(self.queue, self.process_monitor))
            
            # Setup batch processor
            self.batch_processor = BatchProcessor(self.queue, self.behavior_engine, self.db)
            self.file_counter_thread = None
            self.initialized = True

    def start_monitoring(self):
        """Initializes and starts all EDR monitors and processors."""
        # Load directories from DB and update monitoring observer
        self.update_monitoring_paths()
            
        self.process_monitor.start_monitoring()
        self.batch_processor.start()
        
        # Log event
        HistoryRepository(self.db).insert_log(
            event_type="PROTECTION_START",
            severity="LOW",
            description="RansomGuard real-time protection started.",
            action_taken="MONITORING_ACTIVE"
        )
        logger.info("RansomGuard monitoring system activated.")

    def stop_monitoring(self):
        """Safely shuts down all EDR monitors and processors."""
        if hasattr(self, "file_counter_thread") and self.file_counter_thread and self.file_counter_thread.isRunning():
            self.file_counter_thread.stop()
        self.file_monitor.stop()
        self.process_monitor.stop_monitoring()
        self.batch_processor.stop()
        
        # Log event
        try:
            HistoryRepository(self.db).insert_log(
                event_type="PROTECTION_STOP",
                severity="LOW",
                description="RansomGuard real-time protection stopped.",
                action_taken="MONITORING_DEACTIVATED"
            )
        except Exception as e:
            logger.error(f"Error logging protection stop: {e}")
        logger.info("RansomGuard monitoring system deactivated.")

    def add_monitored_directory(self, path, recursive=True):
        """Adds a path to SQLite settings and monitors it actively."""
        self.settings_repo.add_monitored_path(path, recursive)
        return self.file_monitor.add_path(path, recursive)

    def remove_monitored_directory(self, path):
        """Removes a path from SQLite settings and stops monitoring it."""
        self.settings_repo.remove_monitored_path(path)
        return self.file_monitor.remove_path(path)

    def start_file_counting(self, paths, callback):
        """Starts a background thread to recursively count files in the monitored paths."""
        if self.file_counter_thread and self.file_counter_thread.isRunning():
            self.file_counter_thread.stop()
            
        self.file_counter_thread = FileCounterThread(paths, self.db)
        self.file_counter_thread.count_updated.connect(callback)
        self.file_counter_thread.start()

    def update_monitoring_paths(self):
        """Dynamically re-loads active paths from database and configures watchdog observer."""
        self.file_monitor.stop()
        from core.monitoring.event_handler import FileSystemEventHandlerImpl
        self.file_monitor = FileMonitor(FileSystemEventHandlerImpl(self.queue, self.process_monitor))
        
        # Only start observer if EDR protection is enabled
        shield_active = self.settings_repo.get_setting("protection_enabled", "True").lower() == "true"
        if shield_active:
            self.file_monitor.start()
            monitored_paths = self.settings_repo.get_monitored_paths()
            for mp in monitored_paths:
                path = mp["path"]
                self.file_monitor.add_path(path, mp["recursive"])
            logger.info(f"Watchdog observer active monitoring paths updated to: {[mp['path'] for mp in monitored_paths]}")
        else:
            logger.info("Watchdog observer not started because protection shield is currently disabled.")
