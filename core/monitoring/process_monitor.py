import os
import tempfile
import psutil
import threading
import time
import logging

logger = logging.getLogger("RansomGuard.ProcessMonitor")

class ProcessMonitor(threading.Thread):
    def __init__(self, interval_sec=1.5):
        super(ProcessMonitor, self).__init__(name="ProcessMonitorThread")
        self.interval = interval_sec
        self.running = False
        self._lock = threading.Lock()
        
        # Cache mapping PID -> process details
        self.process_cache = {}
        
        self.daemon = True

    def start_monitoring(self):
        self.running = True
        self.start()
        logger.info("Process Monitor thread started.")

    def stop_monitoring(self):
        self.running = False
        logger.info("Process Monitor thread stop requested.")

    def run(self):
        # Initial population of cache
        self._update_cache()
        
        while self.running:
            time.sleep(self.interval)
            try:
                self._update_cache()
            except Exception as e:
                logger.error(f"Error during process cache update: {e}")

    def _update_cache(self):
        current_cache = {}
        for proc in psutil.process_iter(attrs=['pid', 'name', 'exe', 'cpu_percent', 'io_counters']):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name']
                exe = info['exe'] or "Unknown"
                cpu = info['cpu_percent'] or 0.0
                
                # Disk I/O ops
                io = info['io_counters']
                write_ops = io.write_count if io else 0
                write_bytes = io.write_bytes if io else 0
                
                # Check previous delta if available
                prev = self.process_cache.get(pid)
                write_ops_delta = 0
                write_bytes_delta = 0
                
                if prev:
                    write_ops_delta = max(0, write_ops - prev.get('write_ops', 0))
                    write_bytes_delta = max(0, write_bytes - prev.get('write_bytes', 0))
                
                current_cache[pid] = {
                    'pid': pid,
                    'name': name,
                    'exe': exe,
                    'cpu_percent': cpu,
                    'write_ops': write_ops,
                    'write_bytes': write_bytes,
                    'write_ops_delta': write_ops_delta,
                    'write_bytes_delta': write_bytes_delta
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        with self._lock:
            self.process_cache = current_cache

    def get_process_info(self, pid):
        """Retrieves info about a process from the cache."""
        with self._lock:
            return self.process_cache.get(pid)

    SYSTEM_PROCESS_SKIPS = {
        "system", "system idle process", "registry", "smss.exe", "csrss.exe", 
        "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe", 
        "dwm.exe", "ravcpl64.exe", "audiodg.exe", "spoolsv.exe", "searchindexer.exe"
    }

    def find_process_accessing_path(self, target_path):
        """
        Attempts to locate a real Windows process that has open file handles to target_path
        or is working from within the targeted directory hierarchy.
        Returns dict with {'pid', 'name', 'exe', 'username', 'attribution_status'} or None if not determinable.
        Does NOT guess, fabricate PIDs, or return placeholders.
        """
        if not target_path:
            return None
            
        try:
            target_norm = os.path.normpath(os.path.abspath(target_path)).lower()
            target_dir = target_norm if os.path.isdir(target_norm) else os.path.dirname(target_norm)
            windir = os.environ.get("WINDIR", "C:\\Windows").lower()
            temp_dir = tempfile.gettempdir().lower()

            # 1. Fast check: Check current process first (e.g. running test or active tool)
            try:
                cur_proc = psutil.Process()
                for of in cur_proc.open_files():
                    if of.path and os.path.normpath(os.path.abspath(of.path)).lower() == target_norm:
                        return {
                            'pid': cur_proc.pid,
                            'name': cur_proc.name(),
                            'exe': cur_proc.exe() if hasattr(cur_proc, 'exe') else None,
                            'username': cur_proc.username() if hasattr(cur_proc, 'username') else None,
                            'attribution_status': 'DIRECT'
                        }
            except Exception:
                pass

            # 2. Check active user processes with a hard timeout budget (max 300 ms total)
            start_time = time.perf_counter()
            for proc in psutil.process_iter(attrs=['pid', 'name']):
                # Budget limit to guarantee worker threads never hang
                if (time.perf_counter() - start_time) > 0.35:
                    break

                try:
                    pname = (proc.info.get('name') or "").lower()
                    pid = proc.info.get('pid')

                    # Skip known Windows kernel / audio / hardware drivers that hang NtQueryInformationFile
                    if pid <= 4 or pname in self.SYSTEM_PROCESS_SKIPS:
                        continue

                    # Check working directory first (very fast CWD check)
                    try:
                        cwd = proc.cwd()
                        if cwd:
                            cwd_norm = os.path.normpath(os.path.abspath(cwd)).lower()
                            if (len(cwd_norm) > 3 and 
                                not cwd_norm.startswith(windir) and 
                                not cwd_norm.startswith(temp_dir)):
                                if target_norm.startswith(cwd_norm + os.sep) or target_norm == cwd_norm:
                                    return {
                                        'pid': proc.pid,
                                        'name': proc.name(),
                                        'exe': proc.exe() if hasattr(proc, 'exe') else None,
                                        'username': proc.username() if hasattr(proc, 'username') else None,
                                        'attribution_status': 'CORRELATED'
                                    }
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                    # Check open file handles (Direct Attribution)
                    try:
                        open_files = proc.open_files()
                        for of in open_files:
                            if of.path:
                                of_norm = os.path.normpath(os.path.abspath(of.path)).lower()
                                if of_norm == target_norm:
                                    return {
                                        'pid': proc.pid,
                                        'name': proc.name(),
                                        'exe': proc.exe() if hasattr(proc, 'exe') else None,
                                        'username': proc.username() if hasattr(proc, 'username') else None,
                                        'attribution_status': 'DIRECT'
                                    }
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            logger.debug(f"Error querying process correlation for {target_path}: {e}")
                
        return None
