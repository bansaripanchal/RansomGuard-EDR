import os
import time
import hashlib
import threading
from watchdog.events import FileSystemEventHandler
from core.monitoring.event_queue import EventQueue

def _compute_sha256(path, max_bytes=1048576):
    """Computes complete SHA-256 for files up to max_bytes. Returns hex string or None on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

class FileSystemEventHandlerImpl(FileSystemEventHandler):
    def __init__(self, event_queue=None, process_monitor=None):
        super(FileSystemEventHandlerImpl, self).__init__()
        self.queue = event_queue or EventQueue()
        self.process_monitor = process_monitor
        self._lock = threading.Lock()
        
        # Cache mapping canonical path -> dict with state:
        # {'size': int, 'mtime_ns': int, 'hash': str, 'last_emitted_time': float, 'timer': threading.Timer}
        self.path_state_cache = {}

    def _enqueue_event(self, event_type, src_path, dest_path=None):
        # 1. Canonical full absolute Windows path
        src_path = os.path.normpath(os.path.abspath(src_path))
        if dest_path:
            dest_path = os.path.normpath(os.path.abspath(dest_path))

        # Skip internal database and log files created by RansomGuard
        src_lower = src_path.lower()
        if "ransomguard.db" in src_lower or "ransomguard.log" in src_lower or "ransomguard.db-wal" in src_lower or "ransomguard.db-shm" in src_lower:
            return

        # Extract normalized file extension
        target_path = dest_path if (event_type == "RENAME" and dest_path) else src_path
        _, ext = os.path.splitext(target_path)
        ext = ext.lower()

        # 2. Real File Size Capture
        # Semantic codes:
        #   >= 0 : Real file size in bytes (including genuine 0-byte files)
        #   -1   : Deleted before capture / no longer exists on disk
        #   -2   : Unavailable (OS denied access, locked, permission error, stat error)
        file_size = -2  # Default: Unavailable
        file_sha256 = None
        if event_type in ("CREATE", "MODIFY"):
            if os.path.exists(target_path):
                if not os.path.isdir(target_path):
                    try:
                        stat_info = os.stat(target_path)
                        file_size = stat_info.st_size
                        with self._lock:
                            cached = self.path_state_cache.get(target_path, {})
                            cached['size'] = file_size
                            cached['mtime_ns'] = stat_info.st_mtime_ns
                            if file_size <= 1048576:
                                file_sha256 = cached.get('hash')
                                if not file_sha256:
                                    file_sha256 = _compute_sha256(target_path)
                                    cached['hash'] = file_sha256
                            self.path_state_cache[target_path] = cached
                    except (PermissionError, OSError):
                        file_size = -2
                    except Exception:
                        with self._lock:
                            file_size = self.path_state_cache.get(target_path, {}).get('size', -2)
                else:
                    file_size = -2
            else:
                with self._lock:
                    file_size = self.path_state_cache.get(target_path, {}).get('size', -1)
        elif event_type == "RENAME":
            if dest_path and os.path.exists(dest_path) and not os.path.isdir(dest_path):
                try:
                    stat_info = os.stat(dest_path)
                    file_size = stat_info.st_size
                    with self._lock:
                        old_cache = self.path_state_cache.pop(src_path, {})
                        old_cache['size'] = file_size
                        old_cache['mtime_ns'] = stat_info.st_mtime_ns
                        self.path_state_cache[dest_path] = old_cache
                except Exception:
                    with self._lock:
                        file_size = self.path_state_cache.get(src_path, {}).get('size', -2)
            else:
                with self._lock:
                    file_size = self.path_state_cache.get(src_path, {}).get('size', -2)
        elif event_type == "DELETE":
            with self._lock:
                cached = self.path_state_cache.pop(src_path, {})
                file_size = cached.get('size', -1)

        # Limit cache size to prevent memory bloat
        with self._lock:
            if len(self.path_state_cache) > 50000:
                self.path_state_cache.clear()

        # 3. Genuine Process Attribution
        proc_name = "Unknown"
        proc_pid = None
        attribution_status = "UNAVAILABLE"
        if self.process_monitor:
            try:
                pinfo = self.process_monitor.find_process_accessing_path(target_path)
                if pinfo:
                    proc_name = pinfo.get("name") or "Unknown"
                    proc_pid = pinfo.get("pid")
                    attribution_status = pinfo.get("attribution_status") or "CORRELATED"
            except Exception:
                pass

        # Normalized structure: (event_type, src_path, dest_path, extension, file_size, incident_id, sha256, proc_name, proc_pid, attribution_status)
        self.queue.put((event_type, src_path, dest_path, ext, file_size, None, file_sha256, proc_name, proc_pid, attribution_status))

    def on_created(self, event):
        if event.is_directory:
            return
        target = os.path.normpath(os.path.abspath(event.src_path))
        # Initial registration in state cache
        if os.path.exists(target) and not os.path.isdir(target):
            try:
                stat_info = os.stat(target)
                h = _compute_sha256(target) if stat_info.st_size <= 1048576 else None
                with self._lock:
                    self.path_state_cache[target] = {
                        'size': stat_info.st_size,
                        'mtime_ns': stat_info.st_mtime_ns,
                        'hash': h,
                        'last_emitted_time': time.time(),
                        'timer': None
                    }
            except Exception:
                pass
        self._enqueue_event("CREATE", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return

        target_path = os.path.normpath(os.path.abspath(event.src_path))

        # Skip internal database and log files created by RansomGuard
        src_lower = target_path.lower()
        if "ransomguard.db" in src_lower or "ransomguard.log" in src_lower or "ransomguard.db-wal" in src_lower or "ransomguard.db-shm" in src_lower:
            return

        if not os.path.exists(target_path) or os.path.isdir(target_path):
            return

        try:
            stat_info = os.stat(target_path)
            curr_size = stat_info.st_size
            curr_mtime = stat_info.st_mtime_ns
        except Exception:
            return

        with self._lock:
            cached = self.path_state_cache.get(target_path)

            # Tier 1 (Fast Guard): If cached state has identical size and mtime_ns,
            # this event was triggered by an open, read, query, or AV scan. Suppress immediately.
            if cached and cached.get('size') == curr_size and cached.get('mtime_ns') == curr_mtime:
                return

            # Tier 2 (Small files <= 1 MB): Cryptographically verify complete file content
            if curr_size <= 1048576:
                curr_hash = _compute_sha256(target_path)
                if cached and cached.get('hash') and curr_hash == cached.get('hash'):
                    # Content did not change (e.g. metadata or timestamp touch only). Suppress.
                    cached['mtime_ns'] = curr_mtime
                    return
                # Content changed (or initial state)
                new_hash = curr_hash
            else:
                # Tier 3 (Larger files > 1 MB): Non-blocking path.
                # Size or mtime changed, signaling an actual write operation.
                new_hash = None

            now = time.time()
            if not cached:
                cached = {
                    'size': curr_size,
                    'mtime_ns': curr_mtime,
                    'hash': new_hash,
                    'last_emitted_time': now,
                    'timer': None
                }
                self.path_state_cache[target_path] = cached
                self._enqueue_event("MODIFY", target_path)
                return

            # Trailing-edge debouncing: if writes are streaming rapidly (< 150ms)
            cached['size'] = curr_size
            cached['mtime_ns'] = curr_mtime
            if new_hash is not None:
                cached['hash'] = new_hash

            last_emitted = cached.get('last_emitted_time', 0.0)
            if now - last_emitted < 0.15:
                # Cancel existing pending timer and reset debounce timer to capture final write state
                existing_timer = cached.get('timer')
                if existing_timer:
                    try:
                        existing_timer.cancel()
                    except Exception:
                        pass
                
                def _debounced_flush(p=target_path):
                    with self._lock:
                        c = self.path_state_cache.get(p)
                        if c:
                            c['timer'] = None
                            c['last_emitted_time'] = time.time()
                    self._enqueue_event("MODIFY", p)

                t = threading.Timer(0.15, _debounced_flush)
                t.daemon = True
                cached['timer'] = t
                t.start()
                return

            # If more than 150ms since last emitted event, dispatch genuine MODIFY immediately
            cached['last_emitted_time'] = now
            existing_timer = cached.get('timer')
            if existing_timer:
                try:
                    existing_timer.cancel()
                except Exception:
                    pass
                cached['timer'] = None

        self._enqueue_event("MODIFY", target_path)

    def on_deleted(self, event):
        if not event.is_directory:
            target = os.path.normpath(os.path.abspath(event.src_path))
            with self._lock:
                cached = self.path_state_cache.pop(target, None)
                if cached and cached.get('timer'):
                    try:
                        cached['timer'].cancel()
                    except Exception:
                        pass
            self._enqueue_event("DELETE", event.src_path)

    def on_moved(self, event):
        # In watchdog, moving/renaming uses MovedEvent
        if not event.is_directory:
            src = os.path.normpath(os.path.abspath(event.src_path))
            dst = os.path.normpath(os.path.abspath(event.dest_path))
            with self._lock:
                cached = self.path_state_cache.pop(src, {})
                if cached and cached.get('timer'):
                    try:
                        cached['timer'].cancel()
                    except Exception:
                        pass
                    cached['timer'] = None
                self.path_state_cache[dst] = cached
            self._enqueue_event("RENAME", event.src_path, event.dest_path)
        else:
            # If an entire folder was moved, propagate individual file moves for any contained files
            dest_dir = event.dest_path
            src_dir = event.src_path
            if os.path.exists(dest_dir):
                try:
                    for root, _, files in os.walk(dest_dir):
                        for f in files:
                            dst_f = os.path.join(root, f)
                            rel = os.path.relpath(dst_f, dest_dir)
                            src_f = os.path.join(src_dir, rel)
                            self._enqueue_event("RENAME", src_f, dst_f)
                except Exception:
                    pass

