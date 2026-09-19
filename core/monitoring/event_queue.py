import queue
import threading
import logging
from config import EVENT_QUEUE_MAX_SIZE

logger = logging.getLogger("RansomGuard.EventQueue")

class EventQueue:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(EventQueue, cls).__new__(cls)
            return cls._instance

    def __init__(self, maxsize=EVENT_QUEUE_MAX_SIZE):
        if not hasattr(self, "initialized"):
            self.queue = queue.Queue(maxsize=maxsize)
            self.maxsize = maxsize
            self.dropped_events_count = 0
            self.initialized = True

    def put(self, event, block=False, timeout=None):
        """
        Pushes a telemetry event into the queue.
        If the queue is full, drops the event to protect memory usage and logs a warning.
        """
        try:
            self.queue.put_nowait(event)
            return True
        except queue.Full:
            self.dropped_events_count += 1
            if self.dropped_events_count % 1000 == 1:
                logger.warning(
                    f"Event queue is full (size={self.queue.qsize()}). "
                    f"Dropped {self.dropped_events_count} events so far due to backpressure."
                )
            return False

    def get_batch(self, batch_size=100, timeout=0.1):
        """
        Retrieves a batch of events from the queue.
        Blocks for up to 'timeout' seconds if the queue is empty.
        """
        batch = []
        try:
            # Block for the first element
            first_event = self.queue.get(block=True, timeout=timeout)
            batch.append(first_event)
            self.queue.task_done()
            
            # Fetch remaining elements without blocking
            while len(batch) < batch_size:
                try:
                    event = self.queue.get_nowait()
                    batch.append(event)
                    self.queue.task_done()
                except queue.Empty:
                    break
        except queue.Empty:
            pass
            
        return batch

    def qsize(self):
        return self.queue.qsize()

    def clear(self):
        """Drains all events from the queue."""
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
            except (queue.Empty, ValueError):
                break
        self.dropped_events_count = 0
