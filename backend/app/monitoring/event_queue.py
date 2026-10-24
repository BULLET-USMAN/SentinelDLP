"""Bounded Event Queue Module for SentinelDLP (Phase 4).

Buffers normalized filesystem events with bounded capacity, overflow metrics,
and non-blocking ingestion to protect observer threads from backpressure.
"""

import queue
import threading
from typing import Optional
from app.core.logging import logger
from app.monitoring.event_normalizer import NormalizedEvent


class BoundedEventQueue:
    """Thread-safe bounded FIFO queue for activity events."""

    def __init__(self, maxsize: int = 5000) -> None:
        self.maxsize = maxsize
        self._queue: queue.Queue[Optional[NormalizedEvent]] = queue.Queue(maxsize=maxsize)
        self._overflow_count = 0
        self._lock = threading.Lock()

    def enqueue(self, event: NormalizedEvent) -> bool:
        """Enqueue event without blocking the filesystem watcher thread.

        Returns:
            True if event was queued successfully.
            False if queue is full (overflow recorded).
        """
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            with self._lock:
                self._overflow_count += 1
            logger.warning(
                f"Monitoring queue overflow! Dropped event {event.event_type} on '{event.relative_path}'. "
                f"Total overflows: {self._overflow_count}",
                extra={"event": "monitoring_queue_overflow", "overflow_count": self._overflow_count},
            )
            return False

    def dequeue(self, timeout: float = 1.0) -> Optional[NormalizedEvent]:
        """Retrieve next event for processing, blocking up to timeout seconds."""
        try:
            return self._queue.get(block=True, timeout=timeout)
        except queue.Empty:
            return None

    def task_done(self) -> None:
        """Signal completion of dequeued item."""
        self._queue.task_done()

    @property
    def overflow_count(self) -> int:
        """Total number of events dropped due to queue saturation."""
        with self._lock:
            return self._overflow_count

    @property
    def qsize(self) -> int:
        """Current number of items waiting in queue."""
        return self._queue.qsize()

    def clear(self) -> None:
        """Drain all remaining items."""
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except queue.Empty:
                break
