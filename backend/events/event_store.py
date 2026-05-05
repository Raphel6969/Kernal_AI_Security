"""
In-memory event store for security events.
Maintains a rolling buffer of the most recent events.
"""

from collections import deque
from typing import List
from backend.events.models import SecurityEvent


class EventStore:
    """
    Thread-safe event storage using a circular buffer.
    Automatically evicts oldest events when capacity is reached.
    """

    def __init__(self, max_events: int = 1000):
        """
        Initialize event store.
        
        Args:
            max_events: Maximum number of events to keep in memory
        """
        self.max_events = max_events
        self.events: deque = deque(maxlen=max_events)

    def append(self, event: SecurityEvent) -> None:
        """
        Add an event to the store.
        
        Args:
            event: SecurityEvent to store
        """
        self.events.append(event)

    def get_recent(self, n: int = 100) -> List[SecurityEvent]:
        """
        Get the N most recent events.
        
        Args:
            n: Number of recent events to retrieve
            
        Returns:
            List of SecurityEvent objects (oldest to newest)
        """
        return list(self.events)[-n:] if n > 0 else []

    def get_all(self) -> List[SecurityEvent]:
        """
        Get all events in the store.
        
        Returns:
            List of all SecurityEvent objects
        """
        return list(self.events)

    def clear(self) -> None:
        """Clear all events from the store."""
        self.events.clear()

    def size(self) -> int:
        """Get the current number of events in the store."""
        return len(self.events)

    def get_by_classification(self, classification: str) -> List[SecurityEvent]:
        """
        Get all events of a specific classification.
        
        Args:
            classification: One of "safe", "suspicious", "malicious"
            
        Returns:
            List of matching SecurityEvent objects
        """
        return [e for e in self.events if e.detection_result.classification == classification]

    def get_malicious_count(self) -> int:
        """Get count of malicious events."""
        return len(self.get_by_classification("malicious"))

    def get_suspicious_count(self) -> int:
        """Get count of suspicious events."""
        return len(self.get_by_classification("suspicious"))

    def get_safe_count(self) -> int:
        """Get count of safe events."""
        return len(self.get_by_classification("safe"))


# Global event store instance
_event_store = None


def get_event_store(max_events: int = 1000) -> EventStore:
    """
    Get or create the global event store.
    
    Args:
        max_events: Max events to keep (only used on first call)
        
    Returns:
        The global EventStore instance
    """
    global _event_store
    if _event_store is None:
        _event_store = EventStore(max_events=max_events)
    return _event_store
