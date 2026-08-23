"""
Model-Compatible Behavioral Telemetry Collector for TRINETRA Watchdog.

Aggregates simulated hardware-level behavioral telemetry (ATA/Memory operations)
emitted by the test harness/simulator to construct the 27-feature vector 
required by the RiskAnalyser ML model.
"""

import math
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import List


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


@dataclass
class BehavioralTelemetryEvent:
    """Represents a discrete hardware-level I/O or Memory operation."""
    timestamp: float
    op_type: str  # e.g., 'ata_write', 'ata_read', 'mem_write', 'mem_exec'
    bytes_count: int
    ops_count: int
    entropies: List[float]
    addresses: List[int]


class HardwareTelemetryCollector:
    """
    Collects and aggregates behavioral telemetry events into a 27-feature vector.
    Maintains a sliding time window of events.
    """

    def __init__(self, max_history_seconds: float = 60.0):
        self.max_history_seconds = max_history_seconds
        self.events: deque[BehavioralTelemetryEvent] = deque()

    def add_event(self, event: BehavioralTelemetryEvent) -> None:
        """Register a new behavioral telemetry event."""
        self.events.append(event)
        self._prune_history()

    def _prune_history(self) -> None:
        """Remove events older than max_history_seconds."""
        now = time.time()
        while self.events and (now - self.events[0].timestamp) > self.max_history_seconds:
            self.events.popleft()

    def get_feature_vector(self, window_duration: float = 10.0) -> List[float]:
        """
        Compute the 27-feature vector over the given window duration (in seconds).
        Returns the features exactly in the order expected by the ML model.
        """
        now = time.time()
        window_start = now - window_duration
        
        # Filter events in the window
        recent_events = [e for e in self.events if e.timestamp >= window_start]
        
        if not recent_events:
            # Return a vector of 27 zeros if no activity
            return [0.0] * 27

        # Aggregate counts
        ata_read_ops = ata_write_ops = 0
        ata_read_bytes = ata_write_bytes = 0
        mem_read_ops = mem_write_ops = mem_readwrite_ops = mem_exec_ops = 0
        
        ata_write_entropies = []
        mem_write_entropies = []
        mem_readwrite_entropies = []
        unique_addresses = set()
        
        for e in recent_events:
            unique_addresses.update(e.addresses)
            
            if e.op_type == "ata_read":
                ata_read_ops += e.ops_count
                ata_read_bytes += e.bytes_count
            elif e.op_type == "ata_write":
                ata_write_ops += e.ops_count
                ata_write_bytes += e.bytes_count
                ata_write_entropies.extend(e.entropies)
            elif e.op_type == "mem_read":
                mem_read_ops += e.ops_count
            elif e.op_type == "mem_write":
                mem_write_ops += e.ops_count
                mem_write_entropies.extend(e.entropies)
            elif e.op_type == "mem_readwrite":
                mem_readwrite_ops += e.ops_count
                mem_readwrite_entropies.extend(e.entropies)
            elif e.op_type == "mem_exec":
                mem_exec_ops += e.ops_count
                
        total_ops = (ata_read_ops + ata_write_ops + mem_read_ops + mem_write_ops + 
                     mem_readwrite_ops + mem_exec_ops)
        total_bytes = ata_read_bytes + ata_write_bytes
        
        # Ensure duration is at least 1 second to avoid division by zero
        effective_duration = max(1.0, window_duration)

        def get_entropy_stats(entropies: List[float]) -> tuple[float, float, float]:
            if not entropies:
                return 0.0, 0.0, 0.0
            mean_val = sum(entropies) / len(entropies)
            max_val = max(entropies)
            if len(entropies) > 1:
                variance = sum((x - mean_val) ** 2 for x in entropies) / (len(entropies) - 1)
                std_val = math.sqrt(variance)
            else:
                std_val = 0.0
            return mean_val, std_val, max_val

        aw_mean, aw_std, aw_max = get_entropy_stats(ata_write_entropies)
        mw_mean, mw_std, mw_max = get_entropy_stats(mem_write_entropies)
        mrw_mean, mrw_std, mrw_max = get_entropy_stats(mem_readwrite_entropies)

        # Build exactly 27 features
        features = [
            float(total_ops),                                    # 1. total_operations
            float(total_bytes),                                  # 2. total_bytes
            float(total_ops) / effective_duration,               # 3. total_operation_velocity
            float(len(unique_addresses)),                        # 4. total_unique_addresses
            float(ata_read_ops),                                 # 5. ata_read_operations
            float(ata_write_ops),                                # 6. ata_write_operations
            float(ata_read_bytes),                               # 7. ata_read_bytes
            float(ata_write_bytes),                              # 8. ata_write_bytes
            float(ata_read_ops) / effective_duration,            # 9. ata_read_velocity
            float(ata_write_ops) / effective_duration,           # 10. ata_write_velocity
            float(mem_read_ops),                                 # 11. mem_read_operations
            float(mem_write_ops),                                # 12. mem_write_operations
            float(mem_readwrite_ops),                            # 13. mem_readwrite_operations
            float(mem_exec_ops),                                 # 14. mem_exec_operations
            float(mem_read_ops) / effective_duration,            # 15. mem_read_velocity
            float(mem_write_ops) / effective_duration,           # 16. mem_write_velocity
            float(mem_readwrite_ops) / effective_duration,       # 17. mem_readwrite_velocity
            float(mem_exec_ops) / effective_duration,            # 18. mem_exec_velocity
            aw_mean,                                             # 19. ata_write_entropy_mean
            aw_std,                                              # 20. ata_write_entropy_std
            aw_max,                                              # 21. ata_write_entropy_max
            mw_mean,                                             # 22. mem_write_entropy_mean
            mw_std,                                              # 23. mem_write_entropy_std
            mw_max,                                              # 24. mem_write_entropy_max
            mrw_mean,                                            # 25. mem_readwrite_entropy_mean
            mrw_std,                                             # 26. mem_readwrite_entropy_std
            mrw_max                                              # 27. mem_readwrite_entropy_max
        ]
        
        return features

# Global instance for the simulator and Watchdog to share in the same process
global_telemetry_collector = HardwareTelemetryCollector()
