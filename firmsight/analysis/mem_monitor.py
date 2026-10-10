"""
Dynamic Memory Leak and Heap Allocation Monitor
Tracks brk/mmap allocation footprints, resident memory growth, and flags memory exhaustion anomalies.
"""

from typing import Dict, Any, List

class MemoryLeakMonitor:
    """Monitors process memory allocation trajectories to identify memory leaks and anomalous heap expansion."""

    def __init__(self, baseline_mb: float = 16.0, growth_threshold_mb: float = 64.0):
        self.baseline_mb = baseline_mb
        self.growth_threshold_mb = growth_threshold_mb
        self.history: List[Dict[str, Any]] = []

    def record_sample(self, timestamp: float, heap_mb: float, mmap_mb: float, rss_mb: float) -> Dict[str, Any]:
        """Records a memory snapshot."""
        total_mb = round(heap_mb + mmap_mb, 2)
        growth_from_baseline = round(total_mb - self.baseline_mb, 2)
        is_anomalous = growth_from_baseline > self.growth_threshold_mb

        sample = {
            "timestamp": timestamp,
            "heap_mb": heap_mb,
            "mmap_mb": mmap_mb,
            "total_allocated_mb": total_mb,
            "rss_mb": rss_mb,
            "growth_mb": growth_from_baseline,
            "anomaly_detected": is_anomalous,
        }
        self.history.append(sample)
        return sample

    def get_summary(self) -> Dict[str, Any]:
        """Computes memory trajectory metrics."""
        if not self.history:
            return {"samples": 0, "max_mb": 0.0, "leak_risk": "LOW"}

        max_alloc = max(s["total_allocated_mb"] for s in self.history)
        anomalies = [s for s in self.history if s["anomaly_detected"]]

        if anomalies or (max_alloc - self.baseline_mb > self.growth_threshold_mb):
            risk = "CRITICAL"
        elif max_alloc - self.baseline_mb > self.growth_threshold_mb / 2:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        return {
            "samples": len(self.history),
            "baseline_mb": self.baseline_mb,
            "max_allocated_mb": max_alloc,
            "net_growth_mb": round(max_alloc - self.baseline_mb, 2),
            "anomaly_count": len(anomalies),
            "leak_risk": risk,
        }
