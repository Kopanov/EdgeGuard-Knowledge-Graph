#!/usr/bin/env python3
"""
EdgeGuard - Metrics Tracking Module

Provides PipelineMetrics class to track pipeline execution metrics:
- Total runs
- Success/failure counts
- Nodes created per run
- Relationships created per run
- Duration per run

Metrics are persisted to JSON file for durability across restarts.
"""

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Configure logging
logger = logging.getLogger(__name__)

# Default metrics file location
DEFAULT_METRICS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "metrics.json")


@dataclass
class RunRecord:
    """Record of a single pipeline run."""

    timestamp: str
    success: bool
    duration_seconds: float
    nodes_created: int
    relationships_created: int
    events_processed: int
    indicators_synced: int
    vulnerabilities_synced: int
    malware_synced: int
    actors_synced: int
    techniques_synced: int
    error_message: Optional[str] = None


class PipelineMetrics:
    """
    Tracks pipeline execution metrics with JSON persistence.

    Usage:
        metrics = PipelineMetrics()  # Loads from file automatically

        # Record a run
        metrics.start_run()
        # ... run pipeline ...
        metrics.end_run(success=True, nodes_created=100, relationships_created=50)

        # Get stats
        stats = metrics.get_summary()
    """

    def __init__(self, metrics_file: str = None):
        """
        Initialize metrics tracker.

        Args:
            metrics_file: Path to JSON file for persistence (default: data/metrics.json)
        """
        self.metrics_file = metrics_file or DEFAULT_METRICS_FILE
        self._ensure_data_dir()

        # Metrics data
        self.total_runs: int = 0
        self.success_count: int = 0
        self.failure_count: int = 0
        self.last_run: Optional[str] = None
        self.last_success: Optional[str] = None
        self.last_failure: Optional[str] = None
        self.runs: List[Dict[str, Any]] = []

        # Current run tracking
        self._current_run_start: Optional[datetime] = None
        self._current_run_data: Dict[str, Any] = {}

        # Load existing metrics
        self.load()

    def _ensure_data_dir(self):
        """Ensure the data directory exists."""
        data_dir = os.path.dirname(self.metrics_file)
        if data_dir and not os.path.exists(data_dir):
            try:
                os.makedirs(data_dir, exist_ok=True)
                logger.debug(f"Created data directory: {data_dir}")
            except Exception as e:
                logger.warning(f"Could not create data directory: {e}")

    def load(self) -> bool:
        """
        Load metrics from JSON file.

        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            if os.path.exists(self.metrics_file):
                with open(self.metrics_file, "r") as f:
                    data = json.load(f)

                self.total_runs = data.get("total_runs", 0)
                self.success_count = data.get("success_count", 0)
                self.failure_count = data.get("failure_count", 0)
                self.last_run = data.get("last_run")
                self.last_success = data.get("last_success")
                self.last_failure = data.get("last_failure")
                self.runs = data.get("runs", [])

                logger.debug(f"Loaded metrics from {self.metrics_file}: {self.total_runs} runs")
                return True
            else:
                logger.debug(f"No existing metrics file at {self.metrics_file}")
                return False

        except Exception as e:
            logger.warning(f"Failed to load metrics: {e}")
            return False

    def save(self) -> bool:
        """
        Save metrics to JSON file.

        Returns:
            True if saved successfully, False otherwise
        """
        try:
            data = {
                "total_runs": self.total_runs,
                "success_count": self.success_count,
                "failure_count": self.failure_count,
                "last_run": self.last_run,
                "last_success": self.last_success,
                "last_failure": self.last_failure,
                "runs": self.runs,
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }

            # Write to temp file first for atomicity
            temp_file = self.metrics_file + ".tmp"
            with open(temp_file, "w") as f:
                json.dump(data, f, indent=2)

            # Rename for atomic replace
            os.replace(temp_file, self.metrics_file)

            logger.debug(f"Saved metrics to {self.metrics_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to save metrics: {e}")
            return False

    def start_run(self) -> None:
        """Mark the start of a new pipeline run."""
        self._current_run_start = datetime.now(timezone.utc)
        self._current_run_data = {
            "timestamp": self._current_run_start.isoformat(),
            "success": False,
            "duration_seconds": 0.0,
            "nodes_created": 0,
            "relationships_created": 0,
            "events_processed": 0,
            "indicators_synced": 0,
            "vulnerabilities_synced": 0,
            "malware_synced": 0,
            "actors_synced": 0,
            "techniques_synced": 0,
            "error_message": None,
        }
        logger.info("Metrics: Started tracking new pipeline run")

    def end_run(
        self,
        success: bool,
        nodes_created: int = 0,
        relationships_created: int = 0,
        events_processed: int = 0,
        indicators_synced: int = 0,
        vulnerabilities_synced: int = 0,
        malware_synced: int = 0,
        actors_synced: int = 0,
        techniques_synced: int = 0,
        error_message: str = None,
    ) -> None:
        """
        Mark the end of a pipeline run and record metrics.

        Args:
            success: Whether the run was successful
            nodes_created: Number of nodes created in this run
            relationships_created: Number of relationships created
            events_processed: Number of events processed
            indicators_synced: Number of indicators synced
            vulnerabilities_synced: Number of vulnerabilities synced
            malware_synced: Number of malware entries synced
            actors_synced: Number of threat actors synced
            techniques_synced: Number of techniques synced
            error_message: Error message if run failed
        """
        if self._current_run_start is None:
            logger.warning("Metrics: end_run called without start_run")
            self.start_run()

        # Calculate duration
        end_time = datetime.now(timezone.utc)
        duration = (end_time - self._current_run_start).total_seconds()

        # Update current run data
        self._current_run_data.update(
            {
                "success": success,
                "duration_seconds": round(duration, 2),
                "nodes_created": nodes_created,
                "relationships_created": relationships_created,
                "events_processed": events_processed,
                "indicators_synced": indicators_synced,
                "vulnerabilities_synced": vulnerabilities_synced,
                "malware_synced": malware_synced,
                "actors_synced": actors_synced,
                "techniques_synced": techniques_synced,
                "error_message": error_message,
            }
        )

        # Update totals
        self.total_runs += 1
        self.last_run = self._current_run_data["timestamp"]

        if success:
            self.success_count += 1
            self.last_success = self.last_run
        else:
            self.failure_count += 1
            self.last_failure = self.last_run

        # Add to runs history (keep last 100)
        self.runs.append(self._current_run_data)
        if len(self.runs) > 100:
            self.runs = self.runs[-100:]

        # Save to file
        self.save()

        logger.info(
            f"Metrics: Recorded pipeline run - success={success}, duration={duration:.2f}s, "
            f"nodes={nodes_created}, relationships={relationships_created}"
        )

        # Reset current run
        self._current_run_start = None
        self._current_run_data = {}

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all metrics.

        Returns:
            Dict with summary statistics
        """
        # Calculate averages from recent runs
        if self.runs:
            recent_runs = self.runs[-10:]  # Last 10 runs
            avg_duration = sum(r.get("duration_seconds", 0) for r in recent_runs) / len(recent_runs)
            avg_nodes = sum(r.get("nodes_created", 0) for r in recent_runs) / len(recent_runs)
            avg_relationships = sum(r.get("relationships_created", 0) for r in recent_runs) / len(recent_runs)
        else:
            avg_duration = 0.0
            avg_nodes = 0.0
            avg_relationships = 0.0

        # Calculate success rate
        success_rate = (self.success_count / self.total_runs * 100) if self.total_runs > 0 else 0.0

        return {
            "total_runs": self.total_runs,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate_percent": round(success_rate, 2),
            "last_run": self.last_run,
            "last_success": self.last_success,
            "last_failure": self.last_failure,
            "average_duration_seconds": round(avg_duration, 2),
            "average_nodes_created": round(avg_nodes, 2),
            "average_relationships_created": round(avg_relationships, 2),
            "total_nodes_created": sum(r.get("nodes_created", 0) for r in self.runs),
            "total_relationships_created": sum(r.get("relationships_created", 0) for r in self.runs),
        }

    def get_recent_runs(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent run records.

        Args:
            limit: Maximum number of runs to return

        Returns:
            List of run records (most recent first)
        """
        return list(reversed(self.runs[-limit:]))

    def reset(self) -> None:
        """Reset all metrics (use with caution!)."""
        self.total_runs = 0
        self.success_count = 0
        self.failure_count = 0
        self.last_run = None
        self.last_success = None
        self.last_failure = None
        self.runs = []
        self._current_run_start = None
        self._current_run_data = {}
        self.save()
        logger.warning("Metrics: All metrics have been reset")


def get_metrics(metrics_file: str = None) -> PipelineMetrics:
    """
    Get a PipelineMetrics instance (factory function).

    Args:
        metrics_file: Optional path to metrics file

    Returns:
        PipelineMetrics instance
    """
    return PipelineMetrics(metrics_file=metrics_file)


def main():
    """CLI entry point for metrics display."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    metrics = PipelineMetrics()
    summary = metrics.get_summary()

    print("=" * 50)
    print("EdgeGuard Pipeline Metrics")
    print("=" * 50)
    print()
    print(f"Total Runs: {summary['total_runs']}")
    print(f"Successes: {summary['success_count']}")
    print(f"Failures: {summary['failure_count']}")
    print(f"Success Rate: {summary['success_rate_percent']}%")
    print()
    print(f"Last Run: {summary['last_run'] or 'Never'}")
    print(f"Last Success: {summary['last_success'] or 'Never'}")
    print(f"Last Failure: {summary['last_failure'] or 'Never'}")
    print()
    print(f"Average Duration: {summary['average_duration_seconds']}s")
    print(f"Average Nodes Created: {summary['average_nodes_created']}")
    print(f"Average Relationships Created: {summary['average_relationships_created']}")
    print()
    print(f"Total Nodes Created (all time): {summary['total_nodes_created']}")
    print(f"Total Relationships Created (all time): {summary['total_relationships_created']}")
    print("=" * 50)

    # Show recent runs
    recent = metrics.get_recent_runs(5)
    if recent:
        print()
        print("Recent Runs:")
        for run in recent:
            status = "✅" if run.get("success") else "❌"
            print(
                f"  {status} {run.get('timestamp', 'Unknown')} - "
                f"{run.get('duration_seconds', 0)}s - "
                f"nodes: {run.get('nodes_created', 0)}, "
                f"rels: {run.get('relationships_created', 0)}"
            )

    print("=" * 50)


if __name__ == "__main__":
    main()
