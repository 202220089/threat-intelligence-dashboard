from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from statistics import mean, pstdev


def detect_anomaly(
    timestamps: list[datetime],
    now: datetime,
    window_seconds: int,
    minimum_samples: int,
    standard_deviation_limit: float,
) -> dict | None:
    """Detect a connection-frequency spike using rolling windows."""
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    if len(timestamps) < minimum_samples + 1:
        return None

    window = timedelta(seconds=window_seconds)
    current_start = now - window

    # Count events in the current window and in previous windows.
    current_count = sum(current_start <= value <= now for value in timestamps)
    baseline_counts: list[int] = []

    for offset in range(1, minimum_samples + 1):
        end = current_start - (offset - 1) * window
        start = current_start - offset * window
        baseline_counts.append(sum(start <= value < end for value in timestamps))

    if len(baseline_counts) < minimum_samples or not any(baseline_counts):
        return None

    average = mean(baseline_counts)
    deviation = pstdev(baseline_counts)

    # With no historical variation, a positive spike above the baseline is enough.
    if deviation == 0:
        anomalous = current_count > average and current_count > 0
    else:
        anomalous = current_count > average + standard_deviation_limit * deviation

    if not anomalous:
        return None

    return {
        "current_count": current_count,
        "baseline_counts": baseline_counts,
        "rolling_mean": round(average, 3),
        "standard_deviation": round(deviation, 3),
        "threshold": round(average + standard_deviation_limit * deviation, 3),
    }
