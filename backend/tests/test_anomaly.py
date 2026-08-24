from datetime import datetime, timedelta, timezone

from app.anomaly_detector import detect_anomaly


def test_no_anomaly_without_enough_history():
    now = datetime.now(timezone.utc)
    timestamps = [now - timedelta(seconds=10)]
    assert detect_anomaly(timestamps, now, 60, 10, 3) is None
