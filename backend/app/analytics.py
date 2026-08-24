from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, select

from .db import engine
from .tables import logs, threat_alerts


def _severity_expression(severity: str):
    if severity == "low":
        return threat_alerts.c.threat_score <= 30
    if severity == "medium":
        return and_(threat_alerts.c.threat_score >= 31, threat_alerts.c.threat_score <= 60)
    if severity == "high":
        return and_(threat_alerts.c.threat_score >= 61, threat_alerts.c.threat_score <= 80)
    if severity == "critical":
        return threat_alerts.c.threat_score >= 81
    raise ValueError("severity must be low, medium, high, or critical")


def recent_threats(
    severity: str | None,
    from_date: datetime | None,
    to_date: datetime | None,
) -> list[dict]:
    statement = (
        select(
            threat_alerts.c.id,
            threat_alerts.c.log_id,
            threat_alerts.c.threat_type,
            threat_alerts.c.threat_score,
            threat_alerts.c.description,
            threat_alerts.c.is_resolved,
            threat_alerts.c.created_at,
            logs.c.source_ip,
            logs.c.destination_ip,
            logs.c.event_type,
        )
        .select_from(threat_alerts.join(logs, threat_alerts.c.log_id == logs.c.id))
        .order_by(threat_alerts.c.created_at.desc())
    )

    conditions = []
    if severity:
        conditions.append(_severity_expression(severity))
    if from_date:
        conditions.append(threat_alerts.c.created_at >= from_date)
    if to_date:
        conditions.append(threat_alerts.c.created_at <= to_date)
    if conditions:
        statement = statement.where(and_(*conditions))

    with engine.connect() as connection:
        rows = connection.execute(statement).mappings().all()
    return [dict(row) for row in rows]


def threat_stats() -> dict:
    by_severity = Counter()
    by_type = Counter()

    with engine.connect() as connection:
        rows = connection.execute(select(threat_alerts)).mappings().all()

    for row in rows:
        score = int(row["threat_score"])
        severity = (
            "low" if score <= 30 else
            "medium" if score <= 60 else
            "high" if score <= 80 else
            "critical"
        )
        by_severity[severity] += 1
        by_type[row["threat_type"]] += 1

    return {
        "total": sum(by_type.values()),
        "by_severity": dict(by_severity),
        "by_type": dict(by_type),
    }


def parse_range(value: str) -> int:
    value = value.strip().lower()
    if len(value) < 2 or not value[:-1].isdigit():
        raise ValueError("range must look like 24h, 7d, or 30d")
    amount = int(value[:-1])
    unit = value[-1]
    if unit not in {"h", "d"}:
        raise ValueError("range must end with h or d")
    return amount * (3600 if unit == "h" else 86400)


def _bucket(value: datetime, size: int) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    epoch = int(value.timestamp())
    return datetime.fromtimestamp(epoch - epoch % size, tz=timezone.utc)


def timeline(interval: str, range_value: str) -> list[dict]:
    seconds = parse_range(range_value)
    now = datetime.now(timezone.utc)
    start = now - timedelta(seconds=seconds)
    size = {"minute": 60, "hour": 3600, "day": 86400}.get(interval)
    if size is None:
        raise ValueError("interval must be minute, hour, or day")

    with engine.connect() as connection:
        event_rows = connection.execute(
            select(logs.c.timestamp).where(logs.c.timestamp >= start)
        ).all()
        threat_rows = connection.execute(
            select(threat_alerts.c.created_at).where(threat_alerts.c.created_at >= start)
        ).all()

    event_counts = Counter(_bucket(row[0], size) for row in event_rows)
    threat_counts = Counter(_bucket(row[0], size) for row in threat_rows)
    buckets = sorted(set(event_counts) | set(threat_counts))

    return [
        {
            "timestamp": bucket.isoformat(),
            "event_count": event_counts[bucket],
            "threat_count": threat_counts[bucket],
        }
        for bucket in buckets
    ]


def top_sources(limit: int) -> list[dict]:
    with engine.connect() as connection:
        rows = connection.execute(
            select(logs.c.source_ip, threat_alerts.c.threat_score)
            .select_from(threat_alerts.join(logs, threat_alerts.c.log_id == logs.c.id))
            .where(logs.c.source_ip.is_not(None))
        ).all()

    counts = Counter()
    highest = defaultdict(int)
    for source_ip, score in rows:
        counts[source_ip] += 1
        highest[source_ip] = max(highest[source_ip], int(score))

    return [
        {
            "source_ip": address,
            "threat_count": count,
            "highest_score": highest[address],
        }
        for address, count in counts.most_common(limit)
    ]
