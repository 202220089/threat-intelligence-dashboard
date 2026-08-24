from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, insert, select

from .anomaly_detector import detect_anomaly
from .config import settings
from .db import engine
from .scoring import RULE_WEIGHTS, calculate_score, severity_for_score
from .tables import ip_blacklist, logs, threat_alerts


class ThreatDetector:
    def __init__(self, broadcaster):
        self.broadcaster = broadcaster

    async def evaluate(self, log_id: int, parsed: dict[str, Any]) -> list[dict]:
        source_ip = parsed.get("source_ip")
        if not source_ip:
            return []

        now = parsed.get("timestamp") or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        matches: list[str] = []
        reasons: dict[str, str] = {}

        with engine.connect() as connection:
            blacklisted = connection.execute(
                select(ip_blacklist.c.id).where(
                    and_(
                        ip_blacklist.c.ip_address == source_ip,
                        ip_blacklist.c.is_active.is_(True),
                    )
                )
            ).first()

            recent_start = now - timedelta(
                seconds=max(
                    settings.failed_login_window_seconds,
                    settings.port_scan_window_seconds,
                    settings.firewall_block_window_seconds,
                    settings.anomaly_window_seconds
                    * (settings.anomaly_min_samples + 1),
                )
            )

            recent_rows = connection.execute(
                select(logs).where(
                    and_(
                        logs.c.source_ip == source_ip,
                        logs.c.timestamp >= recent_start,
                        logs.c.timestamp <= now,
                    )
                )
            ).mappings().all()

        if blacklisted:
            matches.append("blacklisted_ip")
            reasons["blacklisted_ip"] = f"Source IP {source_ip} is in the active blacklist."

        failed_start = now - timedelta(seconds=settings.failed_login_window_seconds)
        failed_count = sum(
            row["event_type"] == "failed_login"
            and failed_start <= row["timestamp"] <= now
            for row in recent_rows
        )

        if failed_count >= settings.failed_login_threshold:
            matches.append("multiple_failed_logins")
            reasons["multiple_failed_logins"] = (
                f"Source IP {source_ip} generated {failed_count} failed login attempts "
                f"within {settings.failed_login_window_seconds} seconds."
            )

        port_start = now - timedelta(seconds=settings.port_scan_window_seconds)
        destination_ports = {
            row["parsed_data"].get("destination_port")
            for row in recent_rows
            if port_start <= row["timestamp"] <= now
            and isinstance(row["parsed_data"], dict)
            and row["parsed_data"].get("destination_port") is not None
        }
        destination_ports.discard(None)

        if len(destination_ports) >= settings.port_scan_distinct_ports:
            matches.append("port_scanning")
            reasons["port_scanning"] = (
                f"Source IP {source_ip} contacted {len(destination_ports)} distinct "
                f"destination ports within {settings.port_scan_window_seconds} seconds."
            )

        firewall_start = now - timedelta(seconds=settings.firewall_block_window_seconds)
        firewall_blocks = sum(
            row["event_type"] == "firewall_block"
            and firewall_start <= row["timestamp"] <= now
            for row in recent_rows
        )

        if firewall_blocks >= settings.firewall_block_threshold:
            matches.append("firewall_block")
            reasons["firewall_block"] = (
                f"Source IP {source_ip} caused {firewall_blocks} firewall blocks "
                f"within {settings.firewall_block_window_seconds} seconds."
            )

        destination_port = None
        if isinstance(parsed.get("parsed_data"), dict):
            destination_port = parsed["parsed_data"].get("destination_port")

        if (
            parsed.get("event_type") == "connection"
            and isinstance(destination_port, int)
            and destination_port not in settings.allowed_destination_ports
        ):
            matches.append("unusual_port_access")
            reasons["unusual_port_access"] = (
                f"Destination port {destination_port} is not in the configured allowlist."
            )

        connection_timestamps = [
            row["timestamp"]
            for row in recent_rows
            if row["event_type"] == "connection"
        ]
        anomaly = detect_anomaly(
            connection_timestamps,
            now,
            settings.anomaly_window_seconds,
            settings.anomaly_min_samples,
            settings.anomaly_stddev_threshold,
        )

        if anomaly:
            matches.append("unusual_traffic_pattern")
            reasons["unusual_traffic_pattern"] = (
                f"Current connection count {anomaly['current_count']} exceeded the "
                f"anomaly threshold {anomaly['threshold']}."
            )

        if not matches:
            return []

        overall_score = calculate_score(matches)
        alerts: list[dict] = []

        for threat_type in matches:
            if await self._is_duplicate(source_ip, threat_type, now):
                continue

            # Store the combined score so the severity filters and dashboard
            # represent the complete event, not only one matched rule.
            score = overall_score
            description = (
                f"{reasons[threat_type]} Overall score for this event: {overall_score}."
            )

            with engine.begin() as connection:
                result = connection.execute(
                    insert(threat_alerts)
                    .values(
                        log_id=log_id,
                        threat_type=threat_type,
                        threat_score=score,
                        description=description,
                        is_resolved=False,
                    )
                )
                alert_id = result.inserted_primary_key[0]
                row = connection.execute(
                    select(threat_alerts).where(threat_alerts.c.id == alert_id)
                ).mappings().one()

            alert = dict(row)
            alert["severity"] = severity_for_score(overall_score)
            alert["overall_score"] = overall_score
            alerts.append(alert)
            await self.broadcaster("threat_alert", alert)

        return alerts

    async def _is_duplicate(
        self,
        source_ip: str,
        threat_type: str,
        now: datetime,
    ) -> bool:
        start = now - timedelta(seconds=60)

        statement = (
            select(func.count(threat_alerts.c.id))
            .select_from(
                threat_alerts.join(logs, threat_alerts.c.log_id == logs.c.id)
            )
            .where(
                and_(
                    logs.c.source_ip == source_ip,
                    threat_alerts.c.threat_type == threat_type,
                    threat_alerts.c.created_at >= start,
                )
            )
        )

        with engine.connect() as connection:
            count = connection.execute(statement).scalar_one()

        return count > 0
