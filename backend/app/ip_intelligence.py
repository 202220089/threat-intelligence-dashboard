from __future__ import annotations

import json
from ipaddress import ip_address
from urllib.error import URLError
from urllib.request import Request, urlopen

from sqlalchemy import and_, func, select

from .config import settings
from .db import engine
from .tables import ip_blacklist, logs, threat_alerts


def validate_ip(value: str) -> str:
    try:
        return str(ip_address(value))
    except ValueError as exc:
        raise ValueError("Invalid IP address") from exc


def add_to_blacklist(ip_value: str, reason: str, source: str) -> dict:
    address = validate_ip(ip_value)

    with engine.begin() as connection:
        existing = connection.execute(
            select(ip_blacklist).where(ip_blacklist.c.ip_address == address)
        ).mappings().first()

        if existing:
            connection.execute(
                ip_blacklist.update()
                .where(ip_blacklist.c.id == existing["id"])
                .values(reason=reason, source=source, is_active=True)
            )
            row = connection.execute(
                select(ip_blacklist).where(ip_blacklist.c.id == existing["id"])
            ).mappings().one()
        else:
            result = connection.execute(
                ip_blacklist.insert().values(
                    ip_address=address,
                    reason=reason,
                    source=source,
                    is_active=True,
                )
            )
            row = connection.execute(
                select(ip_blacklist).where(
                    ip_blacklist.c.id == result.inserted_primary_key[0]
                )
            ).mappings().one()

    return dict(row)


def ip_info(ip_value: str) -> dict:
    address = validate_ip(ip_value)

    with engine.connect() as connection:
        log_count = connection.execute(
            select(func.count(logs.c.id)).where(logs.c.source_ip == address)
        ).scalar_one()

        threat_count = connection.execute(
            select(func.count(threat_alerts.c.id))
            .select_from(threat_alerts.join(logs, threat_alerts.c.log_id == logs.c.id))
            .where(logs.c.source_ip == address)
        ).scalar_one()

        highest_score = connection.execute(
            select(func.max(threat_alerts.c.threat_score))
            .select_from(threat_alerts.join(logs, threat_alerts.c.log_id == logs.c.id))
            .where(logs.c.source_ip == address)
        ).scalar_one()

        blacklist_row = connection.execute(
            select(ip_blacklist).where(ip_blacklist.c.ip_address == address)
        ).mappings().first()

        last_seen = connection.execute(
            select(func.max(logs.c.timestamp)).where(logs.c.source_ip == address)
        ).scalar_one()

    result = {
        "ip_address": address,
        "is_blacklisted": bool(blacklist_row and blacklist_row["is_active"]),
        "blacklist": dict(blacklist_row) if blacklist_row else None,
        "observed_log_count": int(log_count or 0),
        "threat_count": int(threat_count or 0),
        "highest_threat_score": int(highest_score) if highest_score is not None else None,
        "last_seen": last_seen,
        "external_intelligence": None,
    }

    if settings.ipinfo_token:
        result["external_intelligence"] = fetch_ipinfo(address)

    return result


def fetch_ipinfo(address: str) -> dict | None:
    request = Request(
        f"https://ipinfo.io/{address}/json",
        headers={"Authorization": f"Bearer {settings.ipinfo_token}"},
    )

    try:
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except (URLError, TimeoutError, json.JSONDecodeError):
        return None
