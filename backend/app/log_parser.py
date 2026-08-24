from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any


SUPPORTED_FORMATS = {"pfsense", "auth", "network", "custom"}
SEVERITIES = {"low", "medium", "high", "critical"}
IP_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
SYSLOG_TIMESTAMP = re.compile(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b")


class LogParseError(ValueError):
    """Raised when a log cannot be parsed into the normalized schema."""


def parse_log(log_format: str, raw_message: str) -> dict[str, Any]:
    log_format = log_format.lower().strip()
    if log_format not in SUPPORTED_FORMATS:
        raise LogParseError(
            f"Unsupported log format: {log_format}. "
            f"Supported formats: {', '.join(sorted(SUPPORTED_FORMATS))}"
        )

    if not raw_message or not raw_message.strip():
        raise LogParseError("raw_message cannot be empty")

    if log_format == "pfsense":
        result = _parse_pfsense(raw_message)
    elif log_format == "auth":
        result = _parse_auth(raw_message)
    elif log_format == "network":
        result = _parse_network(raw_message)
    else:
        result = _parse_custom(raw_message)

    result["raw_message"] = raw_message
    result["parsed_data"] = {
        "format": log_format,
        **result.get("parsed_data", {}),
    }

    # The normalized columns are always present, as required by the database schema.
    result.setdefault("source_ip", None)
    result.setdefault("destination_ip", None)
    result.setdefault("event_type", "connection")
    result.setdefault("severity", "low")
    result["severity"] = _normalize_severity(result["severity"])

    if result["timestamp"].tzinfo is None:
        result["timestamp"] = result["timestamp"].replace(tzinfo=timezone.utc)

    return result


def _parse_pfsense(raw_message: str) -> dict[str, Any]:
    lowered = raw_message.lower()
    source_ip, destination_ip = _first_two_ips(raw_message)
    parsed_data: dict[str, Any] = {"parser": "pfsense"}

    # pfSense filterlog is comma separated. The tracker/rule identifier
    # is normally the fourth field after `filterlog:`.
    if "filterlog:" in lowered:
        payload = raw_message[lowered.index("filterlog:") + len("filterlog:"):]
        fields = [item.strip() for item in payload.split(",")]
        if len(fields) > 3 and fields[3]:
            parsed_data["firewall_rule"] = fields[3]

    # In standard filterlog output, the first two numeric values after the
    # destination IP are source and destination ports.
    ip_matches = list(IP_PATTERN.finditer(raw_message))
    if len(ip_matches) >= 2:
        remainder = raw_message[ip_matches[1].end():].split(",")
        numeric_values = []
        for value in remainder:
            value = value.strip()
            if value.isdigit():
                numeric_values.append(int(value))
            if len(numeric_values) == 2:
                break
        if numeric_values:
            parsed_data["source_port"] = numeric_values[0]
        if len(numeric_values) > 1:
            parsed_data["destination_port"] = numeric_values[1]

    if any(word in lowered for word in ("block", "blocked", "deny", "denied", "reject")):
        event_type = "firewall_block"
        severity = "medium"
    else:
        event_type = "connection"
        severity = "low"

    return {
        "timestamp": _extract_timestamp(raw_message),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "event_type": event_type,
        "severity": severity,
        "parsed_data": parsed_data,
    }


def _parse_auth(raw_message: str) -> dict[str, Any]:
    lowered = raw_message.lower()
    source_ip = None

    source_match = re.search(
        r"\bfrom\s+(?P<ip>[^\s]+)",
        raw_message,
        flags=re.IGNORECASE,
    )
    if source_match:
        source_ip = _valid_ip_or_none(source_match.group("ip"))

    if source_ip is None:
        source_ip, _ = _first_two_ips(raw_message)

    if any(
        phrase in lowered
        for phrase in (
            "failed password",
            "authentication failure",
            "failed login",
            "invalid user",
        )
    ):
        event_type = "failed_login"
        severity = "medium"
    elif any(phrase in lowered for phrase in ("accepted password", "successful login")):
        event_type = "login"
        severity = "low"
    else:
        event_type = "login"
        severity = "low"

    return {
        "timestamp": _extract_timestamp(raw_message),
        "source_ip": source_ip,
        "destination_ip": None,
        "event_type": event_type,
        "severity": severity,
        "parsed_data": {"parser": "system_auth"},
    }


def _parse_network(raw_message: str) -> dict[str, Any]:
    decoded = _try_json(raw_message)
    if decoded is not None:
        return _parse_structured(decoded, parser="network")

    source_ip = _extract_key_value_ip(raw_message, ("src", "source", "source_ip"))
    destination_ip = _extract_key_value_ip(
        raw_message,
        ("dst", "destination", "destination_ip"),
    )
    if source_ip is None or destination_ip is None:
        first, second = _first_two_ips(raw_message)
        source_ip = source_ip or first
        destination_ip = destination_ip or second

    event_type = _extract_key_value(raw_message, ("event_type", "event", "type"))
    severity = _extract_key_value(raw_message, ("severity", "level"))

    return {
        "timestamp": _extract_timestamp(raw_message),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "event_type": event_type or "connection",
        "severity": severity or "low",
        "parsed_data": {"parser": "network"},
    }


def _parse_custom(raw_message: str) -> dict[str, Any]:
    decoded = _try_json(raw_message)
    if decoded is None or not isinstance(decoded, dict):
        raise LogParseError(
            "custom format must be a JSON object containing timestamp, event_type, and severity"
        )
    return _parse_structured(decoded, parser="custom")


def _parse_structured(data: dict[str, Any], parser: str) -> dict[str, Any]:
    timestamp_value = data.get("timestamp") or data.get("time")
    event_type = data.get("event_type") or data.get("event") or "connection"
    severity = data.get("severity") or data.get("level") or "low"

    timestamp = _parse_datetime(timestamp_value) if timestamp_value else datetime.now(timezone.utc)

    return {
        "timestamp": timestamp,
        "source_ip": _valid_ip_or_none(
            data.get("source_ip") or data.get("src") or data.get("source")
        ),
        "destination_ip": _valid_ip_or_none(
            data.get("destination_ip") or data.get("dst") or data.get("destination")
        ),
        "event_type": str(event_type),
        "severity": str(severity),
        "parsed_data": {
            "parser": parser,
            "fields": {key: value for key, value in data.items() if key != "raw_message"},
        },
    }


def _try_json(raw_message: str) -> Any | None:
    try:
        return json.loads(raw_message)
    except (json.JSONDecodeError, TypeError):
        return None


def _first_two_ips(value: str) -> tuple[str | None, str | None]:
    result: list[str] = []
    for candidate in IP_PATTERN.findall(value):
        valid = _valid_ip_or_none(candidate)
        if valid and valid not in result:
            result.append(valid)
        if len(result) == 2:
            break
    return (
        result[0] if len(result) > 0 else None,
        result[1] if len(result) > 1 else None,
    )


def _extract_key_value(value: str, keys: tuple[str, ...]) -> str | None:
    key_pattern = "|".join(re.escape(key) for key in keys)
    match = re.search(
        rf"(?:^|[\s,])(?:{key_pattern})\s*[:=]\s*([^\s,;]+)",
        value,
        flags=re.IGNORECASE,
    )
    return match.group(1) if match else None


def _extract_key_value_ip(value: str, keys: tuple[str, ...]) -> str | None:
    candidate = _extract_key_value(value, keys)
    return _valid_ip_or_none(candidate)


def _valid_ip_or_none(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return str(ip_address(str(value)))
    except ValueError:
        return None


def _extract_timestamp(raw_message: str) -> datetime:
    match = SYSLOG_TIMESTAMP.search(raw_message)
    if match:
        current_year = datetime.now(timezone.utc).year
        parsed = datetime.strptime(
            f"{current_year} {match.group(0)}",
            "%Y %b %d %H:%M:%S",
        )
        return parsed.replace(tzinfo=timezone.utc)

    # Network key/value logs may contain an ISO timestamp.
    iso_match = re.search(
        r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b",
        raw_message,
    )
    if iso_match:
        return _parse_datetime(iso_match.group(0))

    # Keep ingestion resilient for formats that do not carry a timestamp.
    return datetime.now(timezone.utc)


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        normalized = value.strip().replace("Z", "+00:00")
        try:
            result = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise LogParseError(f"Invalid timestamp: {value}") from exc
    else:
        raise LogParseError("timestamp must be an ISO datetime string")

    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result


def _normalize_severity(value: Any) -> str:
    normalized = str(value).strip().lower()
    aliases = {
        "info": "low",
        "informational": "low",
        "notice": "low",
        "warning": "medium",
        "warn": "medium",
        "error": "high",
        "emergency": "critical",
        "alert": "critical",
    }
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in SEVERITIES else "low"
