from app.log_parser import parse_log


def test_auth_failed_login():
    result = parse_log(
        "auth",
        "Aug 23 10:15:30 sshd: Failed password for admin from 203.0.113.10 port 5522 ssh2",
    )
    assert result["source_ip"] == "203.0.113.10"
    assert result["event_type"] == "failed_login"


def test_custom_json():
    result = parse_log(
        "custom",
        '{"timestamp":"2026-08-23T10:00:00Z","source_ip":"192.0.2.1","event_type":"connection","severity":"low"}',
    )
    assert result["source_ip"] == "192.0.2.1"
    assert result["event_type"] == "connection"
