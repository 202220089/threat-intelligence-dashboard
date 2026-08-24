from app.scoring import calculate_score, severity_for_score


def test_score_is_capped():
    assert calculate_score([
        "blacklisted_ip",
        "multiple_failed_logins",
        "port_scanning",
        "firewall_block",
    ]) == 100


def test_severity_ranges():
    assert severity_for_score(30) == "low"
    assert severity_for_score(31) == "medium"
    assert severity_for_score(61) == "high"
    assert severity_for_score(81) == "critical"
