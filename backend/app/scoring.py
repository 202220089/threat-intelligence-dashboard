RULE_WEIGHTS = {
    "blacklisted_ip": 50,
    "multiple_failed_logins": 30,
    "port_scanning": 40,
    "firewall_block": 20,
    "unusual_port_access": 20,
    "unusual_traffic_pattern": 20,
}


def calculate_score(matches: list[str]) -> int:
    return min(sum(RULE_WEIGHTS.get(rule, 0) for rule in matches), 100)


def severity_for_score(score: int) -> str:
    if score <= 30:
        return "low"
    if score <= 60:
        return "medium"
    if score <= 80:
        return "high"
    return "critical"
