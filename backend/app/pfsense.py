from .log_parser import parse_log


def parse_pfsense(raw_message: str) -> dict:
    return parse_log("pfsense", raw_message)
