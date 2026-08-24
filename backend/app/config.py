from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def as_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def as_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def as_list_of_ints(name: str, default: str) -> set[int]:
    value = os.getenv(name, default)
    result: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if item:
            try:
                result.add(int(item))
            except ValueError:
                pass
    return result


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://postgres:postgres@localhost:5432/threat_intelligence",
    )
    failed_login_threshold: int = as_int("FAILED_LOGIN_THRESHOLD", 5)
    failed_login_window_seconds: int = as_int("FAILED_LOGIN_WINDOW_SECONDS", 60)
    port_scan_distinct_ports: int = as_int("PORT_SCAN_DISTINCT_PORTS", 10)
    port_scan_window_seconds: int = as_int("PORT_SCAN_WINDOW_SECONDS", 60)
    firewall_block_threshold: int = as_int("FIREWALL_BLOCK_THRESHOLD", 5)
    firewall_block_window_seconds: int = as_int("FIREWALL_BLOCK_WINDOW_SECONDS", 60)
    anomaly_stddev_threshold: float = as_float("ANOMALY_STDDEV_THRESHOLD", 3.0)
    anomaly_min_samples: int = as_int("ANOMALY_MIN_SAMPLES", 10)
    anomaly_window_seconds: int = as_int("ANOMALY_WINDOW_SECONDS", 60)
    unusual_port_weight: int = as_int("UNUSUAL_PORT_WEIGHT", 20)
    allowed_destination_ports: set[int] = None  # type: ignore[assignment]
    ipinfo_token: str = os.getenv("IPINFO_TOKEN", "")
    cors_origins: str = os.getenv("CORS_ORIGINS", "http://localhost:5173")

    def __post_init__(self) -> None:
        if self.allowed_destination_ports is None:
            object.__setattr__(
                self,
                "allowed_destination_ports",
                as_list_of_ints(
                    "ALLOWED_DESTINATION_PORTS",
                    "22,25,53,80,110,123,143,443,587,993,995",
                ),
            )


settings = Settings()
