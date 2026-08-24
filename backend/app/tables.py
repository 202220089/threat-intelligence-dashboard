from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    MetaData,
    String,
    Table,
    Text,
    func,
    text,
)


metadata = MetaData()

logs = Table(
    "logs",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True), nullable=False),
    Column("source_ip", String(45), nullable=True),
    Column("destination_ip", String(45), nullable=True),
    Column("event_type", String(100), nullable=False),
    Column("severity", String(20), nullable=False),
    Column("raw_message", Text, nullable=False),
    Column("parsed_data", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)

threat_alerts = Table(
    "threat_alerts",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("log_id", Integer, ForeignKey("logs.id"), nullable=False),
    Column("threat_type", String(100), nullable=False),
    Column("threat_score", Integer, nullable=False),
    Column("description", Text, nullable=False),
    Column("is_resolved", Boolean, nullable=False, server_default=text("false")),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)

ip_blacklist = Table(
    "ip_blacklist",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("ip_address", String(45), nullable=False, unique=True),
    Column("reason", Text, nullable=False),
    Column("source", String(100), nullable=False),
    Column("is_active", Boolean, nullable=False, server_default=text("true")),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)

Index("ix_logs_timestamp", logs.c.timestamp)
Index("ix_logs_source_ip", logs.c.source_ip)
Index("ix_logs_destination_ip", logs.c.destination_ip)
Index("ix_logs_event_type", logs.c.event_type)
Index("ix_logs_severity", logs.c.severity)
Index("ix_logs_source_event_time", logs.c.source_ip, logs.c.event_type, logs.c.timestamp)
Index("ix_threat_alerts_log_id", threat_alerts.c.log_id)
Index("ix_threat_alerts_created_at", threat_alerts.c.created_at)
Index("ix_threat_alerts_resolved", threat_alerts.c.is_resolved)
Index("ix_ip_blacklist_address", ip_blacklist.c.ip_address)
