"""Create the required Day One tables.

Revision ID: 0001_day1
Revises:
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_day1"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(length=45)),
        sa.Column("destination_ip", sa.String(length=45)),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("raw_message", sa.Text(), nullable=False),
        sa.Column("parsed_data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_logs_timestamp", "logs", ["timestamp"])
    op.create_index("ix_logs_source_ip", "logs", ["source_ip"])
    op.create_index("ix_logs_destination_ip", "logs", ["destination_ip"])
    op.create_index("ix_logs_event_type", "logs", ["event_type"])
    op.create_index("ix_logs_severity", "logs", ["severity"])
    op.create_index("ix_logs_source_event_time", "logs", ["source_ip", "event_type", "timestamp"])

    op.create_table(
        "threat_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("log_id", sa.Integer(), sa.ForeignKey("logs.id"), nullable=False),
        sa.Column("threat_type", sa.String(length=100), nullable=False),
        sa.Column("threat_score", sa.Integer(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("is_resolved", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_threat_alerts_log_id", "threat_alerts", ["log_id"])
    op.create_index("ix_threat_alerts_created_at", "threat_alerts", ["created_at"])
    op.create_index("ix_threat_alerts_resolved", "threat_alerts", ["is_resolved"])


def downgrade() -> None:
    op.drop_table("threat_alerts")
    op.drop_table("logs")
