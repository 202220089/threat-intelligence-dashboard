"""Create the blacklist table needed by the required IP API.

Revision ID: 0002_supporting
Revises: 0001_day1
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_supporting"
down_revision: Union[str, None] = "0001_day1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ip_blacklist",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ip_address", sa.String(length=45), nullable=False, unique=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_ip_blacklist_address", "ip_blacklist", ["ip_address"])


def downgrade() -> None:
    op.drop_table("ip_blacklist")
