"""Exception decision revision and approved source scope on correlation cases (F3: FR-GRC-04).

``exception_state`` and ``exception_expires_at`` (``0001``) carry the exception state machine.
These two columns record which decision revision and which source scope the current approval
covers, so a superseded revision or an out-of-scope finding is reversed by the F3 converge loop.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_exception_state"
down_revision: str | None = "0003_system_lookups"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("correlation_case", sa.Column("exception_revision", sa.Text(), nullable=True))
    op.add_column(
        "correlation_case",
        sa.Column("exception_scope_uids", postgresql.ARRAY(sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("correlation_case", "exception_scope_uids")
    op.drop_column("correlation_case", "exception_revision")
