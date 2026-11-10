"""Natural key on action requests with an active-scope unique index (MVP 4.17 and connector natural-key actions).

``natural_key`` carries the connector-declared identity of a natural-key write. The partial unique
index admits at most one active request per tenant, connection, action, and natural key, so a
concurrent duplicate submission cannot create a second vendor write while the first is in flight.
Terminal states drop out of the index and a later request for the same identity is admitted.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0005_action_natural_key"
down_revision: str | None = "0004_exception_state"
branch_labels: str | None = None
depends_on: str | None = None

_ACTIVE_STATES = (
    "received",
    "pending_approval",
    "approved",
    "executing",
    "accepted_async",
    "outcome_unknown",
)


def upgrade() -> None:
    op.add_column("action_request", sa.Column("natural_key", sa.String(length=200), nullable=True))
    op.create_index(
        "uq_action_request_natural_key_active",
        "action_request",
        ["tenant_id", "connection_id", "action", "natural_key"],
        unique=True,
        postgresql_where=sa.text(
            "natural_key IS NOT NULL AND state IN (" + ", ".join(f"'{state}'" for state in _ACTIVE_STATES) + ")"
        ),
    )


def downgrade() -> None:
    op.drop_index("uq_action_request_natural_key_active", table_name="action_request")
    op.drop_column("action_request", "natural_key")
