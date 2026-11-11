"""System functions for the outbox relay: cross-tenant claim, mark, and fail on ``outbox_event``.

``outbox_event`` carries row-level security. ``FORCE ROW LEVEL SECURITY`` applies to the table owner
too, so the relay cannot read other tenants' rows through a plain query under ``icuhub_app``, which
has no tenant bound. These ``SECURITY DEFINER`` functions run as the migration owner and are the only
cross-tenant path to ``outbox_event``. ``PUBLIC`` loses ``EXECUTE``; only ``icuhub_app`` receives it.

The owner must be a superuser or hold ``BYPASSRLS``. The guard below refuses to install the functions
otherwise, because a non-bypass owner would see zero rows and the relay would silently publish nothing.
"""

from __future__ import annotations

from alembic import op

revision: str = "0002_system_functions"
down_revision: str | None = "0001_initial"
branch_labels: str | None = None
depends_on: str | None = None

_FUNCTIONS: tuple[str, ...] = (
    "icuhub_outbox_claim(integer)",
    "icuhub_outbox_mark(uuid)",
    "icuhub_outbox_fail(uuid, text)",
)


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = current_user AND (rolsuper OR rolbypassrls)
            ) THEN
                RAISE EXCEPTION
                    'migration owner % must be a superuser or hold BYPASSRLS: outbox functions read across tenants',
                    current_user;
            END IF;
        END
        $$;
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION icuhub_outbox_claim(p_limit integer)
        RETURNS TABLE (id uuid, event_id text, topic text, event_json jsonb)
        LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
            SELECT o.id, o.event_id, o.topic, o.event_json
              FROM outbox_event AS o
             WHERE o.relayed_at IS NULL
             ORDER BY o.created_at, o.id
             LIMIT p_limit
             FOR UPDATE SKIP LOCKED;
        $$;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION icuhub_outbox_mark(p_id uuid)
        RETURNS void
        LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
            UPDATE outbox_event SET relayed_at = now() WHERE id = p_id AND relayed_at IS NULL;
        $$;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION icuhub_outbox_fail(p_id uuid, p_error text)
        RETURNS void
        LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
            UPDATE outbox_event
               SET attempts = attempts + 1, last_error = p_error
             WHERE id = p_id AND relayed_at IS NULL;
        $$;
        """
    )

    for signature in _FUNCTIONS:
        op.execute(f"REVOKE EXECUTE ON FUNCTION {signature} FROM PUBLIC")

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'icuhub_app') THEN
                GRANT EXECUTE ON FUNCTION icuhub_outbox_claim(integer) TO icuhub_app;
                GRANT EXECUTE ON FUNCTION icuhub_outbox_mark(uuid) TO icuhub_app;
                GRANT EXECUTE ON FUNCTION icuhub_outbox_fail(uuid, text) TO icuhub_app;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS icuhub_outbox_fail(uuid, text)")
    op.execute("DROP FUNCTION IF EXISTS icuhub_outbox_mark(uuid)")
    op.execute("DROP FUNCTION IF EXISTS icuhub_outbox_claim(integer)")
