"""Cross-tenant system lookups: due stream states, webhook endpoints, service accounts.

Same pattern as ``0002``: narrow ``SECURITY DEFINER`` functions owned by the migration
role, ``PUBLIC`` loses ``EXECUTE``, ``icuhub_app`` receives it. Each function exposes
only the columns the system path needs; tenant data stays behind row-level security.
"""

from __future__ import annotations

from alembic import op

revision: str = "0003_system_lookups"
down_revision: str | None = "0002_system_functions"
branch_labels: str | None = None
depends_on: str | None = None

_FUNCTIONS: tuple[str, ...] = (
    "icuhub_due_stream_states(timestamptz, integer)",
    "icuhub_webhook_endpoint_lookup(text)",
    "icuhub_service_account_by_prefix(text)",
    "icuhub_service_account_by_subject(text, text)",
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
                    'migration owner % must be a superuser or hold BYPASSRLS: system lookups read across tenants',
                    current_user;
            END IF;
        END
        $$;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION icuhub_due_stream_states(p_now timestamptz, p_limit integer)
        RETURNS TABLE (id uuid, tenant_id uuid, connection_id uuid, target_id uuid,
                       stream text, partition_key text)
        LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
            SELECT s.id, s.tenant_id, s.connection_id, s.target_id, s.stream, s.partition
              FROM stream_state AS s
              JOIN connection AS c ON c.id = s.connection_id
             WHERE s.enabled
               AND NOT c.status = 'disabled'
               AND s.next_run_at IS NOT NULL
               AND s.next_run_at <= p_now
               AND (s.lease_expires_at IS NULL OR s.lease_expires_at <= p_now)
             ORDER BY s.next_run_at, s.id
             LIMIT p_limit;
        $$;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION icuhub_webhook_endpoint_lookup(p_id text)
        RETURNS TABLE (tenant_id uuid, connection_id uuid, secret_ref text,
                       previous_secret_ref text, previous_valid_until timestamptz,
                       disabled_at timestamptz)
        LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
            SELECT e.tenant_id, e.connection_id, e.secret_ref,
                   e.previous_secret_ref, e.previous_valid_until, e.disabled_at
              FROM webhook_endpoint AS e
             WHERE e.id = p_id;
        $$;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION icuhub_service_account_by_prefix(p_prefix text)
        RETURNS TABLE (id uuid, tenant_id uuid, name text, key_hash text,
                       roles text[], groups text[], disabled_at timestamptz)
        LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
            SELECT a.id, a.tenant_id, a.name, a.key_hash, a.roles, a.groups, a.disabled_at
              FROM service_account AS a
             WHERE a.key_prefix = p_prefix;
        $$;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION icuhub_service_account_by_subject(p_issuer text, p_subject text)
        RETURNS TABLE (id uuid, tenant_id uuid, name text, key_hash text,
                       roles text[], groups text[], disabled_at timestamptz)
        LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
            SELECT a.id, a.tenant_id, a.name, a.key_hash, a.roles, a.groups, a.disabled_at
              FROM service_account AS a
             WHERE a.oidc_issuer = p_issuer AND a.oidc_subject = p_subject;
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
                GRANT EXECUTE ON FUNCTION icuhub_due_stream_states(timestamptz, integer) TO icuhub_app;
                GRANT EXECUTE ON FUNCTION icuhub_webhook_endpoint_lookup(text) TO icuhub_app;
                GRANT EXECUTE ON FUNCTION icuhub_service_account_by_prefix(text) TO icuhub_app;
                GRANT EXECUTE ON FUNCTION icuhub_service_account_by_subject(text, text) TO icuhub_app;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    for signature in reversed(_FUNCTIONS):
        op.execute(f"DROP FUNCTION IF EXISTS {signature}")
