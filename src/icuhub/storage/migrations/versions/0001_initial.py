"""Initial ICUHUB schema: tables, indexes, row-level security, grants, audit append-only trigger.

This revision is frozen. It is written out as explicit DDL and does not import
``icuhub.storage.models``, so later model edits never change this history.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None

_TENANT_TABLES: tuple[str, ...] = ('action_plan', 'action_request', 'approval', 'audit_record', 'case_member', 'connection', 'correlation_case', 'credential', 'evidence_item', 'file_import', 'finding', 'notification', 'outbox_event', 'policy_rule', 'quarantine_item', 'raw_batch', 'service_account', 'source_record', 'stream_state', 'sync_run', 'target', 'ticket_link', 'ticket_route', 'webhook_delivery', 'webhook_endpoint')

_TENANT_POLICY_USING = "tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid"
_TENANT_SELF_USING = "id = nullif(current_setting('app.tenant_id', true), '')::uuid"


def upgrade() -> None:
    op.create_table(
        'tenant',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('slug', sa.String(63), nullable=False),
        sa.Column('display_name', sa.String(200), nullable=False),
        sa.Column('automation_enabled', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id', name='pk_tenant'),
        sa.UniqueConstraint('slug', name='uq_tenant_slug'),
    )
    op.create_table(
        'audit_record',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('seq', sa.BigInteger(), nullable=False),
        sa.Column('prev_hash', sa.String(71), nullable=False),
        sa.Column('hash', sa.String(71), nullable=False),
        sa.Column('ts', sa.DateTime(timezone=True), nullable=False),
        sa.Column('caller_id', sa.String(200), nullable=False),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('operation', sa.String(200), nullable=False),
        sa.Column('classification', sa.String(16), nullable=True),
        sa.Column('decision', sa.String(24), nullable=True),
        sa.Column('approval_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('args_digest', sa.String(71), nullable=True),
        sa.Column('status', sa.String(32), nullable=False),
        sa.Column('correlation_id', sa.String(200), nullable=True),
        sa.Column('detail_json', postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.PrimaryKeyConstraint('id', name='pk_audit_record'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_audit_record_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
        sa.UniqueConstraint('tenant_id', 'seq', name='uq_audit_record_tenant_id_seq'),
    )
    op.create_table(
        'connection',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('kind', sa.String(64), nullable=False),
        sa.Column('slug', sa.String(63), nullable=False),
        sa.Column('display_name', sa.String(200), nullable=False),
        sa.Column('config_json', postgresql.JSONB(), nullable=False),
        sa.Column('egress_class', sa.String(32), nullable=False, server_default=sa.text("'vendor_tenant'")),
        sa.Column('allowed_operations', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('status', sa.String(16), nullable=False, server_default=sa.text("'active'")),
        sa.Column('last_health_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_health_json', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id', name='pk_connection'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_connection_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
        sa.UniqueConstraint('tenant_id', 'slug', name='uq_connection_tenant_id_slug'),
    )
    op.create_table(
        'correlation_case',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('correlation_key', sa.String(200), nullable=False),
        sa.Column('key_version', sa.SmallInteger(), nullable=False),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('severity_id', sa.SmallInteger(), nullable=False),
        sa.Column('detection_state', sa.String(32), nullable=False, server_default=sa.text("'open'")),
        sa.Column('remediation_state', sa.String(32), nullable=False, server_default=sa.text("'new'")),
        sa.Column('exception_state', sa.String(32), nullable=False, server_default=sa.text("'none'")),
        sa.Column('exception_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('merged_into', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id', name='pk_correlation_case'),
        sa.ForeignKeyConstraint(['merged_into'], ['correlation_case.id'], name='fk_correlation_case_merged_into_correlation_case', ondelete=None, onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_correlation_case_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
    )
    op.create_table(
        'credential',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('kek_id', sa.String(200), nullable=False),
        sa.Column('dek_wrapped', sa.LargeBinary(), nullable=False),
        sa.Column('nonce', sa.LargeBinary(), nullable=False),
        sa.Column('ciphertext', sa.LargeBinary(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('rotated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_credential'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_credential_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
    )
    op.create_table(
        'job',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('queue', sa.String(64), nullable=False),
        sa.Column('kind', sa.String(64), nullable=False),
        sa.Column('payload_json', postgresql.JSONB(), nullable=False),
        sa.Column('priority', sa.SmallInteger(), nullable=False, server_default=sa.text('100')),
        sa.Column('run_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('attempts', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('max_attempts', sa.Integer(), nullable=False, server_default=sa.text('5')),
        sa.Column('state', sa.String(16), nullable=False, server_default=sa.text("'queued'")),
        sa.Column('lease_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('lease_owner', sa.String(200), nullable=True),
        sa.Column('lease_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('dedupe_key', sa.String(300), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id', name='pk_job'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_job_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
    )
    op.create_table(
        'outbox_event',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('event_id', sa.String(200), nullable=False),
        sa.Column('topic', sa.String(249), nullable=False),
        sa.Column('event_json', postgresql.JSONB(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('relayed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('attempts', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_outbox_event'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_outbox_event_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
        sa.UniqueConstraint('event_id', name='uq_outbox_event_event_id'),
    )
    op.create_table(
        'policy_rule',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('priority', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('match_json', postgresql.JSONB(), nullable=False),
        sa.Column('decision', sa.String(24), nullable=False),
        sa.Column('auto_execute_enabled', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('approver_group', sa.String(200), nullable=True),
        sa.Column('approval_ttl_s', sa.Integer(), nullable=False, server_default=sa.text('86400')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id', name='pk_policy_rule'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_policy_rule_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
    )
    op.create_table(
        'service_account',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('key_prefix', sa.String(16), nullable=True),
        sa.Column('key_hash', sa.String(64), nullable=True),
        sa.Column('oidc_issuer', sa.Text(), nullable=True),
        sa.Column('oidc_subject', sa.Text(), nullable=True),
        sa.Column('roles', postgresql.ARRAY(sa.Text()), nullable=False, server_default=sa.text("'{}'")),
        sa.Column('groups', postgresql.ARRAY(sa.Text()), nullable=False, server_default=sa.text("'{}'")),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('disabled_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_service_account'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_service_account_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
        sa.UniqueConstraint('key_prefix', name='uq_service_account_key_prefix'),
        sa.UniqueConstraint('tenant_id', 'name', name='uq_service_account_tenant_id_name'),
    )
    op.create_table(
        'action_request',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('classification', sa.String(16), nullable=False),
        sa.Column('args_json', postgresql.JSONB(), nullable=False),
        sa.Column('args_digest', sa.String(71), nullable=False),
        sa.Column('caller_id', sa.String(200), nullable=False),
        sa.Column('correlation_id', sa.String(200), nullable=True),
        sa.Column('idempotency_key', sa.String(200), nullable=False),
        sa.Column('mode', sa.String(16), nullable=False, server_default=sa.text("'live'")),
        sa.Column('state', sa.String(24), nullable=False),
        sa.Column('decision', sa.String(24), nullable=True),
        sa.Column('rule_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('result_json', postgresql.JSONB(), nullable=True),
        sa.Column('error_class', sa.String(100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id', name='pk_action_request'),
        sa.ForeignKeyConstraint(['connection_id'], ['connection.id'], name='fk_action_request_connection_id_connection', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['rule_id'], ['policy_rule.id'], name='fk_action_request_rule_id_policy_rule', ondelete='SET NULL', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_action_request_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
        sa.UniqueConstraint('tenant_id', 'caller_id', 'idempotency_key', name='uq_action_request_tenant_id_caller_id_idempotency_key'),
    )
    op.create_table(
        'evidence_item',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('case_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('kind', sa.String(32), nullable=False),
        sa.Column('digest', sa.String(71), nullable=False),
        sa.Column('ref_table', sa.String(64), nullable=False),
        sa.Column('ref_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id', name='pk_evidence_item'),
        sa.ForeignKeyConstraint(['case_id'], ['correlation_case.id'], name='fk_evidence_item_case_id_correlation_case', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_evidence_item_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
    )
    op.create_table(
        'notification',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('template', sa.String(100), nullable=False),
        sa.Column('recipients', postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column('subject', sa.Text(), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('state', sa.String(16), nullable=False, server_default=sa.text("'queued'")),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_notification'),
        sa.ForeignKeyConstraint(['connection_id'], ['connection.id'], name='fk_notification_connection_id_connection', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_notification_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
    )
    op.create_table(
        'target',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('source_uid', sa.Text(), nullable=False),
        sa.Column('kind', sa.String(64), nullable=False),
        sa.Column('display_name', sa.Text(), nullable=False),
        sa.Column('attributes_json', postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column('included', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('paused', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('missing_since', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_target'),
        sa.ForeignKeyConstraint(['connection_id'], ['connection.id'], name='fk_target_connection_id_connection', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_target_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
        sa.UniqueConstraint('connection_id', 'source_uid', name='uq_target_connection_id_source_uid'),
    )
    op.create_table(
        'ticket_route',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('match_json', postgresql.JSONB(), nullable=False),
        sa.Column('template_json', postgresql.JSONB(), nullable=False),
        sa.Column('status_policy_json', postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id', name='pk_ticket_route'),
        sa.ForeignKeyConstraint(['connection_id'], ['connection.id'], name='fk_ticket_route_connection_id_connection', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_ticket_route_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
        sa.UniqueConstraint('tenant_id', 'name', name='uq_ticket_route_tenant_id_name'),
    )
    op.create_table(
        'webhook_endpoint',
        sa.Column('id', sa.String(64), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('secret_ref', sa.String(200), nullable=False),
        sa.Column('previous_secret_ref', sa.String(200), nullable=True),
        sa.Column('previous_valid_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('disabled_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_webhook_endpoint'),
        sa.ForeignKeyConstraint(['connection_id'], ['connection.id'], name='fk_webhook_endpoint_connection_id_connection', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_webhook_endpoint_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
    )
    op.create_table(
        'action_plan',
        sa.Column('action_request_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_ref', sa.Text(), nullable=False),
        sa.Column('diff_json', postgresql.JSONB(), nullable=False),
        sa.Column('preconditions_json', postgresql.JSONB(), nullable=False),
        sa.Column('request_json', postgresql.JSONB(), nullable=False),
        sa.Column('idempotency_key', sa.String(200), nullable=False),
        sa.Column('plan_hash', sa.String(71), nullable=False),
        sa.Column('changed', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('action_request_id', name='pk_action_plan'),
        sa.ForeignKeyConstraint(['action_request_id'], ['action_request.id'], name='fk_action_plan_action_request_id_action_request', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_action_plan_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
    )
    op.create_table(
        'approval',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('action_request_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('approver_group', sa.String(200), nullable=True),
        sa.Column('plan_hash', sa.String(71), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('decision', sa.String(16), nullable=True),
        sa.Column('decided_by', sa.String(200), nullable=True),
        sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('change_ref', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id', name='pk_approval'),
        sa.ForeignKeyConstraint(['action_request_id'], ['action_request.id'], name='fk_approval_action_request_id_action_request', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_approval_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
    )
    op.create_table(
        'stream_state',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('target_key', sa.String(64), nullable=False, server_default=sa.text("''")),
        sa.Column('stream', sa.String(100), nullable=False),
        sa.Column('partition', sa.String(200), nullable=False, server_default=sa.text("''")),
        sa.Column('checkpoint_json', postgresql.JSONB(), nullable=True),
        sa.Column('checkpoint_schema', sa.String(200), nullable=True),
        sa.Column('version', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('lease_owner', sa.String(200), nullable=True),
        sa.Column('lease_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('health', sa.String(16), nullable=False, server_default=sa.text("'not_evaluated'")),
        sa.Column('last_success_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_full_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('lag_s', sa.Integer(), nullable=True),
        sa.Column('interval_s', sa.Integer(), nullable=False, server_default=sa.text('900')),
        sa.Column('full_interval_s', sa.Integer(), nullable=False, server_default=sa.text('86400')),
        sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.PrimaryKeyConstraint('id', name='pk_stream_state'),
        sa.ForeignKeyConstraint(['connection_id'], ['connection.id'], name='fk_stream_state_connection_id_connection', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['target_id'], ['target.id'], name='fk_stream_state_target_id_target', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_stream_state_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
        sa.UniqueConstraint('connection_id', 'target_key', 'stream', 'partition', name='uq_stream_state_connection_id_target_key_stream_partition'),
    )
    op.create_table(
        'ticket_link',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('route_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('case_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('state', sa.String(32), nullable=False, server_default=sa.text("'pending'")),
        sa.Column('remote_key', sa.Text(), nullable=True),
        sa.Column('remote_id', sa.Text(), nullable=True),
        sa.Column('remote_url', sa.Text(), nullable=True),
        sa.Column('remote_status', sa.Text(), nullable=True),
        sa.Column('status_category', sa.String(16), nullable=True),
        sa.Column('last_outbound_revision', sa.Text(), nullable=True),
        sa.Column('last_inbound_revision', sa.Text(), nullable=True),
        sa.Column('last_synced_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('action_request_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id', name='pk_ticket_link'),
        sa.ForeignKeyConstraint(['action_request_id'], ['action_request.id'], name='fk_ticket_link_action_request_id_action_request', ondelete='SET NULL', onupdate=None),
        sa.ForeignKeyConstraint(['case_id'], ['correlation_case.id'], name='fk_ticket_link_case_id_correlation_case', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['connection_id'], ['connection.id'], name='fk_ticket_link_connection_id_connection', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['route_id'], ['ticket_route.id'], name='fk_ticket_link_route_id_ticket_route', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_ticket_link_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
        sa.UniqueConstraint('tenant_id', 'route_id', 'case_id', name='uq_ticket_link_tenant_id_route_id_case_id'),
    )
    op.create_table(
        'sync_run',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('stream_state_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('stream', sa.String(100), nullable=False),
        sa.Column('mode', sa.String(16), nullable=False),
        sa.Column('completeness', sa.String(16), nullable=False, server_default=sa.text("'partial'")),
        sa.Column('outcome', sa.String(16), nullable=False, server_default=sa.text("'running'")),
        sa.Column('counts_json', postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column('error_class', sa.String(100), nullable=True),
        sa.Column('error_detail', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_sync_run'),
        sa.ForeignKeyConstraint(['connection_id'], ['connection.id'], name='fk_sync_run_connection_id_connection', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['stream_state_id'], ['stream_state.id'], name='fk_sync_run_stream_state_id_stream_state', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_sync_run_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
    )
    op.create_table(
        'raw_batch',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('sync_run_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('origin', sa.String(16), nullable=False),
        sa.Column('stream', sa.String(100), nullable=False),
        sa.Column('digest', sa.String(71), nullable=False),
        sa.Column('record_count', sa.Integer(), nullable=False),
        sa.Column('parser_version', sa.String(32), nullable=False),
        sa.Column('kek_id', sa.String(200), nullable=False),
        sa.Column('dek_wrapped', sa.LargeBinary(), nullable=False),
        sa.Column('nonce', sa.LargeBinary(), nullable=False),
        sa.Column('payload_enc', sa.LargeBinary(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id', name='pk_raw_batch'),
        sa.ForeignKeyConstraint(['connection_id'], ['connection.id'], name='fk_raw_batch_connection_id_connection', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['sync_run_id'], ['sync_run.id'], name='fk_raw_batch_sync_run_id_sync_run', ondelete='SET NULL', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_raw_batch_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
    )
    op.create_table(
        'file_import',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('importer', sa.String(100), nullable=False),
        sa.Column('filename', sa.Text(), nullable=False),
        sa.Column('digest', sa.String(71), nullable=False),
        sa.Column('size_bytes', sa.BigInteger(), nullable=False),
        sa.Column('state', sa.String(16), nullable=False, server_default=sa.text("'queued'")),
        sa.Column('raw_batch_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('counts_json', postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_file_import'),
        sa.ForeignKeyConstraint(['connection_id'], ['connection.id'], name='fk_file_import_connection_id_connection', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['raw_batch_id'], ['raw_batch.id'], name='fk_file_import_raw_batch_id_raw_batch', ondelete='SET NULL', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_file_import_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
        sa.UniqueConstraint('connection_id', 'importer', 'digest', name='uq_file_import_connection_id_importer_digest'),
    )
    op.create_table(
        'finding',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('stream', sa.String(100), nullable=False),
        sa.Column('source_uid', sa.Text(), nullable=False),
        sa.Column('fingerprint', sa.String(67), nullable=False),
        sa.Column('ocsf_class_uid', sa.Integer(), nullable=False),
        sa.Column('severity_id', sa.SmallInteger(), nullable=False),
        sa.Column('status', sa.String(32), nullable=False, server_default=sa.text("'open'")),
        sa.Column('title', sa.Text(), nullable=True),
        sa.Column('ocsf_json', postgresql.JSONB(), nullable=False),
        sa.Column('revision_digest', sa.String(71), nullable=False),
        sa.Column('raw_batch_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('mapper_version', sa.Integer(), nullable=False),
        sa.Column('correlation_key', sa.String(200), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_finding'),
        sa.ForeignKeyConstraint(['connection_id'], ['connection.id'], name='fk_finding_connection_id_connection', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['raw_batch_id'], ['raw_batch.id'], name='fk_finding_raw_batch_id_raw_batch', ondelete='SET NULL', onupdate=None),
        sa.ForeignKeyConstraint(['target_id'], ['target.id'], name='fk_finding_target_id_target', ondelete='SET NULL', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_finding_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
        sa.UniqueConstraint('connection_id', 'stream', 'source_uid', name='uq_finding_connection_id_stream_source_uid'),
    )
    op.create_table(
        'quarantine_item',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('raw_batch_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('record_index', sa.Integer(), nullable=False),
        sa.Column('error_class', sa.String(100), nullable=False),
        sa.Column('error_detail', sa.Text(), nullable=False),
        sa.Column('mapper_version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('replayed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_quarantine_item'),
        sa.ForeignKeyConstraint(['raw_batch_id'], ['raw_batch.id'], name='fk_quarantine_item_raw_batch_id_raw_batch', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_quarantine_item_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
    )
    op.create_table(
        'source_record',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('stream', sa.String(100), nullable=False),
        sa.Column('record_type', sa.String(64), nullable=False),
        sa.Column('uid', sa.Text(), nullable=False),
        sa.Column('revision', sa.Text(), nullable=True),
        sa.Column('data_json', postgresql.JSONB(), nullable=False),
        sa.Column('links_json', postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column('raw_batch_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_source_record'),
        sa.ForeignKeyConstraint(['connection_id'], ['connection.id'], name='fk_source_record_connection_id_connection', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['raw_batch_id'], ['raw_batch.id'], name='fk_source_record_raw_batch_id_raw_batch', ondelete='SET NULL', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_source_record_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
        sa.UniqueConstraint('connection_id', 'record_type', 'uid', name='uq_source_record_connection_id_record_type_uid'),
    )
    op.create_table(
        'webhook_delivery',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('connection_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('endpoint_id', sa.String(64), nullable=False),
        sa.Column('vendor_delivery_id', sa.String(200), nullable=False),
        sa.Column('event_type', sa.String(200), nullable=True),
        sa.Column('raw_batch_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('status', sa.String(16), nullable=False, server_default=sa.text("'received'")),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('processed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_webhook_delivery'),
        sa.ForeignKeyConstraint(['connection_id'], ['connection.id'], name='fk_webhook_delivery_connection_id_connection', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['endpoint_id'], ['webhook_endpoint.id'], name='fk_webhook_delivery_endpoint_id_webhook_endpoint', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['raw_batch_id'], ['raw_batch.id'], name='fk_webhook_delivery_raw_batch_id_raw_batch', ondelete='SET NULL', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_webhook_delivery_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
        sa.UniqueConstraint('connection_id', 'vendor_delivery_id', name='uq_webhook_delivery_connection_id_vendor_delivery_id'),
    )
    op.create_table(
        'case_member',
        sa.Column('finding_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('case_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('reason', sa.String(32), nullable=False),
        sa.Column('linked_by', sa.String(200), nullable=False),
        sa.Column('linked_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('finding_id', name='pk_case_member'),
        sa.ForeignKeyConstraint(['case_id'], ['correlation_case.id'], name='fk_case_member_case_id_correlation_case', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['finding_id'], ['finding.id'], name='fk_case_member_finding_id_finding', ondelete='CASCADE', onupdate=None),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenant.id'], name='fk_case_member_tenant_id_tenant', ondelete='CASCADE', onupdate=None),
    )

    op.create_index('ix_audit_record_tenant_id', 'audit_record', ['tenant_id'], unique=False)
    op.create_index('ix_connection_tenant_id', 'connection', ['tenant_id'], unique=False)
    op.create_index('ix_correlation_case_tenant_id', 'correlation_case', ['tenant_id'], unique=False)
    op.create_index('uq_correlation_case_open_key', 'correlation_case', ['tenant_id', 'correlation_key'], unique=True, postgresql_where=sa.text('merged_into IS NULL'))
    op.create_index('ix_credential_tenant_id', 'credential', ['tenant_id'], unique=False)
    op.create_index('ix_job_claim', 'job', ['queue', 'state', 'run_at'], unique=False)
    op.create_index('uq_job_dedupe_active', 'job', ['dedupe_key'], unique=True, postgresql_where=sa.text("state IN ('queued', 'running')"))
    op.create_index('ix_outbox_event_pending', 'outbox_event', ['relayed_at', 'created_at'], unique=False)
    op.create_index('ix_outbox_event_tenant_id', 'outbox_event', ['tenant_id'], unique=False)
    op.create_index('ix_policy_rule_tenant_id', 'policy_rule', ['tenant_id'], unique=False)
    op.create_index('ix_service_account_tenant_id', 'service_account', ['tenant_id'], unique=False)
    op.create_index('ix_action_request_tenant_id', 'action_request', ['tenant_id'], unique=False)
    op.create_index('ix_evidence_item_tenant_id', 'evidence_item', ['tenant_id'], unique=False)
    op.create_index('ix_notification_tenant_id', 'notification', ['tenant_id'], unique=False)
    op.create_index('ix_target_tenant_id', 'target', ['tenant_id'], unique=False)
    op.create_index('ix_ticket_route_tenant_id', 'ticket_route', ['tenant_id'], unique=False)
    op.create_index('ix_webhook_endpoint_tenant_id', 'webhook_endpoint', ['tenant_id'], unique=False)
    op.create_index('ix_action_plan_tenant_id', 'action_plan', ['tenant_id'], unique=False)
    op.create_index('ix_approval_tenant_id', 'approval', ['tenant_id'], unique=False)
    op.create_index('ix_stream_state_tenant_id', 'stream_state', ['tenant_id'], unique=False)
    op.create_index('ix_ticket_link_tenant_id', 'ticket_link', ['tenant_id'], unique=False)
    op.create_index('ix_sync_run_tenant_id', 'sync_run', ['tenant_id'], unique=False)
    op.create_index('ix_raw_batch_tenant_id', 'raw_batch', ['tenant_id'], unique=False)
    op.create_index('ix_file_import_tenant_id', 'file_import', ['tenant_id'], unique=False)
    op.create_index('ix_finding_tenant_correlation_key', 'finding', ['tenant_id', 'correlation_key'], unique=False)
    op.create_index('ix_finding_tenant_fingerprint', 'finding', ['tenant_id', 'fingerprint'], unique=False)
    op.create_index('ix_finding_tenant_id', 'finding', ['tenant_id'], unique=False)
    op.create_index('ix_quarantine_item_tenant_id', 'quarantine_item', ['tenant_id'], unique=False)
    op.create_index('ix_source_record_tenant_id', 'source_record', ['tenant_id'], unique=False)
    op.create_index('ix_webhook_delivery_tenant_id', 'webhook_delivery', ['tenant_id'], unique=False)
    op.create_index('ix_case_member_case_id', 'case_member', ['case_id'], unique=False)
    op.create_index('ix_case_member_tenant_id', 'case_member', ['tenant_id'], unique=False)

    for table in _TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({_TENANT_POLICY_USING}) WITH CHECK ({_TENANT_POLICY_USING})"
        )

    op.execute("ALTER TABLE tenant ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tenant FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_self ON tenant USING ({_TENANT_SELF_USING}) WITH CHECK ({_TENANT_SELF_USING})"
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION icuhub_audit_record_append_only() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'UPDATE'
               AND current_setting('icuhub.audit_purge', true) = 'on'
               AND NEW.detail_json = '{}'::jsonb
               AND (to_jsonb(NEW) - 'detail_json') = (to_jsonb(OLD) - 'detail_json') THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'audit_record is append-only (operation %)', TG_OP;
        END
        $$;
        """
    )
    op.execute(
        "CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_record "
        "FOR EACH ROW EXECUTE FUNCTION icuhub_audit_record_append_only()"
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION icuhub_purge_audit_detail(p_tenant_id uuid, p_up_to_seq bigint)
        RETURNS bigint
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
        DECLARE
            purged bigint;
            previous_tenant text := current_setting('app.tenant_id', true);
        BEGIN
            PERFORM set_config('icuhub.audit_purge', 'on', true);
            PERFORM set_config('app.tenant_id', p_tenant_id::text, true);
            UPDATE audit_record
               SET detail_json = '{}'::jsonb
             WHERE tenant_id = p_tenant_id AND seq <= p_up_to_seq AND detail_json <> '{}'::jsonb;
            GET DIAGNOSTICS purged = ROW_COUNT;
            PERFORM set_config('app.tenant_id', coalesce(previous_tenant, ''), true);
            PERFORM set_config('icuhub.audit_purge', 'off', true);
            RETURN purged;
        END
        $$;
        """
    )
    op.execute("REVOKE EXECUTE ON FUNCTION icuhub_purge_audit_detail(uuid, bigint) FROM PUBLIC")

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'icuhub_app') THEN
                GRANT USAGE ON SCHEMA public TO icuhub_app;
                GRANT SELECT, INSERT, UPDATE, DELETE ON tenant, connection, correlation_case, credential, job, outbox_event, policy_rule, service_account, action_request, evidence_item, notification, target, ticket_route, webhook_endpoint, action_plan, approval, stream_state, ticket_link, sync_run, raw_batch, file_import, finding, quarantine_item, source_record, webhook_delivery, case_member TO icuhub_app;
                GRANT SELECT, INSERT ON audit_record TO icuhub_app;
                GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO icuhub_app;
                GRANT EXECUTE ON FUNCTION icuhub_purge_audit_detail(uuid, bigint) TO icuhub_app;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS icuhub_purge_audit_detail(uuid, bigint)")
    op.execute("DROP TRIGGER IF EXISTS audit_append_only ON audit_record")
    op.execute("DROP FUNCTION IF EXISTS icuhub_audit_record_append_only()")
    op.drop_table('case_member')
    op.drop_table('webhook_delivery')
    op.drop_table('source_record')
    op.drop_table('quarantine_item')
    op.drop_table('finding')
    op.drop_table('file_import')
    op.drop_table('raw_batch')
    op.drop_table('sync_run')
    op.drop_table('ticket_link')
    op.drop_table('stream_state')
    op.drop_table('approval')
    op.drop_table('action_plan')
    op.drop_table('webhook_endpoint')
    op.drop_table('ticket_route')
    op.drop_table('target')
    op.drop_table('notification')
    op.drop_table('evidence_item')
    op.drop_table('action_request')
    op.drop_table('service_account')
    op.drop_table('policy_rule')
    op.drop_table('outbox_event')
    op.drop_table('job')
    op.drop_table('credential')
    op.drop_table('correlation_case')
    op.drop_table('connection')
    op.drop_table('audit_record')
    op.drop_table('tenant')
