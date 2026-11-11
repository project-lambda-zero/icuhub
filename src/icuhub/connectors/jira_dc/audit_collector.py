"""Authenticated client for node-local Jira Data Center audit files served by the TLS file collector.

The collector is a service separate from Jira. It receives its own bearer token and client
certificate, and the Jira personal access token never reaches it. The collector client reuses the
connector's CA bundle, proxy, and timeout. Each fetch returns the complete current file so that
``parse_audit_batch`` can verify the committed prefix fingerprint.
"""

from __future__ import annotations

from typing import Final
from urllib.parse import urlsplit

from icuhub.connectors._jira.models import JiraDataCenterConfig
from icuhub.kit.auth import BearerToken, Clock
from icuhub.kit.connector import SecretResolver
from icuhub.kit.errors import ConfigError
from icuhub.kit.http import VendorHttp, build_http

__all__ = ["MAX_AUDIT_RECORD_BYTES", "open_audit_collector"]

# Chosen bound, not a vendor limit: maximum length of one JSONL record line. The whole-file
# snapshot cap is the configured ``audit_max_bytes``.
MAX_AUDIT_RECORD_BYTES: Final = 1024 * 1024


async def open_audit_collector(
    config: JiraDataCenterConfig,
    secrets: SecretResolver,
    clock: Clock,
) -> VendorHttp:
    """Build the collector client for ``config.audit_files``. The caller closes it with ``aclose``.

    The collector certificate is bound as this client's client certificate, so the derived
    configuration carries it in place of the Jira ``client_cert``/``client_key`` references.
    """
    if config.audit_collector_token is None:
        raise ConfigError("audit_files require audit_collector_token")
    token = await secrets.resolve(config.audit_collector_token)
    try:
        text = token.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ConfigError("audit_collector_token must be ASCII text") from exc

    cert_pem: bytes | None = None
    key_pem: bytes | None = None
    if config.audit_collector_client_cert is not None and config.audit_collector_client_key is not None:
        cert_pem = await secrets.resolve(config.audit_collector_client_cert)
        key_pem = await secrets.resolve(config.audit_collector_client_key)

    # [UNVERIFIED] collector mTLS trust: assumed to share the Jira CA bundle carried on the derived config.
    collector_config = config.model_copy(
        update={
            "client_cert": config.audit_collector_client_cert,
            "client_key": config.audit_collector_client_key,
        }
    )
    hosts = frozenset(
        host for host in (urlsplit(source.url).hostname for source in config.audit_files) if host is not None
    )
    return build_http(
        collector_config,
        BearerToken(text),
        clock=clock,
        extra_hosts=hosts,
        client_cert_pem=cert_pem,
        client_key_pem=key_pem,
    )
