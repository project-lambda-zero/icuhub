"""Worker entry point: scheduler loop, queue consumers, and the outbox relay."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import socket
import ssl
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

from icuhub.core.queue import claim, complete, heartbeat, recover_expired, retry
from icuhub.core.relay import AioKafkaProducerAdapter, OutboxRelay, SecurityProtocol
from icuhub.core.services import configure, get_services
from icuhub.core.sync import scheduler_once
from icuhub.kit.types import SecretRef
from icuhub.settings import Settings
from icuhub.storage.db import get_engine
from icuhub.workers.handlers import HANDLERS, QUEUES

__all__ = ["main", "run_once", "worker_loop"]

_LOG = logging.getLogger("icuhub.worker")

_KAFKA_PROTOCOLS: dict[str, SecurityProtocol] = {"plaintext": "PLAINTEXT", "ssl": "SSL", "sasl_ssl": "SASL_SSL"}
_MAX_SECRET_BYTES = 64 * 1024
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class _SystemSecrets:
    """Resolves platform-level Kafka SASL references without a tenant.

    Accepted forms: ``env:NAME`` (an environment variable) and ``file:/absolute/path`` (a mounted
    file, with exactly one trailing line ending removed: CRLF, LF, or CR). Any other form is rejected.
    Tenant credentials are never consulted. Secret values are never logged and never appear in errors.
    """

    async def resolve(self, ref: SecretRef) -> bytes:
        value = ref.ref
        if value.startswith("env:"):
            return _read_env_secret(value[len("env:") :])
        if value.startswith("file:"):
            return _read_file_secret(value[len("file:") :])
        raise ValueError("unsupported platform secret reference: expected env:NAME or file:/absolute/path")


def _read_env_secret(name: str) -> bytes:
    if not _ENV_NAME.fullmatch(name):
        raise ValueError("malformed environment secret reference")
    raw = os.environ.get(name)
    if not raw:
        raise ValueError("environment secret is unset or empty")
    if len(raw.encode("utf-8")) > _MAX_SECRET_BYTES:
        raise ValueError(f"environment secret exceeds {_MAX_SECRET_BYTES} bytes")
    return raw.encode("utf-8")


def _read_file_secret(path_text: str) -> bytes:
    path = Path(path_text)
    if not path.is_absolute():
        raise ValueError("file secret reference must be an absolute path")
    try:
        with path.open("rb") as handle:
            data = handle.read(_MAX_SECRET_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"file secret is unreadable: {type(exc).__name__}") from exc
    if len(data) > _MAX_SECRET_BYTES:
        raise ValueError(f"file secret exceeds {_MAX_SECRET_BYTES} bytes")
    if data.endswith(b"\r\n"):
        data = data[:-2]
    elif data.endswith((b"\n", b"\r")):
        data = data[:-1]
    if not data:
        raise ValueError("file secret is empty")
    return data


async def _run_job(lease: Any) -> None:
    handler = HANDLERS.get(lease.kind)
    if handler is None:
        await retry(lease, f"unknown job kind {lease.kind}")
        return
    try:
        await heartbeat(lease)
        await handler(lease.payload, lease)
    except Exception as exc:  # noqa: BLE001 - failure class is recorded at this boundary  # worker boundary: the job's own state is already recorded
        _LOG.exception("job %s (%s) failed", lease.job_id, lease.kind)
        await retry(lease, f"{type(exc).__name__}: {exc}"[:2000])
    else:
        await complete(lease)


async def _open_relay_producer(settings: Settings) -> AioKafkaProducerAdapter:
    """Build and start the Kafka producer from settings. Shared by ``run_once`` and ``worker_loop``.

    Every configured security setting is applied: TLS for ``ssl`` and ``sasl_ssl`` (trusting
    ``kafka_ca_file`` when set), and SASL for ``sasl_ssl`` with platform secrets resolved by
    ``_SystemSecrets``. Invalid SASL combinations are rejected by the adapter constructor before
    any producer is created; secret resolution runs inside ``start()`` before the broker is contacted.
    """
    if not settings.kafka_bootstrap:
        raise RuntimeError("relay requested but ICUHUB_KAFKA_BOOTSTRAP is not set")
    protocol = _KAFKA_PROTOCOLS[settings.kafka_security]
    tls = protocol in ("SSL", "SASL_SSL")
    sasl = protocol == "SASL_SSL"
    ssl_context = None
    if tls:
        cafile = str(settings.kafka_ca_file) if settings.kafka_ca_file else None
        ssl_context = ssl.create_default_context(cafile=cafile)
    producer = AioKafkaProducerAdapter(
        bootstrap_servers=settings.kafka_bootstrap,
        security_protocol=protocol,
        sasl_mechanism=settings.kafka_sasl_mechanism if sasl else None,
        sasl_username=settings.kafka_sasl_username_ref if sasl else None,
        sasl_password=settings.kafka_sasl_password_ref if sasl else None,
        ssl_context=ssl_context,
        secrets=_SystemSecrets() if sasl else None,
    )
    await producer.start()
    return producer


async def run_once(*, queues: tuple[str, ...] = QUEUES, max_jobs: int = 50, relay: bool = False) -> int:
    """One scheduler pass plus up to ``max_jobs`` claimed jobs, then one relay batch when requested."""
    services = get_services()
    producer = await _open_relay_producer(services.settings) if relay else None
    try:
        scheduled = await scheduler_once()
        if scheduled:
            _LOG.info("scheduled %d sync jobs", scheduled)
        await recover_expired()
        processed = 0
        owner = f"{socket.gethostname()}:{uuid.uuid4()}"
        while processed < max_jobs:
            lease = await claim(queues, owner, timedelta(seconds=60))
            if lease is None:
                break
            await _run_job(lease)
            processed += 1
        if producer is not None:
            outbox = OutboxRelay(
                engine=get_engine(), producer=producer, batch_size=services.settings.relay_batch_size
            )
            await outbox.relay_batch()
        return processed
    finally:
        if producer is not None:
            await producer.stop()


async def worker_loop(*, queues: tuple[str, ...] = QUEUES, idle_s: float = 5.0, relay: bool = False) -> None:
    """Long-running scheduler, relay, and job loop. With ``relay`` the outbox is relayed every pass."""
    settings = get_services().settings
    owner = f"{socket.gethostname()}:{uuid.uuid4()}"
    producer = await _open_relay_producer(settings) if relay else None
    try:
        outbox = (
            OutboxRelay(engine=get_engine(), producer=producer, batch_size=settings.relay_batch_size)
            if producer is not None
            else None
        )
        while True:
            await scheduler_once()
            await recover_expired()
            relayed_full_batch = False
            if outbox is not None:
                result = await outbox.relay_batch()
                relayed_full_batch = result.published == settings.relay_batch_size
            lease = await claim(queues, owner, timedelta(seconds=60))
            if lease is None:
                if not relayed_full_batch:
                    await asyncio.sleep(idle_s)
                continue
            await _run_job(lease)
    finally:
        if producer is not None:
            await producer.stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="icuhub worker")
    parser.add_argument("--once", action="store_true", help="one scheduler and claim pass, then exit")
    parser.add_argument("--queues", default=",".join(QUEUES))
    parser.add_argument("--max-jobs", type=int, default=50)
    parser.add_argument(
        "--relay",
        action="store_true",
        help="relay the outbox to Kafka: every pass of the long-running loop, or one batch with --once",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    configure()
    queues = tuple(q.strip() for q in args.queues.split(",") if q.strip())
    if args.once:
        processed = asyncio.run(run_once(queues=queues, max_jobs=args.max_jobs, relay=args.relay))
        print(f"processed {processed} jobs")
        return 0
    asyncio.run(worker_loop(queues=queues, relay=args.relay))
    return 0
