"""Worker entry point: scheduler loop, queue consumers, and the outbox relay."""

from __future__ import annotations

import argparse
import asyncio
import logging
import socket
import uuid
from datetime import timedelta
from typing import Any

from icuhub.core.queue import claim, complete, heartbeat, recover_expired, retry
from icuhub.core.relay import OutboxRelay
from icuhub.core.services import configure, get_services
from icuhub.core.sync import scheduler_once
from icuhub.workers.handlers import HANDLERS, QUEUES

__all__ = ["main", "run_once", "worker_loop"]

_LOG = logging.getLogger("icuhub.worker")


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


async def run_once(*, queues: tuple[str, ...] = QUEUES, max_jobs: int = 50, relay: bool = False) -> int:
    """One scheduler pass plus up to ``max_jobs`` claimed jobs. Returns jobs processed."""
    services = get_services()
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
    if relay and services.settings.kafka_bootstrap:
        from icuhub.core.relay import AioKafkaProducerAdapter  # noqa: PLC0415

        producer = AioKafkaProducerAdapter(
            bootstrap_servers=services.settings.kafka_bootstrap,
            security_protocol=services.settings.kafka_security.upper(),
        )
        await producer.start()
        try:
            await OutboxRelay(producer=producer, batch_size=services.settings.relay_batch_size).relay_batch()
        finally:
            await producer.stop()
    return processed


async def worker_loop(*, queues: tuple[str, ...] = QUEUES, idle_s: float = 5.0) -> None:
    owner = f"{socket.gethostname()}:{uuid.uuid4()}"
    while True:
        await scheduler_once()
        await recover_expired()
        lease = await claim(queues, owner, timedelta(seconds=60))
        if lease is None:
            await asyncio.sleep(idle_s)
            continue
        await _run_job(lease)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="icuhub worker")
    parser.add_argument("--once", action="store_true", help="one scheduler and claim pass, then exit")
    parser.add_argument("--queues", default=",".join(QUEUES))
    parser.add_argument("--max-jobs", type=int, default=50)
    parser.add_argument("--relay", action="store_true", help="also relay one outbox batch (needs Kafka settings)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    configure()
    queues = tuple(q.strip() for q in args.queues.split(",") if q.strip())
    if args.once:
        processed = asyncio.run(run_once(queues=queues, max_jobs=args.max_jobs, relay=args.relay))
        print(f"processed {processed} jobs")
        return 0
    asyncio.run(worker_loop(queues=queues))
    return 0
