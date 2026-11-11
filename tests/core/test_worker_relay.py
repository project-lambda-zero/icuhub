"""Worker relay wiring: one producer factory, system-scoped secrets, and continuous relay in the loop.

Ack-before-mark ordering is covered by ``tests/core/test_relay.py``. These tests use fakes only and
need no database.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import icuhub.workers.main as worker_main
from icuhub.core.credentials import CredentialBroker
from icuhub.core.relay import RelayBatchResult
from icuhub.kit.types import SecretRef
from icuhub.settings import Settings
from icuhub.workers.main import _MAX_SECRET_BYTES, _open_relay_producer, _SystemSecrets, run_once, worker_loop


class _StopError(Exception):
    """Sentinel that ends an otherwise endless worker loop from inside a fake."""


class FakeKafka:
    created: list[FakeKafka] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.started = False
        self.stopped = False
        FakeKafka.created.append(self)

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    async def send_and_wait(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("relay wiring tests must not publish")


class FakeRelay:
    instances: list[FakeRelay] = []
    stop_after: int | None = None

    def __init__(self, *, engine: Any, producer: Any, batch_size: int) -> None:
        self.engine = engine
        self.producer = producer
        self.batch_size = batch_size
        self.calls = 0
        FakeRelay.instances.append(self)

    async def relay_batch(self) -> RelayBatchResult:
        self.calls += 1
        if FakeRelay.stop_after is not None and self.calls >= FakeRelay.stop_after:
            raise _StopError
        return RelayBatchResult(published=0, failed_event_id=None)


@pytest.fixture(autouse=True)
def _fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeKafka.created = []
    FakeRelay.instances = []
    FakeRelay.stop_after = None
    monkeypatch.setattr("icuhub.core.relay.AIOKafkaProducer", FakeKafka)
    monkeypatch.setattr(worker_main, "OutboxRelay", FakeRelay)
    monkeypatch.setattr(worker_main, "get_engine", lambda: object())

    async def _no_broker_resolve(self: CredentialBroker, *args: Any, **kwargs: Any) -> bytes:
        raise AssertionError("platform relay secrets must never reach CredentialBroker.resolve")

    monkeypatch.setattr(CredentialBroker, "resolve", _no_broker_resolve)


def _settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "kafka_bootstrap": "kafka.example:9093",
        "kafka_security": "plaintext",
        "kafka_ca_file": None,
        "kafka_sasl_mechanism": None,
        "kafka_sasl_username_ref": None,
        "kafka_sasl_password_ref": None,
        "relay_batch_size": 7,
    }
    values.update(overrides)
    # Duck-typed stand-in: the factory reads only these attributes, and Settings may require env.
    return cast(Settings, SimpleNamespace(**values))


def _sasl_settings(username: str, password: str) -> Settings:
    return _settings(
        kafka_security="sasl_ssl",
        kafka_sasl_mechanism="SCRAM-SHA-512",
        kafka_sasl_username_ref=SecretRef(ref=username),
        kafka_sasl_password_ref=SecretRef(ref=password),
    )


def _patch_loop_dependencies(monkeypatch: pytest.MonkeyPatch, settings: SimpleNamespace, claim: Any) -> None:
    async def _schedule() -> int:
        return 0

    async def _recover() -> None:
        return None

    monkeypatch.setattr(worker_main, "get_services", lambda: SimpleNamespace(settings=settings))
    monkeypatch.setattr(worker_main, "scheduler_once", _schedule)
    monkeypatch.setattr(worker_main, "recover_expired", _recover)
    monkeypatch.setattr(worker_main, "claim", claim)


# ---------------------------------------------------------------- factory: protocol and TLS


def test_factory_ssl_applies_tls_without_sasl(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        producer = await _open_relay_producer(_settings(kafka_security="ssl"))
        kwargs = FakeKafka.created[0].kwargs
        assert kwargs["security_protocol"] == "SSL"
        assert isinstance(kwargs["ssl_context"], ssl.SSLContext)
        assert kwargs["sasl_plain_username"] is None
        assert kwargs["sasl_plain_password"] is None
        assert FakeKafka.created[0].started
        await producer.stop()

    asyncio.run(scenario())


def test_factory_plaintext_has_no_tls_and_no_secret_lookup() -> None:
    async def scenario() -> None:
        await _open_relay_producer(_settings(kafka_security="plaintext"))
        kwargs = FakeKafka.created[0].kwargs
        assert kwargs["security_protocol"] == "PLAINTEXT"
        assert kwargs["ssl_context"] is None
        assert kwargs["sasl_plain_username"] is None
        assert kwargs["sasl_plain_password"] is None

    asyncio.run(scenario())


def test_factory_ca_file_is_trusted_for_tls(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[dict[str, Any]] = []
    real_context = ssl.create_default_context

    def _record(**kwargs: Any) -> ssl.SSLContext:
        calls.append(kwargs)
        return real_context(purpose=ssl.Purpose.SERVER_AUTH)

    monkeypatch.setattr(worker_main.ssl, "create_default_context", _record)
    ca_file = tmp_path / "ca.pem"

    async def scenario() -> None:
        await _open_relay_producer(_settings(kafka_security="ssl", kafka_ca_file=ca_file))

    asyncio.run(scenario())
    assert calls == [{"cafile": str(ca_file)}]


# ---------------------------------------------------------------- factory: SASL_SSL


def test_factory_sasl_ssl_resolves_platform_env_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ICUHUB_TEST_KAFKA_USER", "relay-user")
    monkeypatch.setenv("ICUHUB_TEST_KAFKA_PASS", "relay-pass")

    async def scenario() -> None:
        await _open_relay_producer(_sasl_settings("env:ICUHUB_TEST_KAFKA_USER", "env:ICUHUB_TEST_KAFKA_PASS"))
        kwargs = FakeKafka.created[0].kwargs
        assert kwargs["security_protocol"] == "SASL_SSL"
        assert kwargs["sasl_mechanism"] == "SCRAM-SHA-512"
        assert kwargs["sasl_plain_username"] == "relay-user"
        assert kwargs["sasl_plain_password"] == "relay-pass"
        assert isinstance(kwargs["ssl_context"], ssl.SSLContext)
        assert FakeKafka.created[0].started

    asyncio.run(scenario())


def test_factory_sasl_ssl_resolves_mounted_file_secrets(tmp_path: Path) -> None:
    user_file = tmp_path / "user"
    pass_file = tmp_path / "pass"
    user_file.write_bytes(b"mounted-user\r\n")
    pass_file.write_bytes(b"mounted-pass")

    async def scenario() -> None:
        await _open_relay_producer(
            _sasl_settings(f"file:{user_file.as_posix()}", f"file:{pass_file.as_posix()}")
        )
        kwargs = FakeKafka.created[0].kwargs
        assert kwargs["sasl_plain_username"] == "mounted-user"
        assert kwargs["sasl_plain_password"] == "mounted-pass"

    asyncio.run(scenario())


def test_factory_sasl_ssl_rejects_missing_refs_before_producer_exists() -> None:
    async def scenario() -> None:
        settings = _settings(kafka_security="sasl_ssl", kafka_sasl_mechanism="SCRAM-SHA-512")
        with pytest.raises(ValueError, match="SASL"):
            await _open_relay_producer(settings)

    asyncio.run(scenario())
    assert FakeKafka.created == []


def test_factory_sasl_ssl_unsupported_ref_fails_before_broker_start() -> None:
    async def scenario() -> None:
        with pytest.raises(ValueError, match="unsupported platform secret reference"):
            await _open_relay_producer(_sasl_settings("cred:6f1c0e2a", "env:ICUHUB_TEST_KAFKA_PASS"))

    asyncio.run(scenario())
    assert FakeKafka.created == []


def test_factory_rejects_missing_bootstrap_visibly() -> None:
    async def scenario() -> None:
        with pytest.raises(RuntimeError, match="ICUHUB_KAFKA_BOOTSTRAP"):
            await _open_relay_producer(_settings(kafka_bootstrap=None))

    asyncio.run(scenario())
    assert FakeKafka.created == []


# ---------------------------------------------------------------- system secret resolver


def test_env_ref_resolves_to_utf8_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ICUHUB_TEST_SECRET", "s3cret-value")

    async def scenario() -> bytes:
        return await _SystemSecrets().resolve(SecretRef(ref="env:ICUHUB_TEST_SECRET"))

    assert asyncio.run(scenario()) == b"s3cret-value"


@pytest.mark.parametrize("ref", ["env:1BAD", "env:HAS-DASH", "env:", "env:A B"])
def test_env_ref_rejects_malformed_names(ref: str) -> None:
    async def scenario() -> None:
        await _SystemSecrets().resolve(SecretRef(ref=ref))

    with pytest.raises(ValueError, match="malformed environment secret reference"):
        asyncio.run(scenario())


def test_env_ref_rejects_unset_and_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ICUHUB_TEST_UNSET", raising=False)
    monkeypatch.setenv("ICUHUB_TEST_EMPTY", "")

    for ref in ("env:ICUHUB_TEST_UNSET", "env:ICUHUB_TEST_EMPTY"):
        with pytest.raises(ValueError, match="unset or empty"):
            asyncio.run(_SystemSecrets().resolve(SecretRef(ref=ref)))


def test_env_ref_rejects_oversized_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker_main, "_MAX_SECRET_BYTES", 32)
    monkeypatch.setenv("ICUHUB_TEST_BIG", "x" * 33)
    with pytest.raises(ValueError, match="exceeds"):
        asyncio.run(_SystemSecrets().resolve(SecretRef(ref="env:ICUHUB_TEST_BIG")))


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"value\r\n", b"value"),  # CRLF
        (b"value\n", b"value"),  # bare LF, the Kubernetes Secret default
        (b"value\r", b"value"),  # bare CR
        (b"value", b"value"),  # no terminator
        (b"value\n\n", b"value\n"),  # exactly one line ending removed, the second is kept
        (b"value\r\n\r\n", b"value\r\n"),  # exactly one CRLF removed
        (b"value  \n", b"value  "),  # other whitespace is never stripped
    ],
)
def test_file_ref_strips_exactly_one_trailing_line_ending(tmp_path: Path, content: bytes, expected: bytes) -> None:
    secret = tmp_path / "secret"
    secret.write_bytes(content)

    resolved = asyncio.run(_SystemSecrets().resolve(SecretRef(ref=f"file:{secret.as_posix()}")))

    assert resolved == expected


def test_file_ref_rejects_content_that_is_only_a_line_ending(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_bytes(b"\n")

    with pytest.raises(ValueError, match="empty"):
        asyncio.run(_SystemSecrets().resolve(SecretRef(ref=f"file:{secret.as_posix()}")))


def test_file_ref_accepts_exact_limit_and_rejects_one_byte_over(tmp_path: Path) -> None:
    at_limit = tmp_path / "at_limit"
    at_limit.write_bytes(b"x" * _MAX_SECRET_BYTES)
    over = tmp_path / "over"
    over.write_bytes(b"x" * (_MAX_SECRET_BYTES + 1))
    resolver = _SystemSecrets()

    assert len(asyncio.run(resolver.resolve(SecretRef(ref=f"file:{at_limit.as_posix()}")))) == _MAX_SECRET_BYTES
    with pytest.raises(ValueError, match="exceeds"):
        asyncio.run(resolver.resolve(SecretRef(ref=f"file:{over.as_posix()}")))


def test_file_ref_rejects_missing_empty_and_relative(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.write_bytes(b"\r\n")
    resolver = _SystemSecrets()

    with pytest.raises(ValueError, match="unreadable"):
        asyncio.run(resolver.resolve(SecretRef(ref=f"file:{(tmp_path / 'absent').as_posix()}")))
    with pytest.raises(ValueError, match="empty"):
        asyncio.run(resolver.resolve(SecretRef(ref=f"file:{empty.as_posix()}")))
    with pytest.raises(ValueError, match="absolute path"):
        asyncio.run(resolver.resolve(SecretRef(ref="file:relative/secret")))


@pytest.mark.parametrize("ref", ["cred:6f1c0e2a", "vault:kafka/pass", "plain-value"])
def test_unsupported_scheme_is_rejected(ref: str) -> None:
    with pytest.raises(ValueError, match="unsupported platform secret reference"):
        asyncio.run(_SystemSecrets().resolve(SecretRef(ref=ref)))


# ---------------------------------------------------------------- run_once


def test_run_once_relay_opens_producer_relays_once_and_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    claimed: list[Any] = []

    async def _claim(*args: Any, **kwargs: Any) -> None:
        claimed.append(args)
        return None

    _patch_loop_dependencies(monkeypatch, _settings(), _claim)

    processed = asyncio.run(run_once(queues=("sync",), max_jobs=3, relay=True))

    assert processed == 0
    assert len(FakeRelay.instances) == 1
    assert FakeRelay.instances[0].calls == 1
    assert FakeRelay.instances[0].batch_size == 7
    assert FakeKafka.created[0].started and FakeKafka.created[0].stopped


def test_run_once_relay_without_bootstrap_raises_before_claiming(monkeypatch: pytest.MonkeyPatch) -> None:
    claimed: list[Any] = []

    async def _claim(*args: Any, **kwargs: Any) -> None:
        claimed.append(args)
        return None

    _patch_loop_dependencies(monkeypatch, _settings(kafka_bootstrap=None), _claim)

    with pytest.raises(RuntimeError, match="ICUHUB_KAFKA_BOOTSTRAP"):
        asyncio.run(run_once(queues=("sync",), max_jobs=3, relay=True))
    assert claimed == []
    assert FakeKafka.created == []


# ---------------------------------------------------------------- worker_loop


def test_worker_loop_relays_every_pass_and_stops_producer_once(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _claim(*args: Any, **kwargs: Any) -> None:
        return None

    _patch_loop_dependencies(monkeypatch, _settings(), _claim)
    FakeRelay.stop_after = 3

    with pytest.raises(_StopError):
        asyncio.run(worker_loop(queues=("sync",), idle_s=0, relay=True))

    assert FakeRelay.instances[0].calls == 3
    assert len(FakeKafka.created) == 1
    assert FakeKafka.created[0].started
    assert FakeKafka.created[0].stopped


def test_worker_loop_without_relay_builds_no_producer(monkeypatch: pytest.MonkeyPatch) -> None:
    passes = 0

    async def _claim(*args: Any, **kwargs: Any) -> None:
        nonlocal passes
        passes += 1
        if passes == 2:
            raise _StopError
        return None

    _patch_loop_dependencies(monkeypatch, _settings(), _claim)

    with pytest.raises(_StopError):
        asyncio.run(worker_loop(queues=("sync",), idle_s=0, relay=False))

    assert FakeKafka.created == []
    assert FakeRelay.instances == []


def test_worker_loop_cancellation_stops_producer(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        first_pass = asyncio.Event()

        async def _claim(*args: Any, **kwargs: Any) -> None:
            first_pass.set()
            return None

        _patch_loop_dependencies(monkeypatch, _settings(), _claim)
        task = asyncio.create_task(worker_loop(queues=("sync",), idle_s=0, relay=True))
        await asyncio.wait_for(first_pass.wait(), timeout=5)
        await asyncio.sleep(0)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        assert FakeKafka.created[0].stopped

    asyncio.run(scenario())


def test_worker_loop_relay_with_bad_bootstrap_fails_visibly(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _claim(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("claim must not run when relay cannot start")

    _patch_loop_dependencies(monkeypatch, _settings(kafka_bootstrap=""), _claim)

    with pytest.raises(RuntimeError, match="ICUHUB_KAFKA_BOOTSTRAP"):
        asyncio.run(worker_loop(queues=("sync",), idle_s=0, relay=True))
    assert FakeKafka.created == []
