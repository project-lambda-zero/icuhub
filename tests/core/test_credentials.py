"""Behavioral tests for envelope-encrypted credentials (ADR-0006). Each async scenario runs through asyncio.run."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, NamedTuple

import httpx2
import pytest

from icuhub.core.credentials import (
    CredentialBroker,
    CredentialDecryptionError,
    CredentialNotFound,
    FileKek,
    KekConfigurationError,
    KekOperationError,
    OpenBaoTransitKek,
)
from icuhub.kit.types import SecretRef
from icuhub.storage.db import admin_session, create_engine
from icuhub.storage.models import Credential, Tenant

_POSIX = os.name == "posix"
_VAULT_BASE = "https://vault.example.test"
_VAULT_TOKEN = "vault-token-value"
_VAULT_PREFIX = "vault:v1:"
Handler = Callable[[httpx2.Request], httpx2.Response]


class _Snapshot(NamedTuple):
    kek_id: str
    dek_wrapped: bytes
    nonce: bytes
    ciphertext: bytes
    rotated_at: datetime | None


def _write_key(directory: Path, key: bytes | None = None) -> Path:
    path = directory / "kek.bin"
    path.write_bytes(os.urandom(32) if key is None else key)
    if _POSIX:
        path.chmod(0o600)
    return path


def _write_token(directory: Path, token: str = _VAULT_TOKEN) -> Path:
    path = directory / "vault-token"
    path.write_text(f"{token}\n", encoding="utf-8")
    return path


def _flip_last_byte(data: bytes) -> bytes:
    return data[:-1] + bytes((data[-1] ^ 0x01,))


def _credential_id(ref: SecretRef) -> uuid.UUID:
    return uuid.UUID(ref.ref.removeprefix("cred:"))


async def _tenant() -> uuid.UUID:
    tenant_id = uuid.uuid4()
    async with admin_session() as session:
        session.add(Tenant(id=tenant_id, slug=f"cred-{tenant_id.hex[:12]}", display_name="credentials"))
    return tenant_id


@asynccontextmanager
async def _app_broker(app_database_url: str, key_path: Path) -> AsyncIterator[CredentialBroker]:
    engine = create_engine(app_database_url)
    try:
        yield CredentialBroker(FileKek(key_path), engine=engine)
    finally:
        await engine.dispose()


async def _snapshot(credential_id: uuid.UUID) -> _Snapshot:
    async with admin_session() as session:
        row = await session.get(Credential, credential_id)
        assert row is not None
        return _Snapshot(row.kek_id, row.dek_wrapped, row.nonce, row.ciphertext, row.rotated_at)


async def _set_columns(credential_id: uuid.UUID, **columns: Any) -> None:
    async with admin_session() as session:
        row = await session.get(Credential, credential_id)
        assert row is not None
        for name, value in columns.items():
            setattr(row, name, value)


# File KEK


def test_file_kek_round_trips_data_key(tmp_path: Path) -> None:
    async def scenario() -> None:
        kek = FileKek(_write_key(tmp_path))
        tenant_id = uuid.uuid4()
        dek = os.urandom(32)
        wrapped = await kek.wrap(dek, tenant_id=tenant_id, aad=b"bound")
        assert await kek.unwrap(wrapped, tenant_id=tenant_id, kek_id=kek.kek_id(tenant_id), aad=b"bound") == dek

    asyncio.run(scenario())


def test_file_kek_rejects_wrapping_data_key_of_wrong_length(tmp_path: Path) -> None:
    async def scenario() -> None:
        kek = FileKek(_write_key(tmp_path))
        with pytest.raises(ValueError):
            await kek.wrap(b"short", tenant_id=uuid.uuid4(), aad=b"bound")

    asyncio.run(scenario())


def test_file_kek_rejects_key_file_of_wrong_length(tmp_path: Path) -> None:
    with pytest.raises(KekConfigurationError):
        FileKek(_write_key(tmp_path, os.urandom(31)))


@pytest.mark.skipif(not _POSIX, reason="file mode bits are only enforced on POSIX")
@pytest.mark.parametrize("mode", [0o640, 0o604])
def test_file_kek_rejects_group_or_world_readable_key(tmp_path: Path, mode: int) -> None:
    path = _write_key(tmp_path)
    path.chmod(mode)
    with pytest.raises(KekConfigurationError):
        FileKek(path)


def test_file_kek_rejects_wrong_aad_truncation_tampering_and_unknown_kek(tmp_path: Path) -> None:
    async def scenario() -> None:
        kek = FileKek(_write_key(tmp_path))
        tenant_id = uuid.uuid4()
        kek_id = kek.kek_id(tenant_id)
        wrapped = await kek.wrap(os.urandom(32), tenant_id=tenant_id, aad=b"bound")
        with pytest.raises(KekOperationError):
            await kek.unwrap(wrapped, tenant_id=tenant_id, kek_id=kek_id, aad=b"other")
        with pytest.raises(KekOperationError):
            await kek.unwrap(_flip_last_byte(wrapped), tenant_id=tenant_id, kek_id=kek_id, aad=b"bound")
        with pytest.raises(KekOperationError):
            await kek.unwrap(wrapped[:-1], tenant_id=tenant_id, kek_id=kek_id, aad=b"bound")
        with pytest.raises(KekOperationError):
            await kek.unwrap(wrapped, tenant_id=tenant_id, kek_id="file-sha256:" + "0" * 64, aad=b"bound")

    asyncio.run(scenario())


# OpenBao Transit KEK


class _FakeTransit:
    """Transit double that binds associated data to each ciphertext the way OpenBao does."""

    def __init__(self) -> None:
        self.requests: list[httpx2.Request] = []
        self._associated_data: dict[str, str] = {}

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        body = json.loads(request.content)
        if request.url.path.startswith("/v1/transit/encrypt/"):
            ciphertext = _VAULT_PREFIX + body["plaintext"]
            self._associated_data[ciphertext] = body["associated_data"]
            return httpx2.Response(200, json={"data": {"ciphertext": ciphertext}})
        if request.url.path.startswith("/v1/transit/decrypt/"):
            ciphertext = body["ciphertext"]
            if self._associated_data.get(ciphertext) != body["associated_data"]:
                return httpx2.Response(400, json={"errors": ["unable to decrypt"]})
            return httpx2.Response(200, json={"data": {"plaintext": ciphertext.removeprefix(_VAULT_PREFIX)}})
        return httpx2.Response(404, json={"errors": []})


def _openbao(directory: Path, handler: Handler, **kwargs: Any) -> OpenBaoTransitKek:
    return OpenBaoTransitKek(
        _VAULT_BASE,
        _write_token(directory),
        transport=httpx2.MockTransport(handler),
        **kwargs,
    )


async def _wrap_failure(directory: Path, handler: Handler) -> KekOperationError:
    kek = _openbao(directory, handler)
    try:
        with pytest.raises(KekOperationError) as excinfo:
            await kek.wrap(os.urandom(32), tenant_id=uuid.uuid4(), aad=b"aad")
        return excinfo.value
    finally:
        await kek.close()


def test_openbao_wrap_and_unwrap_send_transit_requests(tmp_path: Path) -> None:
    async def scenario() -> None:
        transit = _FakeTransit()
        kek = _openbao(tmp_path, transit.handle)
        tenant_id = uuid.uuid4()
        kek_id = kek.kek_id(tenant_id)
        dek = os.urandom(32)
        aad = b"aad-bytes"
        try:
            wrapped = await kek.wrap(dek, tenant_id=tenant_id, aad=aad)
            assert wrapped.startswith(_VAULT_PREFIX.encode("ascii"))
            assert kek_id == f"openbao:transit:icuhub-{tenant_id}"
            assert await kek.unwrap(wrapped, tenant_id=tenant_id, kek_id=kek_id, aad=aad) == dek
        finally:
            await kek.close()

        encrypt, decrypt = transit.requests
        expected_aad = base64.b64encode(aad).decode("ascii")
        assert str(encrypt.url) == f"{_VAULT_BASE}/v1/transit/encrypt/icuhub-{tenant_id}"
        assert str(decrypt.url) == f"{_VAULT_BASE}/v1/transit/decrypt/icuhub-{tenant_id}"
        assert encrypt.headers["X-Vault-Token"] == _VAULT_TOKEN
        assert decrypt.headers["X-Vault-Token"] == _VAULT_TOKEN
        encrypt_body = json.loads(encrypt.content)
        assert base64.b64decode(encrypt_body["plaintext"]) == dek
        assert encrypt_body["associated_data"] == expected_aad
        assert json.loads(decrypt.content)["associated_data"] == expected_aad

    asyncio.run(scenario())


def test_openbao_unwrap_rejects_mismatched_associated_data_and_unknown_kek(tmp_path: Path) -> None:
    async def scenario() -> None:
        transit = _FakeTransit()
        kek = _openbao(tmp_path, transit.handle)
        tenant_id = uuid.uuid4()
        kek_id = kek.kek_id(tenant_id)
        dek = os.urandom(32)
        try:
            wrapped = await kek.wrap(dek, tenant_id=tenant_id, aad=b"bound")
            with pytest.raises(KekOperationError):
                await kek.unwrap(wrapped, tenant_id=tenant_id, kek_id=kek_id, aad=b"other")
            with pytest.raises(KekOperationError):
                await kek.unwrap(wrapped, tenant_id=tenant_id, kek_id="openbao:transit:other", aad=b"bound")
            assert len(transit.requests) == 2
            assert await kek.unwrap(wrapped, tenant_id=tenant_id, kek_id=kek_id, aad=b"bound") == dek
        finally:
            await kek.close()

    asyncio.run(scenario())


def test_openbao_maps_transport_timeout(tmp_path: Path) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.TimeoutException("upstream timed out")

    error = asyncio.run(_wrap_failure(tmp_path, handler))
    assert str(error) == "OpenBao transit request timed out"


def test_openbao_maps_transport_failure(tmp_path: Path) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.RequestError("connection refused")

    error = asyncio.run(_wrap_failure(tmp_path, handler))
    assert str(error) == "OpenBao transit request failed"


def test_openbao_maps_http_error_without_leaking_token(tmp_path: Path) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(403, json={"errors": [f"permission denied for {_VAULT_TOKEN}"]})

    error = asyncio.run(_wrap_failure(tmp_path, handler))
    assert str(error) == "OpenBao transit returned HTTP 403"
    assert _VAULT_TOKEN not in str(error)


def test_openbao_maps_invalid_json(tmp_path: Path) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, content=b"<html>not json</html>")

    error = asyncio.run(_wrap_failure(tmp_path, handler))
    assert str(error) == "OpenBao transit returned invalid JSON"


def test_openbao_maps_response_without_data(tmp_path: Path) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"warnings": None})

    error = asyncio.run(_wrap_failure(tmp_path, handler))
    assert str(error) == "OpenBao transit response is missing data"


@pytest.mark.parametrize(
    "base_url",
    [
        "http://vault.example.test",
        "https://user:pw@vault.example.test",
        "https://vault.example.test/?x=1",
        "https://vault.example.test/#frag",
        "https:///v1",
    ],
)
def test_openbao_requires_https_base_url_without_credentials(tmp_path: Path, base_url: str) -> None:
    with pytest.raises(KekConfigurationError):
        OpenBaoTransitKek(base_url, _write_token(tmp_path))


@pytest.mark.parametrize(
    "template",
    [
        "icuhub",
        "icuhub-{tenant_id}-{other}",
        "icuhub-{}",
        "icuhub-{tenant_id!r}",
        "icuhub-{tenant_id:>36}",
        "icuhub-{tenant_id",
    ],
)
def test_openbao_key_name_template_allows_only_tenant_placeholder(tmp_path: Path, template: str) -> None:
    with pytest.raises(KekConfigurationError):
        OpenBaoTransitKek(_VAULT_BASE, _write_token(tmp_path), key_name_template=template)


@pytest.mark.parametrize("mount_path", ["", "transit/../sys"])
def test_openbao_rejects_invalid_mount_path(tmp_path: Path, mount_path: str) -> None:
    with pytest.raises(KekConfigurationError):
        OpenBaoTransitKek(_VAULT_BASE, _write_token(tmp_path), mount_path=mount_path)


@pytest.mark.parametrize("timeout_s", [0.0, -1.0, float("nan"), float("inf")])
def test_openbao_rejects_non_positive_or_non_finite_timeout(tmp_path: Path, timeout_s: float) -> None:
    with pytest.raises(KekConfigurationError):
        OpenBaoTransitKek(_VAULT_BASE, _write_token(tmp_path), timeout_s=timeout_s)


def test_openbao_rejects_empty_or_missing_token_file(tmp_path: Path) -> None:
    with pytest.raises(KekConfigurationError):
        OpenBaoTransitKek(_VAULT_BASE, _write_token(tmp_path, "   "))
    with pytest.raises(KekConfigurationError):
        OpenBaoTransitKek(_VAULT_BASE, tmp_path / "missing-token")


def test_openbao_rejects_wrapping_data_key_of_wrong_length_before_network(tmp_path: Path) -> None:
    async def scenario() -> None:
        transit = _FakeTransit()
        kek = _openbao(tmp_path, transit.handle)
        try:
            with pytest.raises(ValueError):
                await kek.wrap(b"short", tenant_id=uuid.uuid4(), aad=b"aad")
            assert transit.requests == []
        finally:
            await kek.close()

    asyncio.run(scenario())


# Credential broker (database)


@pytest.mark.usefixtures("clean_database")
def test_store_then_resolve_round_trips_secret(tmp_path: Path, app_database_url: str) -> None:
    async def scenario() -> None:
        tenant_id = await _tenant()
        async with _app_broker(app_database_url, _write_key(tmp_path)) as broker:
            ref = await broker.store(tenant_id, "partner-token", b"s3cr3t")
            assert ref.ref.startswith("cred:")
            assert await broker.resolve(tenant_id, ref) == b"s3cr3t"

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_rotate_keeps_reference_and_replaces_stored_material(tmp_path: Path, app_database_url: str) -> None:
    async def scenario() -> None:
        tenant_id = await _tenant()
        async with _app_broker(app_database_url, _write_key(tmp_path)) as broker:
            ref = await broker.store(tenant_id, "db-password", b"old-secret")
            credential_id = _credential_id(ref)
            before = await _snapshot(credential_id)

            rotated_ref = await broker.rotate(tenant_id, ref, b"new-secret")

            assert rotated_ref == ref
            assert await broker.resolve(tenant_id, ref) == b"new-secret"
            after = await _snapshot(credential_id)
            assert after.dek_wrapped != before.dek_wrapped
            assert after.nonce != before.nonce
            assert after.ciphertext != before.ciphertext
            assert before.rotated_at is None
            assert after.rotated_at is not None

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_wrong_tenant_cannot_resolve_or_rotate(tmp_path: Path, app_database_url: str) -> None:
    async def scenario() -> None:
        owner = await _tenant()
        other = await _tenant()
        async with _app_broker(app_database_url, _write_key(tmp_path)) as broker:
            ref = await broker.store(owner, "api-key", b"owner-only")
            with pytest.raises(CredentialNotFound):
                await broker.resolve(other, ref)
            with pytest.raises(CredentialNotFound):
                await broker.rotate(other, ref, b"hijacked")
            assert await broker.resolve(owner, ref) == b"owner-only"

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
@pytest.mark.parametrize("raw_ref", ["cred:not-a-uuid", "cred:", "vault:1"])
def test_malformed_reference_is_not_found(tmp_path: Path, app_database_url: str, raw_ref: str) -> None:
    async def scenario() -> None:
        tenant_id = await _tenant()
        async with _app_broker(app_database_url, _write_key(tmp_path)) as broker:
            with pytest.raises(CredentialNotFound):
                await broker.resolve(tenant_id, SecretRef(ref=raw_ref))

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_unknown_credential_is_not_found(tmp_path: Path, app_database_url: str) -> None:
    async def scenario() -> None:
        tenant_id = await _tenant()
        async with _app_broker(app_database_url, _write_key(tmp_path)) as broker:
            with pytest.raises(CredentialNotFound):
                await broker.resolve(tenant_id, SecretRef(ref=f"cred:{uuid.uuid4()}"))

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_tampered_ciphertext_fails_closed(tmp_path: Path, app_database_url: str) -> None:
    async def scenario() -> None:
        tenant_id = await _tenant()
        async with _app_broker(app_database_url, _write_key(tmp_path)) as broker:
            ref = await broker.store(tenant_id, "api-key", b"value")
            credential_id = _credential_id(ref)
            current = await _snapshot(credential_id)
            await _set_columns(credential_id, ciphertext=_flip_last_byte(current.ciphertext))
            with pytest.raises(CredentialDecryptionError):
                await broker.resolve(tenant_id, ref)

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_tampered_kek_identifier_fails_closed(tmp_path: Path, app_database_url: str) -> None:
    async def scenario() -> None:
        tenant_id = await _tenant()
        async with _app_broker(app_database_url, _write_key(tmp_path)) as broker:
            ref = await broker.store(tenant_id, "api-key", b"value")
            await _set_columns(_credential_id(ref), kek_id="file-sha256:" + "0" * 64)
            with pytest.raises(KekOperationError):
                await broker.resolve(tenant_id, ref)

    asyncio.run(scenario())


# Raw payload encryption (no database)


def test_blob_round_trip_compresses_and_binds_object_identity(tmp_path: Path) -> None:
    async def scenario() -> None:
        broker = CredentialBroker(FileKek(_write_key(tmp_path)))
        tenant_id = uuid.uuid4()
        object_id = uuid.uuid4()
        payload = b'{"event":"login","result":"ok"}' * 500

        blob = await broker.encrypt_blob(tenant_id, object_id, payload)

        assert await broker.decrypt_blob(tenant_id, object_id, blob) == payload
        assert len(blob.ciphertext) < len(payload)
        with pytest.raises(KekOperationError):
            await broker.decrypt_blob(tenant_id, uuid.uuid4(), blob)
        with pytest.raises(KekOperationError):
            await broker.decrypt_blob(uuid.uuid4(), object_id, blob)

    asyncio.run(scenario())


def test_blob_ciphertext_tampering_fails_closed(tmp_path: Path) -> None:
    async def scenario() -> None:
        broker = CredentialBroker(FileKek(_write_key(tmp_path)))
        tenant_id = uuid.uuid4()
        object_id = uuid.uuid4()
        blob = await broker.encrypt_blob(tenant_id, object_id, b"raw payload bytes")

        tampered = replace(blob, ciphertext=_flip_last_byte(blob.ciphertext))
        with pytest.raises(CredentialDecryptionError):
            await broker.decrypt_blob(tenant_id, object_id, tampered)

    asyncio.run(scenario())
