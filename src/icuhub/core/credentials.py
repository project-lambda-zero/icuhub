"""Envelope-encrypted credentials and raw payload encryption (ADR-0006)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import stat
import string
import uuid
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

import httpx2
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from icuhub.kit.types import SecretRef
from icuhub.storage.db import session_scope
from icuhub.storage.models import Credential

__all__ = [
    "CredentialBroker",
    "broker_from_settings",
    "CredentialDecryptionError",
    "CredentialError",
    "CredentialNotFound",
    "EncryptedBlob",
    "FileKek",
    "KekConfigurationError",
    "KekError",
    "KekOperationError",
    "KekProvider",
    "OpenBaoTransitKek",
]

_DEK_BYTES = 32
_NONCE_BYTES = 12
_FILE_WRAP_VERSION = 1
_CREDENTIAL_FIELD = b"credential.secret"
_RAW_BATCH_FIELD = b"raw_batch.payload"


class CredentialError(Exception):
    """Base class for credential storage failures."""


class CredentialNotFound(CredentialError):  # noqa: N818  # name pinned by tests/core/test_credentials.py
    """The requested credential does not exist in the caller's tenant."""


class CredentialDecryptionError(CredentialError):
    """Encrypted credential or payload data failed validation or authentication."""


class KekError(CredentialError):
    """Base class for key-encryption-key failures."""


class KekConfigurationError(KekError):
    """A KEK provider is not configured safely."""


class KekOperationError(KekError):
    """A KEK provider could not wrap or unwrap a data key."""


class KekProvider(Protocol):
    """Asynchronous provider for wrapping 32-byte data encryption keys."""

    def kek_id(self, tenant_id: uuid.UUID) -> str:
        """Return the stable identifier stored beside wrapped data keys."""
        ...

    async def wrap(self, dek: bytes, *, tenant_id: uuid.UUID, aad: bytes) -> bytes:
        """Wrap a data key and bind it to the supplied associated data."""
        ...

    async def unwrap(self, wrapped_dek: bytes, *, tenant_id: uuid.UUID, kek_id: str, aad: bytes) -> bytes:
        """Authenticate and unwrap a data key."""
        ...


@dataclass(frozen=True, slots=True)
class EncryptedBlob:
    """Encrypted raw payload fields matching the raw_batch persistence columns."""

    kek_id: str
    dek_wrapped: bytes
    nonce: bytes
    ciphertext: bytes


def _require_dek(dek: bytes) -> None:
    if not isinstance(dek, bytes) or len(dek) != _DEK_BYTES:
        raise ValueError("Data encryption keys must be exactly 32 bytes")


def _associated_data(field: bytes, tenant_id: uuid.UUID, object_id: uuid.UUID, kek_id: str) -> bytes:
    parts = (b"icuhub", b"1", field, tenant_id.bytes, object_id.bytes, kek_id.encode("utf-8"))
    return b"".join(len(part).to_bytes(4, "big") + part for part in parts)


def _decrypt_aes(dek: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(dek).decrypt(nonce, ciphertext, aad)
    except (InvalidTag, ValueError) as exc:
        raise CredentialDecryptionError("Encrypted data authentication failed") from exc


class FileKek:
    """Development KEK loaded from an exactly 32-byte read-only file."""

    def __init__(self, path: str | Path, *, kek_id: str | None = None) -> None:
        key_path = Path(path)
        try:
            with key_path.open("rb") as key_file:
                if os.name == "posix":
                    mode = stat.S_IMODE(os.fstat(key_file.fileno()).st_mode)
                    if mode & (stat.S_IRGRP | stat.S_IROTH):
                        raise KekConfigurationError("File KEK must not be readable by group or other users")
                key = key_file.read()
        except KekConfigurationError:
            raise
        except OSError as exc:
            raise KekConfigurationError(f"Unable to read file KEK: {key_path}") from exc
        if len(key) != _DEK_BYTES:
            raise KekConfigurationError("File KEK must contain exactly 32 bytes")
        if kek_id is not None and (not kek_id or len(kek_id) > 200):
            raise KekConfigurationError("File KEK identifier must contain between 1 and 200 characters")
        self._key = key
        self._kek_id = kek_id or f"file-sha256:{hashlib.sha256(key).hexdigest()}"

    def kek_id(self, tenant_id: uuid.UUID) -> str:
        return self._kek_id

    async def wrap(self, dek: bytes, *, tenant_id: uuid.UUID, aad: bytes) -> bytes:
        _require_dek(dek)
        nonce = os.urandom(_NONCE_BYTES)
        wrapped = AESGCM(self._key).encrypt(nonce, dek, aad)
        return bytes((_FILE_WRAP_VERSION,)) + nonce + wrapped

    async def unwrap(self, wrapped_dek: bytes, *, tenant_id: uuid.UUID, kek_id: str, aad: bytes) -> bytes:
        if kek_id != self._kek_id:
            raise KekOperationError("Stored credential uses an unknown file KEK")
        minimum_length = 1 + _NONCE_BYTES + 16 + _DEK_BYTES
        if len(wrapped_dek) < minimum_length or wrapped_dek[0] != _FILE_WRAP_VERSION:
            raise KekOperationError("Wrapped data key has an invalid format")
        nonce = wrapped_dek[1 : 1 + _NONCE_BYTES]
        ciphertext = wrapped_dek[1 + _NONCE_BYTES :]
        try:
            dek = AESGCM(self._key).decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError) as exc:
            raise KekOperationError("Wrapped data key authentication failed") from exc
        if len(dek) != _DEK_BYTES:
            raise KekOperationError("Unwrapped data key has an invalid length")
        return dek


class OpenBaoTransitKek:
    """Minimal asynchronous OpenBao Transit KEK client."""

    def __init__(
        self,
        base_url: str,
        token_file: str | Path,
        *,
        key_name_template: str = "icuhub-{tenant_id}",
        mount_path: str = "transit",
        timeout_s: float = 10.0,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        parsed_url = urlsplit(base_url)
        if (
            parsed_url.scheme != "https"
            or not parsed_url.hostname
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise KekConfigurationError("OpenBao base URL must be an HTTPS URL without credentials, query, or fragment")
        normalized_mount = mount_path.strip("/")
        if not normalized_mount or any(part in {"", ".", ".."} for part in normalized_mount.split("/")):
            raise KekConfigurationError("OpenBao transit mount path is invalid")
        try:
            parsed = list(string.Formatter().parse(key_name_template))
        except ValueError as exc:
            raise KekConfigurationError("OpenBao key name template is invalid") from exc
        placeholders = [(field, spec, conversion) for _, field, spec, conversion in parsed if field is not None]
        if not placeholders or any(
            field != "tenant_id" or spec or conversion is not None for field, spec, conversion in placeholders
        ):
            raise KekConfigurationError("OpenBao key name template must use only the tenant_id placeholder")
        if not math.isfinite(timeout_s) or timeout_s <= 0:
            raise KekConfigurationError("OpenBao timeout must be a positive finite number")
        token_path = Path(token_file)
        try:
            token = token_path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as exc:
            raise KekConfigurationError(f"Unable to read OpenBao token file: {token_path}") from exc
        if not token:
            raise KekConfigurationError("OpenBao token file must not be empty")
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._key_name_template = key_name_template
        self._mount_path = normalized_mount
        self._client = httpx2.AsyncClient(
            timeout=httpx2.Timeout(timeout_s),
            verify=True,
            transport=transport,
        )

    def _key_name(self, tenant_id: uuid.UUID) -> str:
        return self._key_name_template.format(tenant_id=str(tenant_id))

    def kek_id(self, tenant_id: uuid.UUID) -> str:
        identifier = f"openbao:{self._mount_path}:{self._key_name(tenant_id)}"
        if len(identifier) > 200:
            raise KekConfigurationError("OpenBao KEK identifier exceeds the storage limit")
        return identifier

    def _operation_url(self, operation: str, tenant_id: uuid.UUID) -> str:
        mount = quote(self._mount_path, safe="/")
        key_name = quote(self._key_name(tenant_id), safe="")
        return f"{self._base_url}/v1/{mount}/{operation}/{key_name}"

    async def _post(self, operation: str, tenant_id: uuid.UUID, body: dict[str, str]) -> dict[str, object]:
        try:
            response = await self._client.post(
                self._operation_url(operation, tenant_id),
                json=body,
                headers={"X-Vault-Token": self._token},
            )
        except httpx2.TimeoutException as exc:
            raise KekOperationError("OpenBao transit request timed out") from exc
        except httpx2.RequestError as exc:
            raise KekOperationError("OpenBao transit request failed") from exc
        if response.status_code != 200:
            raise KekOperationError(f"OpenBao transit returned HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise KekOperationError("OpenBao transit returned invalid JSON") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
            raise KekOperationError("OpenBao transit response is missing data")
        return payload["data"]

    async def wrap(self, dek: bytes, *, tenant_id: uuid.UUID, aad: bytes) -> bytes:
        _require_dek(dek)
        data = await self._post(
            "encrypt",
            tenant_id,
            {
                "plaintext": base64.b64encode(dek).decode("ascii"),
                "associated_data": base64.b64encode(aad).decode("ascii"),
            },
        )
        ciphertext = data.get("ciphertext")
        if not isinstance(ciphertext, str) or not ciphertext:
            raise KekOperationError("OpenBao transit response is missing ciphertext")
        try:
            return ciphertext.encode("ascii")
        except UnicodeEncodeError as exc:
            raise KekOperationError("OpenBao transit ciphertext is not ASCII") from exc

    async def unwrap(self, wrapped_dek: bytes, *, tenant_id: uuid.UUID, kek_id: str, aad: bytes) -> bytes:
        if kek_id != self.kek_id(tenant_id):
            raise KekOperationError("Stored credential uses an unknown OpenBao KEK")
        try:
            ciphertext = wrapped_dek.decode("ascii")
        except UnicodeDecodeError as exc:
            raise KekOperationError("Wrapped data key is not an OpenBao ciphertext") from exc
        data = await self._post(
            "decrypt",
            tenant_id,
            {
                "ciphertext": ciphertext,
                "associated_data": base64.b64encode(aad).decode("ascii"),
            },
        )
        plaintext = data.get("plaintext")
        if not isinstance(plaintext, str) or not plaintext:
            raise KekOperationError("OpenBao transit response is missing plaintext")
        try:
            dek = base64.b64decode(plaintext, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise KekOperationError("OpenBao transit plaintext is not valid base64") from exc
        if len(dek) != _DEK_BYTES:
            raise KekOperationError("OpenBao transit returned an invalid data key length")
        return dek

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()


class CredentialBroker:
    """Stores and resolves tenant-scoped envelope-encrypted secrets."""

    def __init__(self, kek: KekProvider, *, engine: AsyncEngine | None = None) -> None:
        self._kek = kek
        self._engine = engine

    @staticmethod
    def _credential_id(ref: SecretRef) -> uuid.UUID:
        if not isinstance(ref, SecretRef) or not ref.ref.startswith("cred:"):
            raise CredentialNotFound("Credential not found")
        try:
            return uuid.UUID(ref.ref.removeprefix("cred:"))
        except ValueError as exc:
            raise CredentialNotFound("Credential not found") from exc

    @staticmethod
    def _reference(credential_id: uuid.UUID) -> SecretRef:
        return SecretRef(ref=f"cred:{credential_id}")

    async def store(
        self, tenant_id: uuid.UUID, name: str, secret: bytes, *, session: AsyncSession | None = None
    ) -> SecretRef:
        """Encrypt and persist a new secret, returning its opaque reference.

        When ``session`` is given the insert joins the caller's transaction (required
        when the tenant row itself is still uncommitted); otherwise a new tenant-scoped
        transaction is opened.
        """
        if not name.strip() or len(name) > 200:
            raise ValueError("Credential name must contain between 1 and 200 characters")
        if not isinstance(secret, bytes):
            raise TypeError("Credential secrets must be bytes")
        credential_id = uuid.uuid4()
        kek_id = self._kek.kek_id(tenant_id)
        aad = _associated_data(_CREDENTIAL_FIELD, tenant_id, credential_id, kek_id)
        dek = os.urandom(_DEK_BYTES)
        wrapped_dek = await self._kek.wrap(dek, tenant_id=tenant_id, aad=aad)
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCM(dek).encrypt(nonce, secret, aad)
        credential = Credential(
            id=credential_id,
            tenant_id=tenant_id,
            name=name,
            kek_id=kek_id,
            dek_wrapped=wrapped_dek,
            nonce=nonce,
            ciphertext=ciphertext,
            rotated_at=None,
        )
        if session is not None:
            session.add(credential)
            await session.flush()
        else:
            async with session_scope(tenant_id, engine=self._engine) as owned:
                owned.add(credential)
        return self._reference(credential_id)

    async def resolve(self, tenant_id: uuid.UUID, ref: SecretRef, *, session: AsyncSession | None = None) -> bytes:
        """Resolve a secret only when its reference belongs to the tenant."""
        credential_id = self._credential_id(ref)
        if session is not None:
            credential = await session.get(Credential, credential_id)
            if credential is None or credential.tenant_id != tenant_id:
                raise CredentialNotFound("Credential not found")
        else:
            async with session_scope(tenant_id, engine=self._engine) as owned:
                result = await owned.execute(
                    select(Credential).where(Credential.id == credential_id, Credential.tenant_id == tenant_id)
                )
                credential = result.scalar_one_or_none()
                if credential is None:
                    raise CredentialNotFound("Credential not found")
        kek_id = credential.kek_id
        wrapped_dek = credential.dek_wrapped
        nonce = credential.nonce
        ciphertext = credential.ciphertext
        aad = _associated_data(_CREDENTIAL_FIELD, tenant_id, credential_id, kek_id)
        dek = await self._kek.unwrap(wrapped_dek, tenant_id=tenant_id, kek_id=kek_id, aad=aad)
        return _decrypt_aes(dek, nonce, ciphertext, aad)

    async def rotate(self, tenant_id: uuid.UUID, ref: SecretRef, secret: bytes) -> SecretRef:
        """Replace a secret under the same reference with a fresh data key and nonce."""
        if not isinstance(secret, bytes):
            raise TypeError("Credential secrets must be bytes")
        credential_id = self._credential_id(ref)
        kek_id = self._kek.kek_id(tenant_id)
        aad = _associated_data(_CREDENTIAL_FIELD, tenant_id, credential_id, kek_id)
        dek = os.urandom(_DEK_BYTES)
        wrapped_dek = await self._kek.wrap(dek, tenant_id=tenant_id, aad=aad)
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCM(dek).encrypt(nonce, secret, aad)
        async with session_scope(tenant_id, engine=self._engine) as session:
            result = await session.execute(
                select(Credential)
                .where(Credential.id == credential_id, Credential.tenant_id == tenant_id)
                .with_for_update()
            )
            credential = result.scalar_one_or_none()
            if credential is None:
                raise CredentialNotFound("Credential not found")
            credential.kek_id = kek_id
            credential.dek_wrapped = wrapped_dek
            credential.nonce = nonce
            credential.ciphertext = ciphertext
            credential.rotated_at = datetime.now(UTC)
        return self._reference(credential_id)

    async def encrypt_blob(self, tenant_id: uuid.UUID, object_id: uuid.UUID, payload: bytes) -> EncryptedBlob:
        """Compress and encrypt a raw_batch payload for the supplied object identity."""
        if not isinstance(payload, bytes):
            raise TypeError("Raw payloads must be bytes")
        kek_id = self._kek.kek_id(tenant_id)
        aad = _associated_data(_RAW_BATCH_FIELD, tenant_id, object_id, kek_id)
        dek = os.urandom(_DEK_BYTES)
        wrapped_dek = await self._kek.wrap(dek, tenant_id=tenant_id, aad=aad)
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCM(dek).encrypt(nonce, zlib.compress(payload), aad)
        return EncryptedBlob(
            kek_id=kek_id,
            dek_wrapped=wrapped_dek,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    async def decrypt_blob(self, tenant_id: uuid.UUID, object_id: uuid.UUID, blob: EncryptedBlob) -> bytes:
        """Authenticate, decrypt, and decompress a raw_batch payload."""
        aad = _associated_data(_RAW_BATCH_FIELD, tenant_id, object_id, blob.kek_id)
        dek = await self._kek.unwrap(
            blob.dek_wrapped,
            tenant_id=tenant_id,
            kek_id=blob.kek_id,
            aad=aad,
        )
        compressed = _decrypt_aes(dek, blob.nonce, blob.ciphertext, aad)
        decompressor = zlib.decompressobj()
        try:
            payload = decompressor.decompress(compressed) + decompressor.flush()
        except zlib.error as exc:
            raise CredentialDecryptionError("Decrypted raw payload is not valid compressed data") from exc
        if not decompressor.eof or decompressor.unused_data:
            raise CredentialDecryptionError("Decrypted raw payload has an invalid compressed stream")
        return payload


def broker_from_settings(settings: Any, *, engine: AsyncEngine | None = None) -> CredentialBroker:
    """Build the credential broker from process settings (ADR-0006).

    ``file`` is the development provider and requires ``kek_file_path``; ``openbao``
    requires ``openbao_url``, ``openbao_token_file``, and uses ``openbao_transit_key``
    as an optional key-name template override.
    """
    if settings.kek_provider == "file":
        if settings.kek_file_path is None:
            raise KekConfigurationError("ICUHUB_KEK_FILE_PATH is required for the file KEK provider")
        kek: KekProvider = FileKek(settings.kek_file_path)
    else:
        if not settings.openbao_url or not settings.openbao_token_file:
            raise KekConfigurationError("OpenBao provider needs ICUHUB_OPENBAO_URL and ICUHUB_OPENBAO_TOKEN_FILE")
        kwargs: dict[str, Any] = {}
        if settings.openbao_transit_key:
            kwargs["key_name_template"] = settings.openbao_transit_key
        kek = OpenBaoTransitKek(settings.openbao_url, settings.openbao_token_file, **kwargs)
    return CredentialBroker(kek, engine=engine)
