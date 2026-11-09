"""Connector base class, runtime context, and declarative decorators.

Decorators attach a frozen spec object to the decorated function. ``Connector.__init_subclass__`` collects
those specs into a per-class registry and validates them at class creation, so an inconsistent connector
fails at import time rather than at the first sync.
"""

from __future__ import annotations

import inspect
import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar, Literal, Protocol

from pydantic import BaseModel

from icuhub.kit.errors import ConfigError
from icuhub.kit.types import ConnectorConfig, HealthReport, Scope, SecretRef, TargetRecord

if TYPE_CHECKING:
    from icuhub.kit.auth import AuthStrategy
    from icuhub.kit.http import VendorHttp
    from icuhub.kit.webhook import WebhookVerifier

__all__ = [
    "KNOWN_CAPABILITIES",
    "ActionDef",
    "ActionSpec",
    "Connector",
    "ConnectorContext",
    "ImporterSpec",
    "MapperSpec",
    "OperationSpec",
    "RedactingLoggerAdapter",
    "SecretRedactor",
    "SecretResolver",
    "StreamSpec",
    "WebhookSpec",
    "action",
    "build_context",
    "importer",
    "mapper",
    "operation",
    "stream",
    "webhook",
]

# HLD section 5.1 / ADR-0002 capability names.
KNOWN_CAPABILITIES: frozenset[str] = frozenset(
    {
        "SourceControl",
        "CodeScanningSink",
        "FindingSource",
        "TelemetrySource",
        "TelemetrySearch",
        "Enforcer",
        "Containment",
        "Tracker",
        "BuildSystem",
        "ClusterOps",
        "ThreatIntel",
        "RiskRegister",
        "VulnIntel",
        "SbomSink",
        "Directory",
        "Notifier",
        "KnowledgeBase",
    }
)

_SPEC_ATTR = "_ICUHUB_SPEC"
_REGISTRY_ATTR = "_icuhub_registry"
_MODES: frozenset[str] = frozenset({"incremental", "full"})
_STABILITIES: frozenset[str] = frozenset({"experimental", "beta", "stable"})
_EGRESS: frozenset[str] = frozenset({"internal", "vendor_tenant", "third_party_shared"})
_ACTION_CLASSES: frozenset[str] = frozenset({"write", "destructive"})
_IDEMPOTENCY: frozenset[str] = frozenset({"key", "natural_key", "none"})


class SecretResolver(Protocol):
    """Resolves an opaque secret reference to raw bytes (implemented by the credential broker)."""

    async def resolve(self, ref: SecretRef) -> bytes: ...


class SecretRedactor:
    """Holds every resolved secret value seen in this context and masks it in log text."""

    def __init__(self) -> None:
        self._values: set[str] = set()

    def add(self, value: bytes) -> None:
        text = value.decode("utf-8", errors="replace")
        if text:
            self._values.add(text)

    def redact(self, text: str) -> str:
        for value in sorted(self._values, key=len, reverse=True):
            text = text.replace(value, "********")
        return text


class _RegisteringResolver:
    """Wraps a resolver so every resolved value is registered with the redactor."""

    def __init__(self, inner: SecretResolver, redactor: SecretRedactor) -> None:
        self._inner = inner
        self._redactor = redactor

    async def resolve(self, ref: SecretRef) -> bytes:
        value = await self._inner.resolve(ref)
        self._redactor.add(value)
        return value


class RedactingLoggerAdapter(logging.LoggerAdapter):  # type: ignore[type-arg]
    """Logger adapter that formats the message and masks registered secret values before emitting."""

    def __init__(self, logger: logging.Logger, redactor: SecretRedactor) -> None:
        super().__init__(logger, {})
        self._redactor = redactor

    def log(self, level: int, msg: object, *args: object, **kwargs: Any) -> None:
        text = str(msg) % args if args else str(msg)
        if self.isEnabledFor(level):
            self.logger.log(level, self._redactor.redact(text), **kwargs)


@dataclass
class ConnectorContext:
    """Runtime services handed to a connector. ``http`` is attached after ``build_auth`` succeeds."""

    secrets: SecretResolver
    log: logging.LoggerAdapter  # type: ignore[type-arg]
    clock: Callable[[], datetime]
    connection_id: str
    tenant_id: str
    http: VendorHttp | None = None


def build_context(
    *,
    secrets: SecretResolver,
    clock: Callable[[], datetime],
    connection_id: str,
    tenant_id: str,
    logger: logging.Logger | None = None,
) -> ConnectorContext:
    """Build a context whose secret reads are registered for log redaction."""
    redactor = SecretRedactor()
    return ConnectorContext(
        secrets=_RegisteringResolver(secrets, redactor),
        log=RedactingLoggerAdapter(logger or logging.getLogger("icuhub.connector"), redactor),
        clock=clock,
        connection_id=connection_id,
        tenant_id=tenant_id,
    )


# ---------------------------------------------------------------------------
# Spec objects (frozen; attached to decorated functions)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StreamSpec:
    name: str
    fn: Callable[..., Any]
    cursor: type[BaseModel]
    modes: tuple[str, ...]
    capability: str
    stability: str
    ocsf_class: int | None
    record_type: str | None
    requires_target: bool


@dataclass(frozen=True)
class MapperSpec:
    stream: str
    version: int
    fn: Callable[..., Any]


@dataclass(frozen=True)
class OperationSpec:
    name: str
    fn: Callable[..., Any]
    capability: str | None
    classification: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    egress_class: str


@dataclass(frozen=True)
class ActionSpec:
    name: str
    plan: Callable[..., Any]
    apply: Callable[..., Any]
    reconcile: Callable[..., Any] | None
    capability: str
    classification: str
    input_model: type[BaseModel]
    idempotency: str
    stability: str


@dataclass(frozen=True)
class WebhookSpec:
    event_types: tuple[str, ...]
    header_event: str | None
    fn: Callable[..., Any]


@dataclass(frozen=True)
class ImporterSpec:
    name: str
    fn: Callable[..., Any]
    stream: str
    media_types: tuple[str, ...]
    extensions: tuple[str, ...]


def _attach(fn: Callable[..., Any], spec: object) -> Callable[..., Any]:
    if hasattr(fn, _SPEC_ATTR):
        raise TypeError(f"{fn.__qualname__}: only one icuhub decorator may be applied to a function")
    setattr(fn, _SPEC_ATTR, spec)
    return fn


def stream(
    name: str,
    *,
    cursor: type[BaseModel],
    capability: str,
    ocsf_class: int | None = None,
    record_type: str | None = None,
    modes: tuple[str, ...] = ("incremental", "full"),
    stability: str = "beta",
    requires_target: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Declare a data stream: an async generator yielding ``RawBatch`` objects."""

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        return _attach(
            fn,
            StreamSpec(
                name=name,
                fn=fn,
                cursor=cursor,
                modes=tuple(modes),
                capability=capability,
                stability=stability,
                ocsf_class=ocsf_class,
                record_type=record_type,
                requires_target=requires_target,
            ),
        )

    return decorate


def mapper(stream_name: str, version: int) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Declare the pure mapper for a stream: raw dict to OCSF events or source records."""

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        return _attach(fn, MapperSpec(stream=stream_name, version=version, fn=fn))

    return decorate


def operation(
    name: str,
    *,
    input_model: type[BaseModel],
    output_model: type[BaseModel],
    classification: str = "read",
    capability: str | None = None,
    egress_class: str = "vendor_tenant",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Declare a read-only operation with typed input and output."""

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        return _attach(
            fn,
            OperationSpec(
                name=name,
                fn=fn,
                capability=capability,
                classification=classification,
                input_model=input_model,
                output_model=output_model,
                egress_class=egress_class,
            ),
        )

    return decorate


class ActionDef:
    """Descriptor produced by ``@action``. Holds the plan function and optional apply/reconcile."""

    def __init__(
        self,
        *,
        name: str,
        plan_fn: Callable[..., Any],
        classification: str,
        capability: str,
        input_model: type[BaseModel],
        idempotency: str,
        stability: str,
    ) -> None:
        self.name = name
        self.plan_fn = plan_fn
        self.classification = classification
        self.capability = capability
        self.input_model = input_model
        self.idempotency = idempotency
        self.stability = stability
        self.apply_fn: Callable[..., Any] | None = None
        self.reconcile_fn: Callable[..., Any] | None = None

    def apply(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Register the apply function. Returns it unchanged so it stays a plain method."""
        if self.apply_fn is not None:
            raise TypeError(f"action {self.name!r} already has an apply function")
        self.apply_fn = fn
        return fn

    def reconcile(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Register the reconcile function used after ``outcome_unknown``. Returns it unchanged."""
        if self.reconcile_fn is not None:
            raise TypeError(f"action {self.name!r} already has a reconcile function")
        self.reconcile_fn = fn
        return fn

    def __get__(self, obj: object, objtype: type | None = None) -> Any:
        if obj is None:
            return self
        return self.plan_fn.__get__(obj, objtype)


def action(
    name: str,
    *,
    classification: str,
    capability: str,
    input_model: type[BaseModel],
    idempotency: str,
    stability: str = "beta",
) -> Callable[[Callable[..., Any]], ActionDef]:
    """Declare a write action. The decorated function is the ``plan`` step; attach ``.apply`` and ``.reconcile``."""

    def decorate(fn: Callable[..., Any]) -> ActionDef:
        return ActionDef(
            name=name,
            plan_fn=fn,
            classification=classification,
            capability=capability,
            input_model=input_model,
            idempotency=idempotency,
            stability=stability,
        )

    return decorate


def webhook(
    *, event_types: tuple[str, ...], header_event: str | None = None
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Declare a webhook delivery parser (sync; pure over the delivery body)."""

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        return _attach(fn, WebhookSpec(event_types=tuple(event_types), header_event=header_event, fn=fn))

    return decorate


def importer(
    name: str,
    *,
    stream: str,
    media_types: tuple[str, ...],
    extensions: tuple[str, ...],
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Declare a file importer: an async generator yielding raw records for ``stream``'s mapper."""

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        return _attach(
            fn,
            ImporterSpec(
                name=name,
                fn=fn,
                stream=stream,
                media_types=tuple(media_types),
                extensions=tuple(extensions),
            ),
        )

    return decorate


# ---------------------------------------------------------------------------
# Per-class registry and validation
# ---------------------------------------------------------------------------


@dataclass
class _Registry:
    streams: dict[str, StreamSpec] = field(default_factory=dict)
    mappers: dict[str, MapperSpec] = field(default_factory=dict)
    operations: dict[str, OperationSpec] = field(default_factory=dict)
    actions: dict[str, ActionSpec] = field(default_factory=dict)
    webhooks: dict[str, WebhookSpec] = field(default_factory=dict)
    importers: dict[str, ImporterSpec] = field(default_factory=dict)


def _fail(cls: type, message: str) -> TypeError:
    return TypeError(f"{cls.__name__}: {message}")


def _check_capability(cls: type, owner: str, capability: str | None) -> None:
    if capability is None:
        return
    if capability not in KNOWN_CAPABILITIES:
        raise _fail(cls, f"{owner} uses unknown capability {capability!r}")
    if capability not in getattr(cls, "capabilities", ()):
        raise _fail(cls, f"{owner} uses capability {capability!r} not declared in capabilities")


def _check_model(cls: type, owner: str, model: object) -> None:
    if not (isinstance(model, type) and issubclass(model, BaseModel)):
        raise _fail(cls, f"{owner} must use a pydantic BaseModel subclass")


def _check_stream(cls: type, spec: StreamSpec) -> None:
    owner = f"stream {spec.name!r}"
    _check_capability(cls, owner, spec.capability)
    _check_model(cls, owner + " cursor", spec.cursor)
    if not spec.modes or not set(spec.modes) <= _MODES:
        raise _fail(cls, f"{owner} modes must be a non-empty subset of incremental/full")
    if spec.stability not in _STABILITIES:
        raise _fail(cls, f"{owner} stability {spec.stability!r} is not valid")
    if not inspect.isasyncgenfunction(spec.fn):
        raise _fail(cls, f"{owner} must be an async generator function")


def _check_operation(cls: type, spec: OperationSpec) -> None:
    owner = f"operation {spec.name!r}"
    _check_capability(cls, owner, spec.capability)
    _check_model(cls, owner + " input", spec.input_model)
    _check_model(cls, owner + " output", spec.output_model)
    if spec.classification != "read":
        raise _fail(cls, f"{owner} classification must be 'read'; writes go through @action")
    if spec.egress_class not in _EGRESS:
        raise _fail(cls, f"{owner} egress_class {spec.egress_class!r} is not valid")
    if not inspect.iscoroutinefunction(spec.fn):
        raise _fail(cls, f"{owner} must be an async function")


def _check_action(cls: type, spec: ActionSpec) -> None:
    owner = f"action {spec.name!r}"
    _check_capability(cls, owner, spec.capability)
    _check_model(cls, owner + " input", spec.input_model)
    if spec.classification not in _ACTION_CLASSES:
        raise _fail(cls, f"{owner} classification {spec.classification!r} is not valid")
    if spec.idempotency not in _IDEMPOTENCY:
        raise _fail(cls, f"{owner} idempotency {spec.idempotency!r} is not valid")
    if spec.stability not in _STABILITIES:
        raise _fail(cls, f"{owner} stability {spec.stability!r} is not valid")
    if spec.apply is None:
        raise _fail(cls, f"{owner} has no @{spec.name}.apply function")
    for label, fn in (("plan", spec.plan), ("apply", spec.apply), ("reconcile", spec.reconcile)):
        if fn is not None and not inspect.iscoroutinefunction(fn):
            raise _fail(cls, f"{owner} {label} function must be async")


def _check_webhook(cls: type, spec: WebhookSpec) -> None:
    if not spec.event_types:
        raise _fail(cls, f"webhook {spec.fn.__name__!r} declares no event_types")
    if inspect.iscoroutinefunction(spec.fn) or inspect.isasyncgenfunction(spec.fn):
        raise _fail(cls, f"webhook {spec.fn.__name__!r} must be a sync function")


def _check_importer(cls: type, spec: ImporterSpec) -> None:
    owner = f"importer {spec.name!r}"
    if not spec.media_types and not spec.extensions:
        raise _fail(cls, f"{owner} declares neither media_types nor extensions")
    if not inspect.isasyncgenfunction(spec.fn):
        raise _fail(cls, f"{owner} must be an async generator function")


def _collect_own(cls: type) -> _Registry:
    own = _Registry()
    for attr_name, value in vars(cls).items():
        if isinstance(value, ActionDef):
            if value.name in own.actions:
                raise _fail(cls, f"duplicate action name {value.name!r}")
            own.actions[value.name] = ActionSpec(
                name=value.name,
                plan=value.plan_fn,
                apply=value.apply_fn,  # type: ignore[arg-type]
                reconcile=value.reconcile_fn,
                capability=value.capability,
                classification=value.classification,
                input_model=value.input_model,
                idempotency=value.idempotency,
                stability=value.stability,
            )
            continue
        spec = getattr(value, _SPEC_ATTR, None)
        if spec is None:
            continue
        if isinstance(spec, StreamSpec):
            _put_unique(cls, own.streams, spec.name, spec, "stream")
        elif isinstance(spec, MapperSpec):
            _put_unique(cls, own.mappers, spec.stream, spec, "mapper for stream")
        elif isinstance(spec, OperationSpec):
            _put_unique(cls, own.operations, spec.name, spec, "operation")
        elif isinstance(spec, WebhookSpec):
            _put_unique(cls, own.webhooks, attr_name, spec, "webhook")
        elif isinstance(spec, ImporterSpec):
            _put_unique(cls, own.importers, spec.name, spec, "importer")
    return own


def _put_unique(cls: type, table: dict[str, Any], key: str, spec: object, what: str) -> None:
    if key in table:
        raise _fail(cls, f"duplicate {what} {key!r}")
    table[key] = spec


class Connector(ABC):
    """Base class for every vendor connector. Subclasses declare metadata, decorated methods, and two async hooks."""

    kind: ClassVar[str]
    version: ClassVar[str]
    sdk: ClassVar[str] = ">=1,<2"
    display_name: ClassVar[str]
    owner: ClassVar[str] = "@icuhub/maintainers"
    support: ClassVar[Literal["core", "community", "archived"]] = "core"
    config_model: ClassVar[type[ConnectorConfig]]
    auth_modes: ClassVar[tuple[str, ...]]
    capabilities: ClassVar[tuple[str, ...]]
    #: Non-HTTP connectors (for example SMTP) set this to False so the runtime attaches no HTTP client.
    uses_http: ClassVar[bool] = True
    scopes: ClassVar[tuple[Scope, ...]] = ()
    flows: ClassVar[tuple[str, ...]]
    rate_limits: ClassVar[dict[str, tuple[float, float]]] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        merged = _Registry()
        for base in reversed(cls.__mro__[1:]):
            base_reg = base.__dict__.get(_REGISTRY_ATTR)
            if base_reg is None:
                continue
            merged.streams.update(base_reg.streams)
            merged.mappers.update(base_reg.mappers)
            merged.operations.update(base_reg.operations)
            merged.actions.update(base_reg.actions)
            merged.webhooks.update(base_reg.webhooks)
            merged.importers.update(base_reg.importers)

        own = _collect_own(cls)
        for spec in own.streams.values():
            _check_stream(cls, spec)
        for spec in own.operations.values():
            _check_operation(cls, spec)
        for spec in own.actions.values():
            _check_action(cls, spec)
        for spec in own.webhooks.values():
            _check_webhook(cls, spec)
        for spec in own.importers.values():
            _check_importer(cls, spec)

        merged.streams.update(own.streams)
        merged.operations.update(own.operations)
        merged.actions.update(own.actions)
        merged.webhooks.update(own.webhooks)
        merged.importers.update(own.importers)
        for stream_name, spec in own.mappers.items():
            if stream_name not in merged.streams:
                raise _fail(cls, f"mapper references undeclared stream {stream_name!r}")
            if not inspect.isfunction(spec.fn) or inspect.iscoroutinefunction(spec.fn):
                raise _fail(cls, f"mapper for stream {stream_name!r} must be a sync function")
            if spec.version < 1:
                raise _fail(cls, f"mapper for stream {stream_name!r} version must be >= 1")
        for importer_spec in own.importers.values():
            if importer_spec.stream not in merged.streams:
                raise _fail(cls, f"importer {importer_spec.name!r} references undeclared stream {importer_spec.stream!r}")
        merged.mappers.update(own.mappers)
        setattr(cls, _REGISTRY_ATTR, merged)

    def __init__(self, config: ConnectorConfig, ctx: ConnectorContext) -> None:
        self.config = config
        self.ctx = ctx

    @property
    def http(self) -> VendorHttp:
        """The authenticated HTTP client. Raises ``ConfigError`` until the runtime attaches it."""
        if self.ctx.http is None:
            raise ConfigError("connector HTTP is not attached; await build_auth() and set ctx.http first")
        return self.ctx.http

    @abstractmethod
    async def build_auth(self) -> AuthStrategy:
        """Resolve secrets from ``self.config`` and return the auth strategy for this connection."""

    @abstractmethod
    async def check(self) -> HealthReport:
        """Probe the vendor. Vendor errors are reported in the result, not raised."""

    async def discover(self) -> AsyncIterator[TargetRecord]:
        """Enumerate candidate targets. The default yields nothing."""
        for record in ():
            yield record

    def webhook_verifier(self, secret: bytes) -> WebhookVerifier | None:
        """Return the verifier for inbound deliveries, or None when the connector takes no webhooks."""
        return None

    @classmethod
    def _registry(cls) -> _Registry:
        return getattr(cls, _REGISTRY_ATTR)

    @classmethod
    def streams(cls) -> dict[str, StreamSpec]:
        return dict(cls._registry().streams)

    @classmethod
    def mappers(cls) -> dict[str, MapperSpec]:
        return dict(cls._registry().mappers)

    @classmethod
    def operations(cls) -> dict[str, OperationSpec]:
        return dict(cls._registry().operations)

    @classmethod
    def actions(cls) -> dict[str, ActionSpec]:
        return dict(cls._registry().actions)

    @classmethod
    def webhooks(cls) -> dict[str, WebhookSpec]:
        return dict(cls._registry().webhooks)

    @classmethod
    def importers(cls) -> dict[str, ImporterSpec]:
        return dict(cls._registry().importers)


setattr(Connector, _REGISTRY_ATTR, _Registry())
