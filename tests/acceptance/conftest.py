"""Live acceptance harness (opt-in, operator-run; MVP.md section 6).

Run with ``ICUHUB_ACC=1`` and, per connector kind, ``ICUHUB_ACC_<KIND>`` pointing to a
JSON file shaped as::

    {"config": {...connector config, secrets as {"ref": "<name>"}...},
     "secrets": {"<name>": "<secret value>"},
     "params": {...kind-specific sandbox identifiers, e.g. project key, repository...},
     "allow_writes": false}

Results are written to ``acceptance/<kind>.json`` (one entry per test) so the operator can
hand them back without sharing credentials. Write-path tests run only when
``allow_writes`` is true in the file, and only against the sandbox identifiers in
``params``.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

ACCEPTANCE_DIR = Path(__file__).resolve().parents[2] / "acceptance"


@dataclass
class AcceptanceSetup:
    kind: str
    config: dict[str, Any]
    secrets: dict[str, bytes]
    params: dict[str, Any]
    allow_writes: bool
    results: list[dict[str, Any]] = field(default_factory=list)

    def record(self, check: str, passed: bool, detail: str = "", **evidence: Any) -> None:
        """Record one acceptance check. ``evidence`` must not contain secrets or record bodies."""
        self.results.append(
            {
                "check": check,
                "passed": passed,
                "detail": detail,
                "evidence": evidence,
                "at": datetime.now(UTC).isoformat(),
            }
        )

    def require_writes(self) -> None:
        if not self.allow_writes:
            pytest.skip(f"{self.kind}: allow_writes is false in the acceptance file")


def _load(kind: str) -> AcceptanceSetup:
    if os.environ.get("ICUHUB_ACC") != "1":
        pytest.skip("live acceptance is opt-in: set ICUHUB_ACC=1")
    path = os.environ.get(f"ICUHUB_ACC_{kind.upper()}")
    if not path:
        pytest.skip(f"ICUHUB_ACC_{kind.upper()} is not set")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return AcceptanceSetup(
        kind=kind,
        config=data["config"],
        secrets={name: value.encode("utf-8") for name, value in data.get("secrets", {}).items()},
        params=data.get("params", {}),
        allow_writes=bool(data.get("allow_writes", False)),
    )


_SETUPS: dict[str, AcceptanceSetup] = {}


@pytest.fixture
def acceptance(request: pytest.FixtureRequest) -> AcceptanceSetup:
    """Per-kind acceptance setup; the test module sets ``ACCEPTANCE_KIND``."""
    kind = getattr(request.module, "ACCEPTANCE_KIND", None)
    if not kind:
        raise RuntimeError(f"{request.module.__name__} must define ACCEPTANCE_KIND")
    if kind not in _SETUPS:
        _SETUPS[kind] = _load(kind)
    return _SETUPS[kind]


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not _SETUPS:
        return
    ACCEPTANCE_DIR.mkdir(exist_ok=True)
    for kind, setup in _SETUPS.items():
        out = {
            "kind": kind,
            "finished_at": datetime.now(UTC).isoformat(),
            "epoch": int(time.time()),
            "results": setup.results,
        }
        (ACCEPTANCE_DIR / f"{kind}.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
