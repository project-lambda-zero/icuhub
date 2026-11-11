"""Fail when the runtime dependency closure of ICUHUB carries a disallowed license.

Usage: python tools/license_check.py [distribution ...]

Only base runtime requirements are inspected. Requirements gated on an extra
and requirements whose environment marker is false are skipped. Licenses are
read from License-Expression, then License, then trove classifiers; a
distribution with no recognized license metadata fails closed.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable, Iterable, Sequence
from importlib import metadata
from typing import Final

from packaging.requirements import InvalidRequirement, Requirement

__all__ = ["DEFAULT_ROOTS", "LicenseCheckError", "check_licenses", "main", "runtime_closure"]

DEFAULT_ROOTS: Final[tuple[str, ...]] = ("icuhub", "icuhub-schemas")

ALLOWED_LICENSES: Final[frozenset[str]] = frozenset(
    {
        "0BSD",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "ISC",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MIT",
        "MIT-0",
        "MPL-2.0",
        "PSF-2.0",
        "Python-2.0",
        "Unlicense",
        "Zlib",
    }
)

# Trove classifiers with an unambiguous SPDX identifier. Ambiguous classifiers
# (for example "BSD License" or "GNU Lesser General Public License v3") are not
# mapped and therefore fail closed.
CLASSIFIER_LICENSES: Final[dict[str, str]] = {
    "License :: OSI Approved :: 0BSD": "0BSD",
    "License :: OSI Approved :: Zero-Clause BSD (0BSD)": "0BSD",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: OSI Approved :: zlib/libpng License": "Zlib",
}

# Legacy single-token License metadata emitted by otherwise valid runtime packages.
# License-Expression is never aliased: that field must always contain valid SPDX.
LICENSE_ALIASES: Final[dict[str, str]] = {
    "PSF": "PSF-2.0",
    "PSFL": "PSF-2.0",
}

# Source-available and commercial-restriction licenses that must never pass,
# even when they appear inside an otherwise parseable expression.
_REJECTED_LICENSES: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (re.compile(r"elastic license|\bELv2\b|\bElastic-2\.0\b", re.IGNORECASE), "Elastic License (ELv2)"),
    (
        re.compile(r"business source license|\bBUSL\b|\bBSL\b", re.IGNORECASE),
        "Business Source License (BSL/BUSL)",
    ),
    (re.compile(r"server side public license|\bSSPL\b", re.IGNORECASE), "Server Side Public License (SSPL)"),
    (re.compile(r"redis source available license|\bRSAL\b", re.IGNORECASE), "Redis Source Available License (RSAL)"),
    (re.compile(r"commons clause", re.IGNORECASE), "Commons Clause"),
)

_Lookup = Callable[[str], metadata.Distribution]


class LicenseCheckError(RuntimeError):
    """A runtime dependency is missing, uses an excluded license, or has no recognized license."""


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _installed(name: str) -> metadata.Distribution:
    return metadata.distribution(name)


def _in_base_runtime(requirement: Requirement) -> bool:
    if requirement.marker is None:
        return True
    return requirement.marker.evaluate({"extra": ""})


def runtime_closure(roots: Iterable[str], lookup: _Lookup | None = None) -> dict[str, metadata.Distribution]:
    """Return every distribution reachable from ``roots`` through base runtime requirements, keyed by canonical name."""

    find = _installed if lookup is None else lookup
    pending = [_canonical(root) for root in roots]
    closure: dict[str, metadata.Distribution] = {}
    while pending:
        name = pending.pop()
        if name in closure:
            continue
        try:
            distribution = find(name)
        except metadata.PackageNotFoundError as exc:
            raise LicenseCheckError(f"{name}: distribution is not installed") from exc
        closure[name] = distribution
        for text in distribution.requires or []:
            try:
                requirement = Requirement(text)
            except InvalidRequirement as exc:
                raise LicenseCheckError(f"{name}: invalid requirement {text!r}") from exc
            if _in_base_runtime(requirement):
                pending.append(_canonical(requirement.name))
    return closure


class _ExpressionParser:
    """Evaluate an SPDX license expression against ALLOWED_LICENSES, failing closed on anything unsupported."""

    _KEYWORDS: Final = frozenset({"AND", "OR", "WITH"})

    def __init__(self, text: str) -> None:
        self._tokens = re.findall(r"\(|\)|[^\s()]+", text)
        self._pos = 0

    def parse(self) -> bool:
        if not self._tokens:
            raise ValueError("empty license expression")
        value = self._or()
        if self._pos != len(self._tokens):
            raise ValueError("trailing tokens in license expression")
        return value

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            raise ValueError("unexpected end of license expression")
        self._pos += 1
        return token

    def _or(self) -> bool:
        value = self._and()
        while self._peek() == "OR":
            self._pos += 1
            right = self._and()
            value = value or right
        return value

    def _and(self) -> bool:
        value = self._atom()
        while self._peek() == "AND":
            self._pos += 1
            right = self._atom()
            value = value and right
        return value

    def _atom(self) -> bool:
        token = self._take()
        if token == "(":
            value = self._or()
            if self._take() != ")":
                raise ValueError("missing ')' in license expression")
            return value
        if token == ")" or token in self._KEYWORDS:
            raise ValueError(f"unexpected {token!r} in license expression")
        if self._peek() == "WITH":
            # License exceptions are not evaluated, so the term is not allowed.
            self._pos += 1
            self._take()
            return False
        return token in ALLOWED_LICENSES


def _expression_allowed(text: str) -> bool | None:
    """Return whether ``text`` is an allowed SPDX expression, or None when it is not an expression at all."""

    try:
        return _ExpressionParser(text).parse()
    except ValueError:
        return None


def _resolve_license(name: str, distribution: metadata.Distribution) -> str:
    headers = distribution.metadata
    expression = headers.get("License-Expression")
    license_field = headers.get("License")
    classifiers = [value for value in headers.get_all("Classifier") or [] if value.startswith("License ::")]

    for text in (expression, license_field, *classifiers):
        if not text:
            continue
        for pattern, label in _REJECTED_LICENSES:
            if pattern.search(text):
                raise LicenseCheckError(f"{name}: {label} is not permitted")

    if expression:
        allowed = _expression_allowed(expression)
        if allowed is None:
            raise LicenseCheckError(f"{name}: License-Expression {expression!r} is not a valid SPDX expression")
        if not allowed:
            raise LicenseCheckError(f"{name}: license {expression!r} is not on the allowlist")
        return expression

    if license_field:
        normalized = LICENSE_ALIASES.get(license_field.strip(), license_field)
        allowed = _expression_allowed(normalized)
        if allowed is True:
            return normalized
        if allowed is False:
            raise LicenseCheckError(f"{name}: license {license_field!r} is not on the allowlist")
        # Free text such as "BSD License" is not an SPDX expression; fall back to classifiers.

    if not classifiers:
        if license_field:
            raise LicenseCheckError(f"{name}: License field {license_field!r} is not a recognized SPDX identifier")
        raise LicenseCheckError(f"{name}: no license metadata found")
    unmapped = sorted(value for value in classifiers if value not in CLASSIFIER_LICENSES)
    if unmapped:
        raise LicenseCheckError(f"{name}: unrecognized license classifier {unmapped[0]!r}")
    identifiers = sorted({CLASSIFIER_LICENSES[value] for value in classifiers})
    disallowed = [identifier for identifier in identifiers if identifier not in ALLOWED_LICENSES]
    if disallowed:
        raise LicenseCheckError(f"{name}: license {disallowed[0]!r} is not on the allowlist")
    return " AND ".join(identifiers)


def check_licenses(roots: Iterable[str] = DEFAULT_ROOTS, lookup: _Lookup | None = None) -> dict[str, str]:
    """Return the resolved license of every runtime distribution under ``roots``.

    Raises LicenseCheckError listing every violation, one per line.
    """

    closure = runtime_closure(roots, lookup)
    resolved: dict[str, str] = {}
    failures: list[str] = []
    for name, distribution in sorted(closure.items()):
        try:
            resolved[name] = _resolve_license(name, distribution)
        except LicenseCheckError as exc:
            failures.append(str(exc))
    if failures:
        raise LicenseCheckError("\n".join(failures))
    return resolved


def main(argv: Sequence[str] | None = None) -> int:
    """Run the check for the given roots (default: DEFAULT_ROOTS) and return a process exit code."""

    roots = tuple(argv) if argv else DEFAULT_ROOTS
    try:
        resolved = check_licenses(roots)
    except LicenseCheckError as exc:
        print(f"license check failed:\n{exc}", file=sys.stderr)
        return 1
    for name, license_id in resolved.items():
        print(f"{name}\t{license_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
