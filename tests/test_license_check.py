"""Behaviour of the runtime license gate, driven by fake distribution metadata."""

from __future__ import annotations

import os
import pathlib
from collections.abc import Callable, Iterable
from importlib import metadata

import pytest

import license_check
from license_check import LicenseCheckError, check_licenses, main


class _FakeDistribution(metadata.Distribution):
    def __init__(self, text: str) -> None:
        self._text = text

    def read_text(self, filename: str) -> str | None:
        return self._text if filename == "METADATA" else None

    def locate_file(self, path: str | os.PathLike[str]) -> pathlib.Path:
        return pathlib.Path(path)


def _dist(
    name: str,
    *,
    requires: Iterable[str] = (),
    expression: str | None = None,
    license_field: str | None = None,
    classifiers: Iterable[str] = (),
) -> _FakeDistribution:
    lines = ["Metadata-Version: 2.1", f"Name: {name}", "Version: 1.0"]
    if expression is not None:
        lines.append(f"License-Expression: {expression}")
    if license_field is not None:
        lines.append(f"License: {license_field}")
    lines.extend(f"Classifier: {value}" for value in classifiers)
    lines.extend(f"Requires-Dist: {value}" for value in requires)
    return _FakeDistribution("\n".join(lines) + "\n")


def _lookup(table: dict[str, _FakeDistribution]) -> Callable[[str], metadata.Distribution]:
    def find(name: str) -> metadata.Distribution:
        try:
            return table[name]
        except KeyError as exc:
            raise metadata.PackageNotFoundError(name) from exc

    return find


def test_allowed_root_and_dependency_pass() -> None:
    table = {
        "app": _dist("app", expression="MIT", requires=["lib>=1"]),
        "lib": _dist("lib", expression="Apache-2.0"),
    }

    resolved = check_licenses(["app"], lookup=_lookup(table))

    assert resolved == {"app": "MIT", "lib": "Apache-2.0"}


def test_transitive_dependency_is_inspected() -> None:
    table = {
        "app": _dist("app", expression="MIT", requires=["mid"]),
        "mid": _dist("mid", expression="MIT", requires=["leaf"]),
        "leaf": _dist("leaf", expression="Elastic-2.0"),
    }

    with pytest.raises(LicenseCheckError, match=r"^leaf: "):
        check_licenses(["app"], lookup=_lookup(table))


def test_source_available_license_is_rejected() -> None:
    table = {"app": _dist("app", expression="BUSL-1.1 OR MIT")}

    with pytest.raises(LicenseCheckError, match="Business Source License"):
        check_licenses(["app"], lookup=_lookup(table))


def test_source_available_license_in_license_field_is_rejected() -> None:
    table = {"app": _dist("app", license_field="Server Side Public License v1")}

    with pytest.raises(LicenseCheckError, match=r"app: .*SSPL"):
        check_licenses(["app"], lookup=_lookup(table))


def test_unknown_license_fails_with_package_name() -> None:
    table = {"app": _dist("app", expression="Proprietary")}

    with pytest.raises(LicenseCheckError, match=r"^app: license 'Proprietary' is not on the allowlist"):
        check_licenses(["app"], lookup=_lookup(table))


def test_missing_license_metadata_fails_with_package_name() -> None:
    table = {"app": _dist("app")}

    with pytest.raises(LicenseCheckError, match=r"^app: no license metadata found"):
        check_licenses(["app"], lookup=_lookup(table))


def test_missing_distribution_fails_with_package_name() -> None:
    table = {"app": _dist("app", expression="MIT", requires=["ghost"])}

    with pytest.raises(LicenseCheckError, match="ghost: distribution is not installed"):
        check_licenses(["app"], lookup=_lookup(table))


def test_malformed_requirement_fails_with_package_name() -> None:
    table = {"app": _dist("app", expression="MIT", requires=["not a requirement !!"])}

    with pytest.raises(LicenseCheckError, match="^app: invalid requirement"):
        check_licenses(["app"], lookup=_lookup(table))


def test_dev_extra_requirements_are_not_inspected() -> None:
    table = {"app": _dist("app", expression="MIT", requires=['ruff>=0.6; extra == "dev"'])}

    assert check_licenses(["app"], lookup=_lookup(table)) == {"app": "MIT"}


def test_environment_excluded_requirements_are_not_inspected() -> None:
    table = {"app": _dist("app", expression="MIT", requires=['legacy-only; python_version < "3"'])}

    assert check_licenses(["app"], lookup=_lookup(table)) == {"app": "MIT"}


def test_classifier_fallback_resolves_license() -> None:
    table = {"app": _dist("app", classifiers=["License :: OSI Approved :: MIT License"])}

    assert check_licenses(["app"], lookup=_lookup(table)) == {"app": "MIT"}


def test_free_text_license_field_falls_back_to_classifier() -> None:
    table = {
        "app": _dist(
            "app",
            license_field="MIT License text",
            classifiers=["License :: OSI Approved :: MIT License"],
        )
    }

    assert check_licenses(["app"], lookup=_lookup(table)) == {"app": "MIT"}


@pytest.mark.parametrize(("raw", "canonical"), [("PSFL", "PSF-2.0"), ("PSF", "PSF-2.0"), ("MIT-0", "MIT-0")])
def test_valid_single_token_license_metadata(raw: str, canonical: str) -> None:
    table = {"app": _dist("app", license_field=raw)}

    assert check_licenses(["app"], lookup=_lookup(table)) == {"app": canonical}


def test_free_text_license_field_without_classifier_fails() -> None:
    table = {"app": _dist("app", license_field="BSD License")}

    with pytest.raises(LicenseCheckError, match=r"^app: License field 'BSD License' is not a recognized SPDX"):
        check_licenses(["app"], lookup=_lookup(table))


def test_ambiguous_classifier_fails_closed() -> None:
    table = {"app": _dist("app", classifiers=["License :: OSI Approved :: BSD License"])}

    with pytest.raises(LicenseCheckError, match=r"^app: unrecognized license classifier"):
        check_licenses(["app"], lookup=_lookup(table))


def test_all_violations_are_reported_together() -> None:
    table = {
        "app": _dist("app", expression="MIT", requires=["bad-one", "bad-two"]),
        "bad-one": _dist("bad-one", expression="Proprietary"),
        "bad-two": _dist("bad-two", expression="SSPL-1.0"),
    }

    with pytest.raises(LicenseCheckError) as excinfo:
        check_licenses(["app"], lookup=_lookup(table))

    message = str(excinfo.value)
    assert "bad-one: " in message
    assert "bad-two: " in message


def test_cli_exit_zero_when_roots_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    table = {"app": _dist("app", expression="MIT")}
    monkeypatch.setattr(license_check, "_installed", _lookup(table))

    assert main(["app"]) == 0


def test_cli_exit_one_when_a_license_is_excluded(monkeypatch: pytest.MonkeyPatch) -> None:
    table = {"app": _dist("app", expression="Elastic-2.0")}
    monkeypatch.setattr(license_check, "_installed", _lookup(table))

    assert main(["app"]) == 1


def test_default_roots_are_the_two_shipped_distributions() -> None:
    assert license_check.DEFAULT_ROOTS == ("icuhub", "icuhub-schemas")
