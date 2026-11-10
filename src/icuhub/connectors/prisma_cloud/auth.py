"""Connection-local authentication for the independent Prisma Cloud profiles."""

from __future__ import annotations

from contextvars import ContextVar

from icuhub.kit.auth import AuthStrategy

__all__ = ["ProfileAuth"]


class ProfileAuth:
    """Route authentication by request host and refresh only the challenged profile.

    ``VendorHttp.refresh`` does not receive the rejected URL. A context variable retains
    the profile selected by ``apply`` in the same request task, including across sibling
    requests running in other tasks.
    """

    def __init__(self, strategies: dict[str, AuthStrategy], hosts: dict[str, str]) -> None:
        self._strategies = strategies
        self._hosts = hosts
        self._selected: ContextVar[str | None] = ContextVar("prisma_auth_profile", default=None)

    def _profile(self, url: str) -> str:
        matches = [profile for profile, host in self._hosts.items() if host and host in url]
        if len(matches) != 1:
            raise ValueError("Prisma request URL does not select exactly one configured profile")
        return matches[0]

    async def apply(self, request_headers: dict[str, str], method: str, url: str) -> None:
        profile = self._profile(url)
        self._selected.set(profile)
        await self._strategies[profile].apply(request_headers, method, url)

    async def refresh(self) -> bool:
        profile = self._selected.get()
        if profile is None:
            return False
        return await self._strategies[profile].refresh()
