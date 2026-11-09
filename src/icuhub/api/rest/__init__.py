"""REST ``/v1`` router assembled from resource modules."""

from __future__ import annotations

from fastapi import APIRouter

from icuhub.api.rest.connections import router as connections_router
from icuhub.api.rest.resources import router as resources_router
from icuhub.api.rest.runtime import router as runtime_router

__all__ = ["router"]

router = APIRouter()
router.include_router(connections_router)
router.include_router(resources_router)
router.include_router(runtime_router)
