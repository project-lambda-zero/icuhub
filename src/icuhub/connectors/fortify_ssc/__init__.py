"""Fortify Software Security Center connector package."""

from icuhub.connectors.fortify_ssc.connector import FortifySsc
from icuhub.connectors.fortify_ssc.models import FortifySscConfig

__all__ = ["FortifySsc", "FortifySscConfig"]
