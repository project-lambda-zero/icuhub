"""Mend SCA connector package: Platform API 3.0 and legacy SCA API 2.0."""

from icuhub.connectors.mend_sca.connector import MendSca
from icuhub.connectors.mend_sca.models import MendSCAConfig

__all__ = ["MendSCAConfig", "MendSca"]
