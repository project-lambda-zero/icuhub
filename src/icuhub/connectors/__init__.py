"""Built-in connectors, populated by explicit imports in connector releases."""

from icuhub.kit.connector import Connector

__all__ = ["CONNECTORS"]

CONNECTORS: dict[str, type[Connector]] = {}
