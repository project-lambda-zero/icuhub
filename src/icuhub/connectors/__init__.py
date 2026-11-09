"""Built-in connectors, populated by explicit imports in connector releases."""

from icuhub.connectors.fortify_fod import FortifyFod
from icuhub.connectors.fortify_ssc import FortifySsc
from icuhub.connectors.google_threat_intelligence import GoogleThreatIntelligence
from icuhub.connectors.smtp import Smtp
from icuhub.kit.connector import Connector

__all__ = ["CONNECTORS"]

CONNECTORS: dict[str, type[Connector]] = {
    FortifySsc.kind: FortifySsc,
    FortifyFod.kind: FortifyFod,
    Smtp.kind: Smtp,
    GoogleThreatIntelligence.kind: GoogleThreatIntelligence,
}
