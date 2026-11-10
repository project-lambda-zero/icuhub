"""Built-in connectors, populated by explicit imports in connector releases."""

from icuhub.connectors.archer import Archer
from icuhub.connectors.f5_bigip import F5BigIp
from icuhub.connectors.fortify_fod import FortifyFod
from icuhub.connectors.fortify_ssc import FortifySsc
from icuhub.connectors.google_threat_intelligence import GoogleThreatIntelligence
from icuhub.connectors.invicti_enterprise import InvictiEnterprise
from icuhub.connectors.invicti_standard import InvictiStandard
from icuhub.connectors.nessus import Nessus
from icuhub.connectors.prisma_cloud import PrismaCloud
from icuhub.connectors.smtp import Smtp
from icuhub.kit.connector import Connector

__all__ = ["CONNECTORS"]

CONNECTORS: dict[str, type[Connector]] = {
    Archer.kind: Archer,
    FortifySsc.kind: FortifySsc,
    FortifyFod.kind: FortifyFod,
    Smtp.kind: Smtp,
    Nessus.kind: Nessus,
    InvictiEnterprise.kind: InvictiEnterprise,
    InvictiStandard.kind: InvictiStandard,
    F5BigIp.kind: F5BigIp,
    GoogleThreatIntelligence.kind: GoogleThreatIntelligence,
    PrismaCloud.kind: PrismaCloud,
}
