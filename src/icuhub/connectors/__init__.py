"""Built-in connectors, populated by explicit imports in connector releases."""

from icuhub.connectors.archer import Archer
from icuhub.connectors.f5_bigip import F5BigIp
from icuhub.connectors.fortify_fod import FortifyFod
from icuhub.connectors.fortify_ssc import FortifySsc
from icuhub.connectors.github import GitHub
from icuhub.connectors.github_enterprise_server import GitHubEnterpriseServer
from icuhub.connectors.gitlab import GitLab
from icuhub.connectors.gitlab_self_managed import GitLabSelfManaged
from icuhub.connectors.google_threat_intelligence import GoogleThreatIntelligence
from icuhub.connectors.invicti_enterprise import InvictiEnterprise
from icuhub.connectors.invicti_standard import InvictiStandard
from icuhub.connectors.jira_cloud import JiraCloud
from icuhub.connectors.jira_dc import JiraDataCenter
from icuhub.connectors.kubernetes import Kubernetes
from icuhub.connectors.mend_sca import MendSca
from icuhub.connectors.nessus import Nessus
from icuhub.connectors.openshift import OpenShift
from icuhub.connectors.prisma_cloud import PrismaCloud
from icuhub.connectors.smtp import Smtp
from icuhub.kit.connector import Connector

__all__ = ["CONNECTORS"]

CONNECTORS: dict[str, type[Connector]] = {
    Archer.kind: Archer,
    FortifySsc.kind: FortifySsc,
    FortifyFod.kind: FortifyFod,
    GitHub.kind: GitHub,
    GitHubEnterpriseServer.kind: GitHubEnterpriseServer,
    GitLab.kind: GitLab,
    GitLabSelfManaged.kind: GitLabSelfManaged,
    Smtp.kind: Smtp,
    Nessus.kind: Nessus,
    InvictiEnterprise.kind: InvictiEnterprise,
    InvictiStandard.kind: InvictiStandard,
    JiraCloud.kind: JiraCloud,
    JiraDataCenter.kind: JiraDataCenter,
    Kubernetes.kind: Kubernetes,
    MendSca.kind: MendSca,
    OpenShift.kind: OpenShift,
    F5BigIp.kind: F5BigIp,
    GoogleThreatIntelligence.kind: GoogleThreatIntelligence,
    PrismaCloud.kind: PrismaCloud,
}
