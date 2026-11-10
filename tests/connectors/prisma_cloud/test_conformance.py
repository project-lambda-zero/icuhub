"""Connector declaration and manifest conformance."""

from icuhub.connectors.prisma_cloud import PrismaCloud
from icuhub.kit.testing import conformance_problems


def test_conformance_and_manifest() -> None:
    assert conformance_problems(PrismaCloud) == []


def test_dod_surface_is_declared() -> None:
    streams = PrismaCloud.streams()
    assert {
        "cspm_config_alerts", "cspm_vulnerability_alerts", "cspm_detection_alerts",
        "cspm_compliance_posture", "cspm_audit_events", "cspm_resources_snapshot",
        "cspm_resource_misconfigurations_snapshot", "cspm_vulnerability_export",
        "cspm_accounts_snapshot", "cspm_rql_assets", "cspm_inventory_aggregates",
        "cspm_policies",
        "compute_image_vulnerabilities", "compute_host_vulnerabilities",
        "compute_container_vulnerabilities", "compute_registry_vulnerabilities",
        "compute_image_compliance", "compute_host_compliance", "compute_container_compliance",
        "compute_registry_compliance", "compute_runtime_container_audits",
        "compute_runtime_host_audits", "compute_runtime_incidents", "compute_waas_alerts",
        "compute_defenders", "compute_collections",
    } <= set(streams)
    operations = set(PrismaCloud.operations())
    assert {"search_vulnerabilities", "download_vulnerability_export"} <= operations
    assert not {
        "submit_vulnerability_export",
        "get_vulnerability_export_status",
    } & operations
    assert {
        "dismiss_alert", "snooze_alert", "reopen_alert", "remediate_alert",
        "start_registry_scan", "acknowledge_incident", "unacknowledge_incident",
        "create_or_update_collection", "delete_collection",
    } == set(PrismaCloud.actions())
