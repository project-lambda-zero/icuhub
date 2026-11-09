# Nessus fixture provenance

Synthetic minimal documents in the documented `NessusClientData_v2` export shape
(`Report` / `ReportHost` / `ReportItem`, `HostProperties`, `cm:compliance-*` tags with the
`http://www.nessus.org/cm` namespace). No customer data. They exercise severity 0-4,
truncation markers, compliance tags, wrong roots, and DTD/XXE rejection; live export
verification is owned by the operator acceptance run.
