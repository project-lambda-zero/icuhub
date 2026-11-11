# Prisma Cloud fixture provenance

STATUS: Synthetic. These fixtures are hand-authored shapes, NOT captured vendor responses. Field names were NOT yet confirmed against the Palo Alto Networks API reference; every field marked in the connector as `[UNVERIFIED]` must be re-checked against the live API (see docs/IMPLEMENTATION_GAPS.md) before the fixtures are treated as authoritative. No customer data, credentials, or copied vendor text is included.

Reference pages the connector contract is checked against (to be read and confirmed; not yet cited as a basis for field names):
- Login and regional API hosts: https://pan.dev/prisma-cloud/api/cspm/login/ and https://pan.dev/prisma-cloud/api/cspm/api-urls/
- Alerts: https://pan.dev/prisma-cloud/api/cspm/alert-v2/
- Cloud accounts: https://pan.dev/prisma-cloud/api/cspm/get-cloud-accounts/
- Compute images: https://pan.dev/prisma-cloud/api/cwpp/get-images/
- Compute audits and incidents: https://pan.dev/prisma-cloud/api/cwpp/get-audits-incidents/
- Compute collections: https://pan.dev/prisma-cloud/api/cwpp/collections/

## UVE impacted-asset CSV fixtures

`uve_cve_2025_38438.csv` and `uve_cve_2022_45885.csv` adapt the first two records
from Elastic's Prisma Cloud vulnerability pipeline fixture at commit
`9ae756f00f82786ac3496ce99c2dd288c5a5c031`:

- https://github.com/elastic/integrations/blob/9ae756f00f82786ac3496ce99c2dd288c5a5c031/packages/prisma_cloud/data_stream/vulnerability/_dev/test/pipeline/test-vulnerability.log
- Primary request and pagination contract: https://github.com/PaloAltoNetworks/pan.dev/blob/99309c7201326d247517c7432e4c53cc9be0f304/openapi-specs/cspm/UVESearchMicroService.json
- V3 impacted-asset download: https://pan.dev/prisma-cloud/api/cspm/download-vulnerability-file-v-3

These are offline field-shape fixtures, not live acceptance captures. Search envelopes,
RQL pagination mutations, gzip failures, duplicate rows, and count mismatches remain
synthetic negative cases.
