# Prisma Cloud fixture provenance

STATUS: Synthetic. These fixtures are hand-authored shapes, NOT captured vendor responses. Field names were NOT yet confirmed against the Palo Alto Networks API reference; every field marked in the connector as `[UNVERIFIED]` must be re-checked against the live API (see docs/IMPLEMENTATION_GAPS.md) before the fixtures are treated as authoritative. No customer data, credentials, or copied vendor text is included.

Reference pages the connector contract is checked against (to be read and confirmed; not yet cited as a basis for field names):
- Login and regional API hosts: https://pan.dev/prisma-cloud/api/cspm/login/ and https://pan.dev/prisma-cloud/api/cspm/api-urls/
- Alerts: https://pan.dev/prisma-cloud/api/cspm/alert-v2/
- Cloud accounts: https://pan.dev/prisma-cloud/api/cspm/get-cloud-accounts/
- Compute images: https://pan.dev/prisma-cloud/api/cwpp/get-images/
- Compute audits and incidents: https://pan.dev/prisma-cloud/api/cwpp/get-audits-incidents/
- Compute collections: https://pan.dev/prisma-cloud/api/cwpp/collections/
