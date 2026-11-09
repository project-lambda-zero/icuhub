# GTI fixture provenance

`domain_report.json` follows the documented VirusTotal API v3 object shape
(`data.attributes.last_analysis_stats`, `reputation`, `categories`, `tags`, `links.self`)
with synthetic indicator data. No customer data. Live lookup verification is operator-run
through `tests/acceptance/test_google_threat_intelligence.py`.
