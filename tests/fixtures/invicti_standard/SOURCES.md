# Sources

The JSON fixture is synthetic and follows the report shape documented for ICUHUB in `docs/VENDOR_CONNECTORS.md` and `docs/MVP.md`: report ID, target URL, metadata, and `Vulnerabilities[]`.

- https://docs.invicti.com/ie-is/integrating-invicti-standard-webhook -- Invicti Standard Send To Actions documentation.
- https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/tools/invicti/parser.py -- field-shape reference only, BSD-3-Clause; no code copied.
- NOTICE: synthetic fixture data is provided under the repository license; no vendor code or proprietary response bodies are copied.

Native Standard and Netsparker desktop XML profiles are intentionally absent until a current real export is available, as required by `docs/MVP.md` section 4.12.
