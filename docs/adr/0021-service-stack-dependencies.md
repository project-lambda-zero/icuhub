# ADR-0021 -- Service stack dependency set

- Status: Accepted
- Date: 2026-11-09
- Closes: D20

## Context

ADR-0016 fixed the HTTP toolkit and ADR-0019 fixed JMESPath. The MVP (ADR-0020) ships
the REST API, webhook ingress, storage with migrations, safe XML parsing for report
files and SOAP, envelope encryption (ADR-0006), the Kafka relay (ADR-0005), and the MCP
endpoint. `HLD.md` section 3 proposed FastAPI and SQLAlchemy with Alembic, to be adopted
by ADR when the core service starts.

## Decision

Runtime dependencies added, pinned in `pyproject.toml` (versions current on 2026-11-09):

| Package | Version | License | Use |
|---|---|---|---|
| `fastapi` | 0.162.2 | MIT | REST `/v1`, webhook ingress, OpenAPI 3.1 |
| `uvicorn` | 0.54.0 | BSD-3-Clause | ASGI server |
| `sqlalchemy[asyncio]` | 2.1.8 | MIT | Typed ORM and SQL over `asyncpg` |
| `alembic` | 1.20.1 | MIT | Schema migrations |
| `defusedxml` | 0.7.1 | PSF-2.0 | XML with DTD, entity, and external reference guards (Nessus, Fortify FPR, Invicti, Archer SOAP) |
| `cryptography` | 50.0.2 | Apache-2.0 OR BSD-3-Clause | AES-256-GCM envelope encryption; RS256 JWT for GitHub App auth |
| `aiokafka` | 0.15.0 | Apache-2.0 | Outbox relay producer (ADR-0005) |
| `mcp` | 2.3.0 | MIT | MCP server, Streamable HTTP transport |

- `aiokafka` and `mcp` follow from the D19 outcome in ADR-0020 (Kafka relay and MCP in
  the MVP); the operator approved the dependency set for that scope.
- Tests use `pytest` only. HTTP is faked through `httpx2.MockTransport` and the kit
  recorded transport; async tests call `asyncio.run`. No HTTP mocking or async test
  plugin is added.
- Development installs use a project virtual environment; nothing is installed into a
  shared interpreter.

## Consequences

- Every package passes the license check (NFR-15).
- Migrations are Alembic revisions under `src/icuhub/storage/migrations/versions/`;
  no runtime `create_all` outside tests.
- Any further runtime dependency needs a new ADR.

## Requirements affected

NFR-15; HLD section 3; ROADMAP P2, P3, P4.
