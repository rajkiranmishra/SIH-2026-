# ADR-0001: Start as an offline modular monolith

- Status: Accepted
- Date: 2026-09-05

## Context

ForenX must run on controlled forensic workstations, process large untrusted evidence sources, preserve complete provenance, and remain installable without routine internet access. The team must deliver one validated recovery path before it needs distributed scale.

## Decision

Use a modular monolith with a local authenticated API, workstation UI, durable job orchestrator, isolated worker processes, case-scoped artifact store, and metadata database.

Domain, evidence-source, adapter, recovery, analysis, custody and reporting packages have explicit boundaries. DVR adapters never depend on the API or database. Untrusted binary/media parsing runs in restricted workers rather than the API process.

## Consequences

- Deployment and auditing remain understandable during early validation.
- Components can later be separated without redesigning their contracts.
- Worker isolation is still mandatory; “monolith” does not mean processing untrusted files inside the web process.
- SQLite can support a single workstation initially, with a PostgreSQL deployment profile added for laboratories.

