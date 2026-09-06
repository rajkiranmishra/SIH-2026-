# Security Policy

## Scope

ForenX processes untrusted disk images, proprietary media and biometric-derived data. Treat every evidence byte, filename, metadata value and generated preview as hostile input.

## Core security properties

- Evidence sources are opened read-only and never mounted by application code.
- Evidence-derived offsets and lengths are validated before reads or allocations.
- Binary parsers and media decoders run in bounded child processes with fixed arguments,
  reduced environments and execution timeouts. An operating-system sandbox remains a
  deployment gate before untrusted pilot evidence is accepted.
- Analysis workers perform no application-level network calls. Production deployment must
  enforce network denial at the operating-system or container boundary.
- External commands use fixed executables and argument arrays, never shell interpolation.
- Every artifact has a source lineage, tool version, parameters and cryptographic hash.
- Authorization is role- and case-scoped. Non-administrators receive a non-disclosing
  not-found response for unassigned cases. Grants and revocations are immutable records
  linked into the case activity chain; administrators retain recovery access.
- Custody history is append-only and independently verifiable.
- Models, dependencies and releases are pinned and hash-verified.
- Face embeddings and galleries are access-controlled, purpose-limited and retention-bound.

## Reporting vulnerabilities

Until a private reporting address is configured, do not publish sensitive evidence samples, credentials or exploitable case data in public issues. Contact the repository owner privately and provide only the minimum reproduction material required.

## Evidence and test data

Never commit real case evidence. Tests must use synthetic, licensed or explicitly sanitized fixtures with recorded provenance and authorization.
