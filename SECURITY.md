# Security Policy

## Scope

ForenX processes untrusted disk images, proprietary media and biometric-derived data. Treat every evidence byte, filename, metadata value and generated preview as hostile input.

## Core security properties

- Evidence sources are opened read-only and never mounted by application code.
- Evidence-derived offsets and lengths are validated before reads or allocations.
- Binary parsers and media decoders run in restricted worker processes.
- Analysis workers have no network access by default.
- External commands use fixed executables and argument arrays, never shell interpolation.
- Every artifact has a source lineage, tool version, parameters and cryptographic hash.
- Authorization is role- and case-scoped.
- Custody history is append-only and independently verifiable.
- Models, dependencies and releases are pinned and hash-verified.
- Face embeddings and galleries are access-controlled, purpose-limited and retention-bound.

## Reporting vulnerabilities

Until a private reporting address is configured, do not publish sensitive evidence samples, credentials or exploitable case data in public issues. Contact the repository owner privately and provide only the minimum reproduction material required.

## Evidence and test data

Never commit real case evidence. Tests must use synthetic, licensed or explicitly sanitized fixtures with recorded provenance and authorization.

