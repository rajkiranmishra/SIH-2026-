# ForenX

ForenX is an offline-first DVR/NVR forensic acquisition, recovery, analysis, and reporting platform for authorized investigators and forensic laboratories.

The product is being built around three non-negotiable properties:

1. Original evidence is opened read-only and never modified.
2. Every recovered or analyzed artifact remains traceable to its source bytes and transformation history.
3. Unsupported evidence and uncertain results are reported explicitly rather than converted into confident claims.

## Current state

This repository contains the new product foundation. It is intentionally separate from the earlier SIH prototype.

Implemented in the first foundation slice:

- Bounded, read-only raw evidence source.
- Streaming SHA-256 calculation and verification.
- Typed DVR adapter contract with physical-extent provenance.
- Hash-linked custody event model and verifier.
- Minimal service health endpoints.
- Initial security, architecture, product, and contribution guidance.
- Automated tests for integrity, bounds, and custody tamper detection.
- Bounded Hikvision signature discovery, including chunk-boundary handling.
- Typed Hikvision master-sector parsing with untrusted-offset safety checks.
- Partition-aware HIKBTREE enumeration for observed 80-byte and 96-byte page layouts.
- Active and partial recording descriptors with exact metadata and video-block provenance.
- Explainable H.264/H.265 Annex-B validation before extraction.
- Non-overwriting, extent-preserving extraction with streaming SHA-256 output hashes.
- Persistent local case database, protected evidence vault, and one-time administrator setup.
- Need-to-know case access layered over role permissions, with creator auto-assignment,
  supervisor-managed grants, immutable revocation history, and non-disclosing denials.
- Examiner workspace for protected clip playback, technical inspection, frame stepping, and immutable timeline bookmarks.
- CCTV container, stream, codec, duration, resolution, frame-rate, and bit-rate inspection in a separate local worker.
- Ed25519-signed evidence manifests and an independent `forenx-verify` command.
- Supervisor-gated PDF and JSON examination reports packaged with encrypted-key
  Ed25519 signatures, archive hashes, and browser-side download verification.
- Immutable supervisor authorization records that restrict future biometric analysis to
  documented, case-specific one-to-one comparison with a retention deadline.
- Offline, authorization-gated YuNet face detection on examiner-selected video frames,
  with a hash-pinned MIT-licensed model, decoded-frame hash, immutable result, protected
  preview, thresholds, landmarks, quality flags, and full activity-chain provenance.
- Source-linked geometric face tracking across an examiner-selected range, retaining every
  contributing detection and frame hash while making no identity claim.
- Signed-report legal handoff artifacts: an unsigned Section 63(4) certificate preparation
  worksheet and independent source SHA-256 report, with missing declarations left visibly
  incomplete for the authorized party, expert, and legal reviewer.

## Vendor support status

"Supported" means evidence has passed detection, enumeration, extraction, corruption,
and real-device validation. Architecture readiness alone is not counted as support.

| Vendor/family | Detection | Metadata | Enumeration | Extraction | Status |
| --- | --- | --- | --- | --- | --- |
| Hikvision proprietary disk | Implemented | Master sector + primary HIKBTREE | Implemented; synthetic validation | Implemented; synthetic validation | Experimental |
| Dahua proprietary disk | Planned | Planned | Planned | Planned | Not started |
| CP Plus/OEM families | Planned | Planned | Planned | Planned | Research queued |
| Unknown H.264/H.265 media | Planned | N/A | Signature carving | Planned | Not started |

The adapter contract allows each family to be added independently. A vendor appears as
fully supported only after authorized image fixtures and repeatable recovery tests pass.

## Development

Requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
forenx-server
```

Open `http://127.0.0.1:8765/app/` to set up the local laboratory workspace.
ForenX listens only on the local computer. Persistent application data is stored in
the platform-specific user data directory; set `FORENX_DATA_DIR` to use an approved
encrypted laboratory volume.

Administrators can see all cases for recovery and governance. Every other user sees only
actively assigned cases, even when their role otherwise permits the requested operation.
Supervisors can manage a case team only after an administrator or another authorized
supervisor assigns them to that case. Databases upgraded from schema version 1 expose
legacy cases only to administrators until explicit assignments are recorded.

## Controlled clip validation

Use exported CCTV clips only when collection is authorized and the people, expected
events, camera clock, and source provenance are documented. Ingesting a clip creates
a read-only vaulted copy and SHA-256 inventory. Technical inspection runs in a separate
local process, and examiner bookmarks reference exact video timestamps without changing
the preserved source.

An exported clip validates the examination workflow. It does not validate proprietary
DVR recovery; that requires an authorized forensic image from a named recorder model.

After the case reaches approved status, a supervisor or administrator can create a
signed examination package from the case workspace. The first export creates an
encrypted local laboratory key using the supplied signing password; later exports
must unlock that same key. The password is not stored. Each download is checked against
the package archive SHA-256 before it is saved by the browser.

## Product sequence

The first supported recovery path will be:

```text
Raw/DD image -> Hikvision probe -> recording enumeration -> extent-preserving extraction
-> H.264/H.265 validation -> playable derivative -> custody-aware evidence package
```

See the [product roadmap](docs/product/ROADMAP.md),
[Hikvision format notes](docs/forensics/HIKVISION_FORMAT_NOTES.md),
[video examination notes](docs/forensics/VIDEO_EXAMINATION.md),
[signed reporting notes](docs/forensics/SIGNED_REPORTING.md),
[Section 63(4) worksheet notes](docs/forensics/SECTION_63_WORKSHEET.md),
[face-analysis governance](docs/forensics/FACE_ANALYSIS_GOVERNANCE.md),
[face-detection implementation notes](docs/forensics/FACE_DETECTION.md),
[face-tracking boundaries](docs/forensics/FACE_TRACKING.md), and the
[architecture decision](docs/architecture/ADR-0001-modular-monolith.md).

## Important boundary

ForenX supports forensic documentation and reproducible analysis. Software output alone does not determine whether evidence is admissible; that decision depends on applicable law, procedure, provenance, expert testimony, and the facts of the case.
