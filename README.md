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
uvicorn forenx.api.app:app --reload
```

Open `http://127.0.0.1:8000/health/ready` to verify the local service.

## Product sequence

The first supported recovery path will be:

```text
Raw/DD image -> Hikvision probe -> recording enumeration -> extent-preserving extraction
-> H.264/H.265 validation -> playable derivative -> custody-aware evidence package
```

See the [product roadmap](docs/product/ROADMAP.md), [Hikvision format notes](docs/forensics/HIKVISION_FORMAT_NOTES.md),
and [architecture decision](docs/architecture/ADR-0001-modular-monolith.md).

## Important boundary

ForenX supports forensic documentation and reproducible analysis. Software output alone does not determine whether evidence is admissible; that decision depends on applicable law, procedure, provenance, expert testimony, and the facts of the case.
