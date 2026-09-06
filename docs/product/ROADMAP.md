# Product Roadmap

## Phase 0 — Foundation

- Case, exhibit, evidence source, artifact and custody domain model.
- Local authentication and role-based access.
- Durable jobs and immutable audit events.
- Security baseline, CI and offline development workflow.

## Phase 1 — Evidence integrity

- Raw/DD/IMG and split-image providers.
- E01 provider after separate validation.
- Streaming hashes, transfer verification and source inventory.
- Government-aligned intake and custody forms.

## Phase 2 — Hikvision recovery

- [x] Bounded dynamic signature probing.
- [x] Master-sector parsing with structural safety checks.
- [x] Bounded primary HIKBTREE parsing for observed 48-byte entry layouts.
- [x] Recording enumeration with physical extents using synthetic fixtures.
- [ ] Real-device HIKBTREE validation across supported firmware samples.
- [ ] Secondary HIKBTREE and embedded SQLite cross-index validation.
- [x] H.264/H.265 Annex-B parameter-set validation using synthetic fixtures.
- [x] Non-overwriting exact block extraction with streaming output hashes.
- [ ] FFprobe validation and safe remuxing of derivative copies.

## Phase 3 — Investigation workspace

- Interactive video and event timeline.
- Motion/object observations and examiner bookmarks.
- Multi-camera clock correction and correlation.
- Findings linked to original evidence provenance.

## Phase 4 — Review and export

- Supervisor approval workflow.
- Signed evidence manifest and independent verifier.
- Report and Section 63 support worksheet.
- Optional face detection/tracking and controlled similarity comparison.

## Phase 5 — Hardening and pilot

- Parser fuzzing and worker isolation.
- Realistic performance and recovery validation.
- Offline installers, upgrade/rollback and restore drills.
- External forensic, security and usability review.

Each phase has a release gate. Vendor breadth never takes priority over validating the existing adapter.
