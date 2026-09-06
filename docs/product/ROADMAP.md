# Product Roadmap

## Phase 0 — Foundation

- [x] Case, exhibit, evidence source, artifact and custody domain model.
- [x] Local authentication, role permissions, and need-to-know case assignments.
- [x] Browser-based laboratory user onboarding for administrators.
- [ ] Durable background jobs.
- [x] Immutable audit events.
- [x] Security baseline, CI and offline development workflow.

## Phase 1 — Evidence integrity

- Raw/DD/IMG and split-image providers.
- E01 provider after separate validation.
- [x] Streaming hashes, transfer verification and source inventory.
- [x] Government-aligned intake and custody forms.

## Phase 2 — Hikvision recovery

- [x] Bounded dynamic signature probing.
- [x] Master-sector parsing with structural safety checks.
- [x] Bounded primary HIKBTREE parsing for observed 48-byte entry layouts.
- [x] Recording enumeration with physical extents using synthetic fixtures.
- [ ] Real-device HIKBTREE validation across supported firmware samples.
- [ ] Secondary HIKBTREE and embedded SQLite cross-index validation.
- [x] H.264/H.265 Annex-B parameter-set validation using synthetic fixtures.
- [x] Non-overwriting exact block extraction with streaming output hashes.
- [x] Case-scoped browser workflow for probe, enumeration, exact extraction, and verified
  artifact download.
- [ ] FFprobe validation and safe remuxing of derivative copies.

## Phase 3 — Investigation workspace

- [x] Protected playback, technical inspection, frame stepping, and examiner bookmarks.
- [ ] Interactive multi-source event timeline.
- [ ] Motion/object observations.
- Multi-camera clock correction and correlation.
- Findings linked to original evidence provenance.

## Phase 4 — Review and export

- [x] Supervisor approval workflow.
- [x] Signed evidence manifest and independent verifier.
- [x] Supervisor-gated PDF and JSON examination report package.
- [x] Unsigned Section 63(4) certificate preparation worksheet and source hash report;
  final statutory form completion remains subject to signatory and jurisdictional review.
- [x] Immutable supervisor authorization gate for controlled biometric analysis.
- [x] Face detection with source-frame provenance and a hash-pinned model registry.
- [x] Source-linked geometric face tracking across a human-selected time range.
- [ ] Human-reviewed, case-specific one-to-one similarity comparison after model licence
  and validation gates pass.

## Phase 5 — Hardening and pilot

- [ ] Parser fuzzing and operating-system-enforced worker isolation.
- [ ] Realistic performance and recovery validation.
- [ ] Offline installers, upgrade/rollback and restore drills.
- [ ] External forensic, security and usability review.

Each phase has a release gate. Vendor breadth never takes priority over validating the existing adapter.
