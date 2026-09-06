# Hikvision Format Notes

## Status

The current adapter implements read-only parsing for one empirically observed Hikvision
disk family. It is not yet a declaration that all Hikvision models or firmware versions
are supported.

Current validation level:

- Synthetic raw-image fixtures: passing.
- Truncated, oversized, ambiguous and out-of-range structures: covered by tests.
- Whole-disk MBR and partition-image offset models: covered by tests.
- Sanitized images from real DVR hardware: pending.
- Independent examiner/tool comparison: pending.

## Observed layout

The parser recognizes:

- `HIKVISION@HANGZHOU` master-sector signature.
- Partition-relative master-sector pointers.
- `HIKBTREE` at the declared offset or the observed `+16` variant.
- 48-byte page-list and recording entries.
- Both 80-byte and 96-byte page-header variants when the layout is unambiguous.
- Video, empty and unknown raw status values.
- `0x7fffffff` partial/incomplete timestamp markers.

The parser preserves raw timestamps and status bytes. Display timestamps are normalized
to UTC but explicitly marked as timezone-unverified until the DVR configuration and case
context establish the device timezone and clock accuracy.

## Safety rules

- Vendor offsets are bounds-checked before every read.
- Page and entry counts have explicit upper limits.
- Conflicting 80/96-byte layouts fail instead of selecting one heuristically.
- Out-of-image video extents are not returned as extractable recordings.
- Empty and unknown-status entries are not described as active video.
- Extraction requires an observable H.264 SPS/PPS or H.265 VPS/SPS/PPS Annex-B sequence.
- Existing output paths are never overwritten.
- Exact source extents are copied without decoding or remuxing and hashed during writing.

## Research provenance

The structure model was independently reimplemented after comparing:

- [akira7799/hikvision-dvr-parser](https://github.com/akira7799/hikvision-dvr-parser)
- [vishwajitsarnobat/HIKVISION-DVR-Tool](https://github.com/vishwajitsarnobat/HIKVISION-DVR-Tool)
- Han, Jeong and Lee, *Analysis of the HIKVISION DVR File System* (2015), as cited by
  those implementations.

These community implementations disagree on some header offsets and describe testing
against limited firmware families. ForenX therefore treats structural variation as an
explicit compatibility question and requires its own authorized fixtures before a
model/firmware combination can enter the supported-device matrix.

## Required real-device fixture record

Each approved fixture must record the DVR/NVR model, firmware version, disk topology,
acquisition method, full-image hashes, known recording/channel/time ground truth, device
timezone and clock drift, expected overwritten regions, and authorization/sanitization
status. Raw evidence must stay outside the source repository.
