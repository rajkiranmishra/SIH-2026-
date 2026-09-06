# Source-linked Face Tracking

ForenX can link face detections from examiner-selected video positions into geometric
continuity hypotheses. Tracking is deliberately separate from identity recognition.

## Method

1. The examiner opens an inspected, preserved video source.
2. An active supervisor authorization must cover the source.
3. The examiner runs the hash-pinned detector at two or more relevant positions.
4. The examiner selects a start and end position and creates a tracking run.
5. ForenX deduplicates identical decoded-frame observations and greedily associates
   bounding boxes using normalized intersection-over-union (IoU) and a fixed maximum
   time gap.

The immutable result records the selected range, IoU threshold, maximum gap, algorithm
and version, every included detection run, decoded-frame hashes, detection identifiers,
box coordinates, confidence values, and association scores. Tracking records are added
to the signed JSON and PDF examination report.

## Evidentiary boundary

A track means that bounding boxes overlap sufficiently across sampled frames. It does
not prove that observations depict the same person, and it never establishes identity.
Sparse sampling, occlusion, camera motion, cuts, scale changes, and crowding can split or
merge geometric tracks. An examiner must review the source-linked frames and state these
limitations in any conclusion.

ForenX does not use a track as recognition input. Identity comparison remains disabled
until a separately licensed model, representative validation data, documented thresholds,
human review procedure, and legal approval are available.
