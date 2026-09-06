# Offline Face Detection

## Scope

ForenX can locate faces on a single examiner-selected frame from an already ingested and
technically inspected video. The feature is disabled until a supervisor or administrator
records an active, case-specific biometric authorization. It does not identify people,
search a gallery, run on a live feed, or declare a match.

## Evidence flow

1. The preserved evidence file is rehashed before analysis.
2. A bounded child process decodes the nearest available frame at the requested timestamp.
3. The source-frame digest is calculated over the original decoded BGR bytes, prefixed by
   the four-byte big-endian frame width and height.
4. A PNG preview is created from that decoded frame and hashed separately.
5. YuNet runs locally with the CPU execution provider. Boxes, five landmarks, confidence,
   quality flags, thresholds, model identity, runtime version, authorization identifier,
   timestamps and both hashes are stored as immutable records.
6. The protected examiner view verifies the preview hash before serving it and overlays the
   stored observations without changing the image.

The preview is a demonstrative derivative. The original evidence remains controlling.

## Pinned detector

| Field | Value |
| --- | --- |
| Model | OpenCV Zoo YuNet face detector |
| Artifact | `face_detection_yunet_2026may.onnx` |
| Task | Face location only |
| Licence | MIT |
| SHA-256 | `ebafce4e3c118d6554634be5c27ab333b4c047a9a8c3faf1d7cf93101c22f0f0` |
| Source | <https://github.com/opencv/opencv_zoo/tree/main/models/face_detection_yunet> |
| Runtime | ONNX Runtime CPU execution provider |

The packaged model is verified against the pinned digest before every run. A changed or
missing artifact fails closed. Recognition weights are not bundled.

## Current safety boundary

The child process has a fixed command, isolated Python mode, a reduced environment, bounded
input dimensions, bounded output, one inference thread, and a timeout. This is process
separation, not a complete operating-system sandbox. A pilot handling untrusted evidence
must additionally enforce worker filesystem, memory, CPU and network limits at the host or
container boundary.

## Validation status

Automated tests cover model integrity, offline inference, timestamp bounds, unsafe paths,
authorization, source re-verification, immutable storage, access-controlled preview delivery
and preview tamper detection. A blank synthetic video is the current reproducible inference
fixture. Accuracy, false-positive, false-negative, demographic and CCTV-condition testing on
authorized representative data is still required before operational claims can be made.
