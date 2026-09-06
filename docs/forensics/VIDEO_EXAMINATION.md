# Video Examination Boundary

## Purpose

The first ForenX video workflow is designed for controlled validation with an exported
CCTV clip. It preserves the uploaded bytes, records their SHA-256 digest, inspects media
structure in a separate local process, serves authenticated range requests for playback,
and stores examiner bookmarks as immutable case-linked observations.

## What the workflow proves

- The received clip can be tied to a case and exhibit with collection authority.
- The vaulted copy matches the digest recorded at intake.
- Container and stream properties can be reproduced with the recorded PyAV version.
- An examiner can revisit an observation at the stored millisecond timestamp.
- Inspection and bookmark events remain present in the case activity hash chain.

## What it does not prove

- That an exported clip is the complete contents of a DVR or NVR.
- That recorder timestamps are accurate or synchronized with civil time.
- That browser playback decodes every proprietary CCTV container.
- That a visible person has been identified.
- That a generated or enhanced frame is an original camera frame.

## Controlled validation protocol

1. Obtain written authorization for the test and use consenting participants.
2. Record camera identity, recorder time, observed clock offset, export method, filename,
   expected events, and test start/end times before analysis.
3. Export the clip without opening the original recorder disk through ForenX.
4. Register the case and exhibit, then ingest the exported file as `video-file` evidence.
5. Verify the recorded digest, run technical inspection, and review the clip.
6. Bookmark the pre-recorded expected events without changing the source.
7. Compare observed timestamps and events with ground truth and record discrepancies.
8. Export and independently verify the evidence package when reporting is connected.

Raw recorder recovery requires a separate, write-protected forensic image and a named
model/firmware validation record.
