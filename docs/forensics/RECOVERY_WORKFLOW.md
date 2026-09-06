# Recovery workflow

ForenX connects an ingested raw DVR/NVR disk image to the registered adapter set through
the case workspace. An authorized examiner can run the following sequence:

1. Recompute the vaulted source SHA-256.
2. Probe every registered adapter and select a match only above the configured confidence
   threshold and outside the ambiguity margin.
3. Enumerate bounded recording descriptors with their exact physical source extents.
4. Store the source hash, every adapter probe result, probe failures, warnings, timestamps,
   confidence, and descriptors in an immutable recovery scan.
5. Extract one descriptor as an exact source-extent copy into the read-only recovery vault.
6. Recompute the extracted artifact SHA-256 before registering it and again before every
   download.
7. Verify the download once more in the browser before saving it.
8. Optionally register the exact recovered stream directly in the protected video examiner.
   ForenX creates a separate read-only vault copy and retains the parent image ID and hash,
   recovery scan and descriptor IDs, physical extents, warnings, and extraction hash.

Signed reports for a registered recovered stream rehash both the stream and its parent disk
image. Report schema v4 and the human-readable PDF carry the complete recovery lineage and
explicitly identify the stream as a derivative.

Every probe and extraction attempt is written to the case activity chain. Database triggers
also reject recovery writes outside an active case and reject updates or deletion of recovery
records.

## Deliberate boundaries

- A probe match is a technical observation, not a vendor-support claim. The web interface
  continues to label Hikvision support experimental until named real recorder models pass the
  validation register.
- Current extraction is an exact H.264/H.265 Annex-B block copy. It is not remuxed, decoded,
  enhanced, or treated as a new original.
- Scans and extraction currently run synchronously on the local service. Durable background
  jobs, cancellation, progress reporting, and crash recovery remain required before large
  multi-terabyte image pilots.
- Proprietary recovery validation still requires authorized raw images from known recorder
  models; an exported CCTV clip only validates the video-examination path.
