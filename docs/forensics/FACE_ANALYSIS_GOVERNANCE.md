# Face Analysis Governance

## Product boundary

ForenX may assist an authorized examiner with post-acquisition analysis of a specific,
lawfully obtained CCTV source. It must not become a live-surveillance or general
watchlist system.

The allowed comparison workflow is deliberately narrow:

1. A supervisor records the case purpose, legal-authority reference, reference-image
   provenance, retention deadline, and predetermined threshold policy.
2. The source is an already-ingested and technically inspected video.
3. An examiner may detect and track faces and compare one human-selected face with one
   case-specific reference (`one-to-one`).
4. The system reports a similarity score, threshold, quality limitations, model identity
   and model hash. It never names a person or declares a match.
5. A human examiner records the conclusion. Uncertain input may produce no comparison.

The following are outside the product boundary:

- open-world or one-to-many gallery search;
- live camera watchlists or automated alerts;
- automatic identity, guilt, arrest, or adverse-action decisions;
- emotion, caste, religion, ethnicity, gender, health, or other sensitive-trait inference;
- comparison against an image whose lawful origin and case relevance are undocumented.

## Reconstruction and enhancement

The preserved source and decoded original frame remain controlling. Any enhancement or
reconstruction is a separately stored, hashed, clearly labelled demonstrative derivative.
It must retain its source frame position, transformation history, tool/model identity,
parameters and operator. Generated or reconstructed pixels must never be represented as
observed fact or used as input to biometric comparison.

## Evidence and audit requirements

Every analysis record must bind the following to the case activity chain:

- evidence source SHA-256, stream index and source timestamp/frame position;
- original crop coordinates and a hash of the decoded input frame;
- authorization identifier and expiry;
- detector/comparator name, version, model hash and configured threshold;
- input-quality flags, raw score, result category and explicit limitations;
- operator identity, execution time and human-reviewed conclusion.

ForenX reports remain technical examination records. They do not replace the electronic
record certificate described by section 63(4) and the Schedule of the Bharatiya Sakshya
Adhiniyam, 2023.

## Authority hierarchy used for the design

### In-force evidence law

The Bharatiya Sakshya Adhiniyam, 2023 has applied since 1 July 2024. Section 63 addresses
admissibility of electronic records, and subsection 63(4) describes the certificate and
device particulars that accompany an electronic record when submitted.

- [Bharatiya Sakshya Adhiniyam, 2023 — official India Code PDF](https://www.indiacode.nic.in/indiacode/bitstream/123456789/20063/1/aa202347.pdf)

### Government procurement baseline

The Ministry of Home Affairs advised government procurement of CCTV and biometric
systems against IS 19380 Part 1:2025 / ISO/IEC 30137-1:2024 for system design and
IS 19380 Part 4:2025 / ISO/IEC 30137-4:2021 for ground-truth and video annotation.
Conformance must be independently established; this repository does not claim it yet.

- [MHA Office Memorandum, 1 December 2025](https://www.mha.gov.in/sites/default/files/BIS_02122025.pdf)

### Responsible-AI guidance

NITI Aayog's facial-recognition paper is guidance, not binding law. This design adopts its
useful controls: lawful and proportionate purpose, privacy by design, a predetermined
threshold, the option to return no result, human review, representative accuracy testing,
audit trails and defined retention.

- [NITI Aayog Responsible AI for All — Facial Recognition Technology](https://www.niti.gov.in/node/1437)

### Data-protection transition

The Digital Personal Data Protection Rules, 2025 and the associated commencement
notification use phased start dates. As of 6 September 2026, many core provisions are
scheduled to commence 18 months after Gazette publication. ForenX should implement
purpose limitation, minimisation, access control, retention and deletion now rather than
wait for the transition to finish.

- [Digital Personal Data Protection Rules, 2025 — official Gazette PDF](https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf)
- [DPDP Act commencement notification — official Gazette PDF](https://www.meity.gov.in/static/uploads/2025/11/c56ceae6c383460ca69577428d36828b.pdf)

## Model-release gate

No recognition model may be bundled until its weights, training-data provenance and
deployment licence pass documented legal and technical review. The OpenCV Zoo SFace
documentation refers to Apache 2.0, but an unresolved upstream issue asks for clarity on
the pretrained weights' training-data and commercial-use provenance. SFace is therefore
not approved for bundling at this stage.

- [OpenCV Zoo SFace model documentation](https://github.com/opencv/opencv_zoo/blob/main/models/face_recognition_sface/README.md)
- [OpenCV Zoo SFace weights provenance issue](https://github.com/opencv/opencv_zoo/issues/313)

Every candidate model must additionally pass held-out validation on relevant Indian CCTV
conditions, segment-specific error analysis, spoof/quality testing and reproducible
threshold calibration before any operational claim is made.
