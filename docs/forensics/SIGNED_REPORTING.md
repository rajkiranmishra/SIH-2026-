# Signed Examination Reporting

ForenX creates a portable report only after the case reaches `approved` or `closed`
status. Report signing requires the supervisor permission and repeats the SHA-256 check
of the vaulted source immediately before export.

Structured reports that include controlled analysis use schema
`forenx-examination-report/v3`.

## Package contents

Each `.zip` download contains:

- `examination-report.pdf` for human review;
- `examination-report.json` containing the same structured case facts and observations;
- one PNG demonstrative derivative for each included face-detection run, named by its
  immutable run identifier;
- `section-63-4-support-worksheet.pdf`, visibly marked as an unsigned preparation
  worksheet and never represented as the statutory certificate;
- `source-hash-report.json`, recording the independently rechecked source SHA-256 for
  attachment and signatory verification;
- `manifest.json` inventorying the report artifacts, source hash, limitations, and the
  exported custody snapshot;
- `manifest.signature.json` containing the Ed25519 signature, public key, signer, and
  signing-key fingerprint.

The package does not duplicate the source video or disk image. Its manifest records the
source filename, size, SHA-256, acquisition method, and read-only treatment. The source
must be preserved and produced separately when required.

When controlled face detection exists, the JSON and PDF include the authorization,
timestamps, face count, model identity and hash, runtime, thresholds, decoded-frame hash,
preview hash, boxes, landmarks and quality flags. Every preview is reverified and then
inventoried as a signed package artifact. A preview is a demonstrative derivative and does
not establish identity.

Geometric tracking runs are serialized with their contributing detection and decoded-frame
identifiers, association parameters, and an explicit non-identification qualification.

## Signing-key handling

The first successful export creates one encrypted Ed25519 private key in the protected
local product data directory. The operator chooses the signing password. That password
is used only for the current request and is not stored by ForenX. Later reports require
the same password, which keeps one stable public-key fingerprint for the laboratory.

The fingerprint must be distributed to reviewers through a separately trusted channel.
An embedded public key can prove that a package has not changed since signing, but it
cannot establish the signer's identity without that external trust anchor.

## Independent verification

Extract the package into a new directory and run:

```bash
forenx-verify /path/to/extracted-package \
  --trusted-key-fingerprint EXPECTED_SHA256_FINGERPRINT
```

The verifier checks the manifest signature, trusted fingerprint, report sizes and
SHA-256 hashes, custody sequence, custody linkage, and custody event hashes.

## Legal boundary

The generated report is a technical examination record. It does not itself decide
admissibility and does not replace a certificate, declaration, expert opinion, or other
procedure required by the applicable court or jurisdiction. A jurisdiction-specific
certificate worksheet must be reviewed by qualified legal and forensic practitioners
before operational use.

ForenX now provides only the preparation worksheet described above. It intentionally
leaves personal declarations, source-control facts, independent expert verification,
date, time, place, designation, and signatures incomplete. See the
[worksheet implementation boundary](SECTION_63_WORKSHEET.md).
