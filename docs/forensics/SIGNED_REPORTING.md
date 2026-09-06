# Signed Examination Reporting

ForenX creates a portable report only after the case reaches `approved` or `closed`
status. Report signing requires the supervisor permission and repeats the SHA-256 check
of the vaulted source immediately before export.

## Package contents

Each `.zip` download contains:

- `examination-report.pdf` for human review;
- `examination-report.json` containing the same structured case facts and observations;
- `manifest.json` inventorying the report artifacts, source hash, limitations, and the
  exported custody snapshot;
- `manifest.signature.json` containing the Ed25519 signature, public key, signer, and
  signing-key fingerprint.

The package does not duplicate the source video or disk image. Its manifest records the
source filename, size, SHA-256, acquisition method, and read-only treatment. The source
must be preserved and produced separately when required.

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
before it is added to the product.
