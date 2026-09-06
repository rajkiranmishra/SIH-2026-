# Section 63(4) Certificate Support Worksheet

## Why it exists

Section 63(4) of the Bharatiya Sakshya Adhiniyam, 2023 requires a certificate to accompany
an electronic record each time it is submitted for admission under that section. The
certificate identifies the record and its manner of production, gives relevant device
particulars, addresses the operational conditions in section 63(2), and follows the
Schedule. The Schedule separates information to be completed by the party from information
to be completed by the expert and calls for a hash report.

- [Bharatiya Sakshya Adhiniyam, 2023 - official India Code PDF](https://www.indiacode.nic.in/indiacode/bitstream/123456789/20063/1/aa202347.pdf)

## Product boundary

ForenX creates `section-63-4-support-worksheet.pdf` and `source-hash-report.json` inside
the signed examination package. These are preparation and verification aids, not a
certificate. The worksheet is prominently marked `UNSIGNED WORKSHEET - NOT A CERTIFICATE`
on every page.

ForenX prepopulates only facts it can verify from the case record and evidence vault:

- case, report, exhibit, and source identifiers;
- original filename, media kind, byte size, and SHA-256;
- recorded device make, model, serial number, and collection authority reference; and
- the result of the immediate pre-export evidence-integrity recheck.

It deliberately leaves declarant identity, relationship details, address, device control,
ordinary-course operation, unrecorded device identifiers, independent expert hash,
designation, signature, date, IST time, and place for authorized humans to complete.

## Release gate

Before operational court use, the exact output must be reviewed against the then-current
statute, applicable procedural rules, court directions, laboratory policy, and the facts of
the specific acquisition. Both the appropriate person in charge or management and the
expert must independently verify statements they sign. The ForenX Ed25519 package signature
protects package integrity; it does not replace their statutory signatures or establish
admissibility.
