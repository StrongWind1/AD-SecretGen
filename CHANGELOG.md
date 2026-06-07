# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-07

### Added

- Initial release. Derive every password-derived secret Active Directory stores PEK-encrypted in `NTDS.dit`, byte-for-byte, from a cleartext password or a raw password blob: the **NT** and **LM** hashes, **RC4-HMAC** (etype 23), **Kerberos DES** (etype 1/3), **AES128/AES256** (etype 17/18), and the **29 WDigest** hashes. The inverse of NTDSWolf.
- Password sources: `--password` (cleartext, or `-` for stdin), `--password-hex`, and `--password-b64`, with `--managed-blob` to parse a gMSA/dMSA `MSDS-MANAGEDPASSWORD_BLOB` ([MS-ADTS] 2.2.19) and derive from its `CurrentPassword`.
- Correct Kerberos salting by account class: user, computer/gMSA (`host/` salt), and interdomain trust (`krbtgt/<partner>` salt). `--account-type` defaults to `computer` for `--managed-blob` or a `$`-suffixed name; `--salt` overrides the salt verbatim for accounts (Administrator, krbtgt) with a frozen install-time salt.
- Three output formats (`text` / `json` / `pretty`) that all carry the identical sections — `meta` / `ntlm` / `kerberos` / `wdigest` — with the supplied password echoed and any non-printable-ASCII meta value UTF-8 hex-encoded.
- Validated byte-for-byte against real AD (DSInternals `Get-ADReplAccount`, cross-checked with secretsdump) and against the published [RFC3961]/[RFC3962] and NT/LM known-answer vectors.
