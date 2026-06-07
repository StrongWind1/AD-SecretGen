# Output Formats

All three formats (`--format text|json|pretty`) carry the **same information**, organised into the same sections — **meta** (the inputs: account-type, realm/domain, `sAMAccountName`, the echoed **password**, the `Kerberos salt`, and any `--netbios`/`--dns-domain`/`--upn` provided), **ntlm** (`nt`, `lm`), **kerberos** (the enctypes, in etype order with the number in parens: `des-cbc-crc (1)`, `des-cbc-md5 (3)`, `aes128-cts-hmac-sha1-96 (17)`, `aes256-cts-hmac-sha1-96 (18)`, `rc4-hmac (23)`), and **wdigest** (the 29 `wdigest[01..29]` hashes) — followed by any **skipped** entries.

Nothing is shown in one format and hidden in another; a row or section is dropped (in every format alike) only when it has no value. They differ only in layout:

- **text** (default) — `[section]` blocks of aligned `label : value` lines, then a trailing `[skipped]` block.
- **json** — each section is a nested object (`meta` / `ntlm` / `kerberos`), with `wdigest` and `skipped` as arrays; machine-readable.
- **pretty** — each section is a grouped `rich` panel (META / NTLM / KERBEROS / WDIGEST).

The PBKDF2 iteration count is a fixed 4096 ([RFC3962] §4) and is documented rather than echoed.

!!! note "Password echo & the hex rule"
    `meta` echoes the **password you supplied** (cleartext for `--password`/stdin; the raw blob as hex for `--password-hex`/`-b64`/`--managed-blob`) so the output is a self-documenting record — note it lands in stdout/redirects/scrollback. Any meta value with a character outside **printable ASCII (`0x21`–`0x7E`)** — space, control, or non-ASCII — is **UTF-8 hex-encoded** and its label/key marked `… (hex)` / `…_hex` (e.g. a Cyrillic `sAMAccountName` becomes `sAMAccountName (hex) : d090…`), so a terminal never receives raw bytes and the value is unambiguous.

!!! info "Which enctypes are salted?"
    The `Kerberos salt` (shown in **meta**) salts **DES (etypes 1, 3) and AES (17, 18)** — all four use the *same* salt. **RC4 (etype 23) is the only saltless enctype**: its key is just the NT hash, so `kerberos.rc4-hmac` equals `ntlm.nt` and is derivable without a realm (which is why it's always present). AES-SHA2 (etypes 19/20) are out of scope — AD's KDC doesn't store them.
