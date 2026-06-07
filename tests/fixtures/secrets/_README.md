# Golden secret fixtures

One JSON per throwaway lab account — `{password, identity, expected, oracle_skip_fields, notes, source}`. The `expected` values are what Active Directory actually stores, captured from a live DC by **DSInternals `Get-ADReplAccount`** and cross-checked against **impacket `secretsdump -just-dc`**; the two tools agreed on all 46 overlapping accounts (2026-06-07).

These pin `gen_secrets.py`: each test loads a fixture, runs `compute_secrets(Identity(**identity), password)`, and asserts field-by-field equality against `expected`, skipping any field listed in `oracle_skip_fields`.

## Realm is real, not masked

The hashes are cryptographically bound to the `snow.lab` / `SNOW` realm (it is part of every Kerberos salt and every WDigest pre-image), so masking it would invalidate them. No IPs, hostnames, or topology appear; the accounts are disposable test principals.

## Coverage

| Fixture | Pins |
|---------|------|
| `svc_ascii` | user with an explicit UPN — proves a UPN does **not** change the salt |
| `svc_long` | >14-char password — LM blank placeholder |
| `svc_uni1` | Latin-1-range non-ASCII — WDigest Latin-1 + DES ANSI codepage |
| `svc_uni2` | >U+00FF (Cyrillic) — NT/AES reproducible; DES/WDigest are AD-stored but outside the oracle's codepage scope (`oracle_skip_fields`) |
| `svc_dollar` | user-class `$`-named account — the trust salt rule |
| `WSGOLD` | computer account — the `host/` salt rule |
| `nw_reverse` | reversible-encryption account — `Primary:CLEARTEXT` present in AD, omitted by the oracle |
