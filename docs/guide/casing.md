# Casing & the Kerberos Salt

`NT`, `LM`, and `RC4-HMAC` depend **only on the password** — the casing of `--user`/`--realm` is irrelevant to them. But the **Kerberos keys (DES/AES) are salted**, and the salt's casing rules differ by account type:

| account type | salt | casing behaviour |
|--------------|------|------------------|
| **user** | `UPPER(realm) + sAMAccountName` | `sAMAccountName` is **case-preserved** — you must pass the exact stored case |
| **computer / gMSA** | `UPPER(realm) + "host" + lower(name) + "." + lower(dns)` | name and DNS are **lowercased** — any input case works |
| **trust** | `UPPER(realm) + "krbtgt" + name-without-$` | the partner flat-name is case-preserved (as stored) |

The realm — Kerberos's name for the AD **domain** — is always uppercased, so `--realm corp.local`, `CORP.LOCAL`, and `Corp.Local` are equivalent.

!!! warning "The footgun"
    For **user** and **trust** accounts, passing the wrong `sAMAccountName` case (`ALICE` vs `alice`) produces a *wrong but valid-looking* salt and therefore wrong AES/DES keys — with **no error**. The NT hash still matches, so the mistake is easy to miss. If you don't know the exact stored case, get it from the KDC (below) and pass it via `--salt`, which skips salt construction entirely.

**WDigest is case-insensitive by design.** The 29 hashes *are* the casing permutations — as-stored, all-lowercase, all-uppercase, and mixed, for the NetBIOS, DNS, and `DOMAIN\user` forms. That is exactly why digest authentication matches a username in any case: AD pre-stores every common casing.

## Let the KDC tell you the casing (CredWolf)

You never have to guess. **The KDC returns the authoritative salt** — carrying the exact realm and username casing — in the `PA-ETYPE-INFO2` pre-auth data of its response to a *bare* AS-REQ. This is **not a login attempt**: it does not increment the bad-password counter and cannot lock the account out, and you only need the **username**, not the password.

[CredWolf](https://github.com/StrongWind1/CredWolf) implements this. Doing Kerberos AES auth, it sends the bare AS-REQ, reads the salt, recovers the correctly-cased username, and reports e.g. `Username case corrected by KDC: ALICE → alice`. Feed the result back:

```bash
# the corrected username…
ad-secretgen --user alice --realm corp.local --password 'P@ssw0rd!'
# …or, most robustly, the salt verbatim:
ad-secretgen --salt 'CORP.LOCALalice' --password 'P@ssw0rd!' --user alice --realm corp.local
```

The `--salt` route is bulletproof: it also handles accounts whose salt is **not** `REALM+username` at all — most notably the built-in **Administrator** (and **krbtgt**), whose salt is frozen from the DC's *original install-time hostname* (e.g. `WIN-ABC123Administrator`).

!!! note "Caveat"
    This trick needs **AES** (which is what triggers salt retrieval) and does **not** work for **AS-REP-roastable** accounts — with pre-auth disabled the KDC returns an AS-REP with no `PA-ETYPE-INFO2`, so there is no salt to read. For those, supply the exact case yourself or use RC4 (which has no salt).
