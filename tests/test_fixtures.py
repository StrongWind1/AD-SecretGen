"""Golden-fixture tests: gen_secrets.compute_secrets vs real-AD values.

Each fixture's ``expected`` block was captured from a live DC (DSInternals
Get-ADReplAccount, cross-checked against impacket secretsdump — 46/46 agree).
``oracle_skip_fields`` marks fields AD stores but the oracle cannot reproduce
by design (NoLMHash blank LM; non-Western >U+00FF DES/WDigest); those are
asserted as visible xfails so the limitations never go silent.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

import ad_secretgen as g

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "secrets"
FIXTURES = sorted(FIXTURE_DIR.glob("*.json"))
IDS = [p.stem for p in FIXTURES]

_SKIP_REASON = {
    "lm_hash": "NoLMHash domain: AD stores a blank LM; the oracle emits the true LM hash (see the LM KATs)",
    "des_cbc_md5": "non-Western password (>U+00FF) outside the DES ANSI codepage",
    "des_cbc_crc": "non-Western password (>U+00FF) outside the DES ANSI codepage",
    "wdigest": "non-Western password (>U+00FF) outside the WDigest ISO-8859-1 codepage",
}


def _hex(b):
    return b.hex() if b is not None else None


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _identity(fx):
    idn = fx["identity"]
    return g.Identity(
        sam_account_name=idn["sam_account_name"],
        realm_dns=idn["realm_dns"],
        account_type=g.AccountType(idn["account_type"]),
        netbios_domain=idn["netbios_domain"],
        dns_domain=idn["dns_domain"],
        upn=idn["upn"],
    )


def _material(fx):
    if "password_b64" in fx or "password_hex" in fx:
        blob = base64.b64decode(fx["password_b64"]) if "password_b64" in fx else bytes.fromhex(fx["password_hex"])
        return g.PasswordMaterial.from_managed_blob(blob) if fx.get("managed_blob") else g.PasswordMaterial.from_blob(blob)
    return fx["password"]


def _emitted(secrets):
    return {
        "nt_hash": secrets.nt.hex(),
        "lm_hash": secrets.lm.hex(),
        "rc4_hmac": secrets.rc4_hmac.hex(),
        "des_cbc_md5": _hex(secrets.des),
        "des_cbc_crc": _hex(secrets.des),
        "aes128_cts_hmac_sha1_96": _hex(secrets.aes128),
        "aes256_cts_hmac_sha1_96": _hex(secrets.aes256),
        "kerberos_salt": secrets.salt,
        "wdigest": [x.hex() for x in secrets.wdigest],
    }


@pytest.mark.parametrize("path", FIXTURES, ids=IDS)
def test_oracle_matches_real_ad(path):
    fx = _load(path)
    got = _emitted(g.compute_secrets(_identity(fx), _material(fx)))
    skip = set(fx.get("oracle_skip_fields", []))
    for field, expected in fx["expected"].items():
        if field in skip or expected is None or (field == "wdigest" and not expected):
            continue
        assert got[field] == expected, f"{path.stem}: {field}"


_LIMITS = [(p.stem, p, fld) for p in FIXTURES for fld in _load(p).get("oracle_skip_fields", [])]


@pytest.mark.parametrize(("name", "path", "field"), _LIMITS, ids=[f"{n}-{f}" for n, _, f in _LIMITS])
def test_documented_limitations(name, path, field):
    pytest.xfail(_SKIP_REASON.get(field, "out of scope"))
