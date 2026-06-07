"""Published known-answer vectors — independent of the lab.

NT/LM are the well-known NTOWFv1/LMOWFv1 values ([MS-NLMP] 3.3.1); the Kerberos
vectors are transcribed from [RFC3961] section 6.2 (DES) and [RFC3962]
Appendix B (AES). DES is additionally validated byte-for-byte against real AD by
the lab fixtures.
"""

from __future__ import annotations

import pytest

import ad_secretgen as g


@pytest.mark.parametrize(
    ("password", "expected"),
    [
        ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        ("Password", "a4f49c406510bdcab6824ee7c30fd852"),
        ("OLDPASSWORD", "6677b2c394311355b54f25eec5bfacf5"),
    ],
)
def test_nt_hash(password, expected):
    assert g.compute_nt_hash(password).hex() == expected
    assert g.compute_secrets(g.Identity(sam_account_name="u", realm_dns=""), password).rc4_hmac.hex() == expected


@pytest.mark.parametrize(
    ("password", "expected"),
    [
        ("", "aad3b435b51404eeaad3b435b51404ee"),
        ("OLDPASSWORD", "c9b81d939d6fd80cd408e6b105741864"),
        ("ThisIsLongerThan14Chars", "aad3b435b51404eeaad3b435b51404ee"),  # >14 OEM bytes -> blank
    ],
)
def test_lm_hash(password, expected):
    assert g.compute_lm_hash(password).hex() == expected


def test_des_string_to_key_rfc3961():
    # [RFC3961] section 6.2 test vector.
    assert g.compute_kerberos_des_key("password", b"ATHENA.MIT.EDUraeburn").hex() == "cbc22fae235298e3"


@pytest.mark.parametrize(
    ("iterations", "key_size", "expected"),
    [
        (1, 16, "42263c6e89f4fc28b8df68ee09799f15"),
        (1, 32, "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"),
        (2, 16, "c651bf29e2300ac27fa469d693bdda13"),
    ],
)
def test_aes_string_to_key_rfc3962(iterations, key_size, expected):
    # [RFC3962] Appendix B test vectors.
    assert g.compute_kerberos_aes_key("password", b"ATHENA.MIT.EDUraeburn", key_size, iterations).hex() == expected
