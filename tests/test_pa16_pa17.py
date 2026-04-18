"""
Tests for PA#16: ElGamal PKC
Author: Shobhan
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from src.elgamal.elgamal import elgamal_keygen, elgamal_enc, elgamal_dec, malleability_attack_demo
from src.utils.ext_gcd import mod_inverse


@pytest.fixture(scope="module")
def eg_keypair():
    return elgamal_keygen(bits=64)


def test_elgamal_roundtrip(eg_keypair):
    pk, sk = eg_keypair
    for m in [2, 100, 9999, pk["p"] - 2]:
        c1, c2 = elgamal_enc(pk, m)
        assert elgamal_dec(sk, c1, c2) == m, f"ElGamal roundtrip failed for m={m}"


def test_elgamal_randomised(eg_keypair):
    """Same plaintext should produce different ciphertexts (fresh r each time)."""
    pk, _ = eg_keypair
    m = 1234
    c1a, c2a = elgamal_enc(pk, m)
    c1b, c2b = elgamal_enc(pk, m)
    assert (c1a, c2a) != (c1b, c2b), "ElGamal ciphertexts must differ across encryptions"


def test_elgamal_malleable(eg_keypair):
    """(c1, 2*c2) must decrypt to 2*m — demonstrating malleability."""
    pk, sk = eg_keypair
    m = 500
    result = malleability_attack_demo(pk, sk, m)
    assert result["malleable"], "ElGamal must be malleable: Dec(c1, 2*c2) = 2*m"


def test_elgamal_100_roundtrips(eg_keypair):
    from src.utils.random_utils import generate
    pk, sk = eg_keypair
    p = pk["p"]
    for _ in range(100):
        m = (int.from_bytes(generate(4), 'big') % (p - 2)) + 1
        c1, c2 = elgamal_enc(pk, m)
        assert elgamal_dec(sk, c1, c2) == m


# ── PA#17: CCA-Secure PKC ──────────────────────────────────────────────────────

"""
Tests for PA#17: CCA-Secure PKC (Signcryption)
"""

from src.pke.signcrypt import (
    generate_cca_keypair, cca_pkc_enc, cca_pkc_dec,
    ind_cca2_game, cca_malleability_demo
)


@pytest.fixture(scope="module")
def cca_keys():
    return generate_cca_keypair(enc_bits=64, sign_bits=512)


def test_cca_roundtrip(cca_keys):
    enc_pk, enc_sk, sign_pk, sign_sk = cca_keys
    for m in [1, 42, 9999, enc_pk["p"] - 2]:
        c1, c2, sigma = cca_pkc_enc(enc_pk, sign_sk, m)
        recovered = cca_pkc_dec(enc_sk, sign_pk, c1, c2, sigma)
        assert recovered == m, f"CCA roundtrip failed for m={m}"


def test_cca_rejects_tampered(cca_keys):
    """Any modification to (c1, c2) must result in ⊥."""
    enc_pk, enc_sk, sign_pk, sign_sk = cca_keys
    m = 1000
    c1, c2, sigma = cca_pkc_enc(enc_pk, sign_sk, m)

    # Tamper with c2
    result = cca_pkc_dec(enc_sk, sign_pk, c1, (c2 + 1) % enc_pk["p"], sigma)
    assert result is None, "Tampered c2 must be rejected (⊥)"

    # Tamper with c1
    result2 = cca_pkc_dec(enc_sk, sign_pk, (c1 + 1) % enc_pk["p"], c2, sigma)
    assert result2 is None, "Tampered c1 must be rejected (⊥)"


def test_cca_invalid_signature(cca_keys):
    """A random σ must be rejected."""
    from src.utils.random_utils import generate
    enc_pk, enc_sk, sign_pk, sign_sk = cca_keys
    c1, c2, _ = cca_pkc_enc(enc_pk, sign_sk, 42)
    bad_sigma = int.from_bytes(generate(8), 'big') % sign_pk["N"]
    result = cca_pkc_dec(enc_sk, sign_pk, c1, c2, bad_sigma)
    assert result is None


def test_cca_malleability_blocked(cca_keys):
    """CCA scheme must block the (c1, 2*c2) malleability attack."""
    enc_pk, enc_sk, sign_pk, sign_sk = cca_keys
    r = cca_malleability_demo(enc_pk, enc_sk, sign_pk, sign_sk, 500)
    assert r["cca_blocked"],          "CCA must block the malleability attack"
    assert r["cpa_tampered_is_2m"],   "CPA (plain ElGamal) must be malleable"


def test_ind_cca2_game(cca_keys):
    """All tampered decryption queries in the CCA2 game must be rejected."""
    enc_pk, enc_sk, sign_pk, sign_sk = cca_keys
    game = ind_cca2_game(enc_pk, enc_sk, sign_pk, sign_sk,
                         m0=100, m1=200, num_dec_queries=20)
    assert game["scheme_secure"], "All tampered queries should be rejected"
    assert game["tampered_accepted"] == 0
