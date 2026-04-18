"""
Tests for PA#12: Textbook RSA + PKCS#1 v1.5
Author: Shobhan
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from src.rsa.rsa import (
    rsa_keygen, rsa_enc, rsa_dec,
    pkcs15_enc, pkcs15_dec, determinism_attack_demo
)


@pytest.fixture(scope="module")
def keypair_512():
    return rsa_keygen(bits=512)


# ── keygen tests ───────────────────────────────────────────────────────────────

def test_keygen_fields(keypair_512):
    pk, sk = keypair_512
    for field in ["N", "e"]:
        assert field in pk
    for field in ["N", "d", "p", "q", "dp", "dq", "q_inv"]:
        assert field in sk


def test_keygen_n_is_product(keypair_512):
    _, sk = keypair_512
    assert sk["N"] == sk["p"] * sk["q"]


def test_keygen_public_exponent(keypair_512):
    pk, _ = keypair_512
    assert pk["e"] == 65537


def test_keygen_ed_inverse(keypair_512):
    pk, sk = keypair_512
    phi = (sk["p"] - 1) * (sk["q"] - 1)
    assert (pk["e"] * sk["d"]) % phi == 1


# ── textbook RSA correctness ───────────────────────────────────────────────────

def test_textbook_roundtrip(keypair_512):
    pk, sk = keypair_512
    for m in [1, 2, 100, 12345, pk["N"] - 1]:
        c = rsa_enc(pk, m)
        assert rsa_dec(sk, c) == m, f"Roundtrip failed for m={m}"


def test_textbook_deterministic(keypair_512):
    """Textbook RSA must be deterministic (same m → same c)."""
    pk, _ = keypair_512
    m = 42
    assert rsa_enc(pk, m) == rsa_enc(pk, m)


# ── PKCS#1 v1.5 tests ─────────────────────────────────────────────────────────

def test_pkcs15_roundtrip(keypair_512):
    pk, sk = keypair_512
    for msg in [b"hello", b"vote_yes", b"a" * 10, b"\x00\x01\x02"]:
        c = pkcs15_enc(pk, msg)
        assert pkcs15_dec(sk, c) == msg, f"PKCS roundtrip failed for {msg}"


def test_pkcs15_randomised(keypair_512):
    """Two encryptions of the same message must differ (random PS)."""
    pk, _ = keypair_512
    msg = b"same_message"
    assert pkcs15_enc(pk, msg) != pkcs15_enc(pk, msg)


def test_pkcs15_message_too_long(keypair_512):
    pk, _ = keypair_512
    N = pk["N"]
    k = (N.bit_length() + 7) // 8
    with pytest.raises(ValueError):
        pkcs15_enc(pk, b"x" * (k - 10))  # too long


# ── determinism attack ─────────────────────────────────────────────────────────

def test_determinism_attack(keypair_512):
    pk, _ = keypair_512
    r = determinism_attack_demo(pk, b"vote_yes")
    assert r["textbook_same"] is True,  "Textbook RSA must produce identical ciphertexts"
    assert r["pkcs15_same"]   is False, "PKCS#1 v1.5 must produce different ciphertexts"


# ── CRT parameters ─────────────────────────────────────────────────────────────

def test_crt_params_consistency(keypair_512):
    pk, sk = keypair_512
    p, q = sk["p"], sk["q"]
    assert sk["dp"] == sk["d"] % (p - 1)
    assert sk["dq"] == sk["d"] % (q - 1)
    assert (sk["q_inv"] * q) % p == 1
