"""
Tests for PA#15: Digital Signatures
Author: Shobhan
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from src.sig.rsa_sig import (
    sign, verify, euf_cma_game, multiplicative_forgery_demo, rsa_keygen
)
from src.utils.random_utils import generate


@pytest.fixture(scope="module")
def sig_keypair():
    return rsa_keygen(bits=512)


def test_sign_verify_basic(sig_keypair):
    pk, sk = sig_keypair
    for msg in [b"hello", b"test message", b"\x00\x01\x02\x03", b"a" * 100]:
        sigma = sign(sk, msg)
        assert verify(pk, msg, sigma), f"Signature should verify for: {msg}"


def test_tampered_message_fails(sig_keypair):
    pk, sk = sig_keypair
    msg = b"original message"
    sigma = sign(sk, msg)
    assert not verify(pk, b"tampered message", sigma), "Tampered message should fail verification"


def test_tampered_signature_fails(sig_keypair):
    pk, sk = sig_keypair
    msg = b"test"
    sigma = sign(sk, msg)
    # Flip a bit in signature
    sigma_bad = sigma ^ 1
    assert not verify(pk, msg, sigma_bad)


def test_euf_cma_secure(sig_keypair):
    pk, sk = sig_keypair
    result = euf_cma_game(pk, sk, num_oracle_queries=50, num_forgery_attempts=20)
    assert result["forgery_successes"] == 0, "No forgeries should succeed"


def test_multiplicative_forgery_on_raw(sig_keypair):
    """Raw RSA sign should be vulnerable to multiplicative forgery."""
    pk, sk = sig_keypair
    result = multiplicative_forgery_demo(pk, sk)
    assert result["forgery_valid"], "Multiplicative forgery on raw RSA must succeed"


def test_hash_then_sign_not_homomorphic(sig_keypair):
    """Hash-then-sign should NOT be multiplicatively homomorphic."""
    from src.sig.rsa_sig import _hash_message
    pk, sk = sig_keypair
    N = pk["N"]
    m1 = int.from_bytes(generate(8), 'big') % N
    m2 = int.from_bytes(generate(8), 'big') % N
    m12 = (m1 * m2) % N
    h1  = int.from_bytes(_hash_message(m1.to_bytes(16, 'big')), 'big') % N
    h2  = int.from_bytes(_hash_message(m2.to_bytes(16, 'big')), 'big') % N
    h12 = int.from_bytes(_hash_message(m12.to_bytes(16, 'big')), 'big') % N
    assert (h1 * h2) % N != h12, "Hash should not be multiplicatively homomorphic"
