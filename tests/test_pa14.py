"""
Tests for PA#14: CRT + Håstad Broadcast Attack
Author: Shobhan
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from src.rsa.crt_rsa import (
    crt, rsa_dec_crt, hastad_attack, hastad_attack_demo,
    hastad_padding_defeat_demo, benchmark_rsa_dec
)
from src.rsa.rsa import rsa_keygen, rsa_enc, rsa_dec


# ── CRT solver ─────────────────────────────────────────────────────────────────

def test_crt_basic():
    """x ≡ 2 (3), x ≡ 3 (5), x ≡ 2 (7) => x = 23."""
    x = crt([2, 3, 2], [3, 5, 7])
    assert x % 3 == 2
    assert x % 5 == 3
    assert x % 7 == 2


def test_crt_two_moduli():
    x = crt([1, 2], [3, 5])
    assert x % 3 == 1 and x % 5 == 2


def test_crt_uniqueness():
    """CRT solution should be unique mod N = product of moduli."""
    moduli   = [3, 5, 7]
    residues = [1, 3, 5]
    N = 3 * 5 * 7
    x = crt(residues, moduli)
    assert 0 <= x < N
    for ai, ni in zip(residues, moduli):
        assert x % ni == ai


def test_crt_mismatched_lengths():
    with pytest.raises(ValueError):
        crt([1, 2], [3])


# ── Garner CRT decryption ──────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def rsa_512():
    return rsa_keygen(bits=512)


def test_crt_dec_matches_standard(rsa_512):
    pk, sk = rsa_512
    N = pk["N"]
    for m in [1, 42, 1000, N // 3]:
        c = rsa_enc(pk, m % N)
        assert rsa_dec(sk, c) == rsa_dec_crt(sk, c), f"Mismatch at m={m}"


def test_crt_dec_100_messages(rsa_512):
    from src.utils.random_utils import generate
    pk, sk = rsa_512
    N = pk["N"]
    for _ in range(100):
        m = int.from_bytes(generate(8), 'big') % (N - 1) + 1
        c = rsa_enc(pk, m)
        assert rsa_dec_crt(sk, c) == m


# ── Håstad broadcast attack ────────────────────────────────────────────────────

def test_hastad_e3_small():
    """Attack must recover m for e=3 with 128-bit moduli."""
    result = hastad_attack_demo(bits=128, e=3)
    assert result["success"], f"Håstad attack failed: got {result['recovered_m']} expected {result['original_m']}"


def test_hastad_correctness_direct():
    """Manually construct a 3-recipient scenario and run the attack."""
    from src.utils.mod_exp import square_and_multiply
    from src.dh.dh import _gen_prime_robust as gen_prime

    e = 3
    # Use very small primes for speed
    primes_p = [gen_prime(64) for _ in range(3)]
    primes_q = [gen_prime(64) for _ in range(3)]
    Ns = [p * q for p, q in zip(primes_p, primes_q)]

    # Choose m small enough
    from src.utils.int_root import integer_root
    min_N = min(Ns)
    m = integer_root(min_N, e) - 2
    if m < 2:
        m = 2

    ciphertexts = [square_and_multiply(m, e, N) for N in Ns]
    recovered = hastad_attack(ciphertexts, Ns, e)
    assert recovered == m


def test_hastad_padding_defeats():
    """PKCS#1 v1.5 padding must defeat the Håstad attack."""
    result = hastad_padding_defeat_demo(bits=128, e=3)
    assert not result["attack_succeeded"], "Attack should FAIL with PKCS#1 v1.5 padding"
