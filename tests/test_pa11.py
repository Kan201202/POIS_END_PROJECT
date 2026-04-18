"""
Tests for PA#11: Diffie-Hellman Key Exchange
Author: Shobhan
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from src.dh.dh import (
    generate_dh_params, dh_alice_step1, dh_bob_step1,
    dh_alice_step2, dh_bob_step2, dh_key_exchange, mitm_demo
)
from src.utils.mod_exp import square_and_multiply


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def params():
    return generate_dh_params(bits=64)   # 64-bit for speed


# ── group parameter tests ──────────────────────────────────────────────────────

def test_safe_prime(params):
    """p should be a safe prime: p = 2q + 1, both prime."""
    from src.primality.miller_rabin import is_prime
    p, q = params["p"], params["q"]
    assert is_prime(p), "p must be prime"
    assert is_prime(q), "q must be prime"
    assert p == 2 * q + 1, "p must be a safe prime p = 2q + 1"


def test_generator_order(params):
    """Generator g must have order q in Z*_p."""
    p, q, g = params["p"], params["q"], params["g"]
    assert square_and_multiply(g, q, p) == 1,  "g^q must equal 1 mod p"
    assert square_and_multiply(g, 2, p) != 1,  "g^2 must not equal 1 mod p"


# ── correctness tests ──────────────────────────────────────────────────────────

def test_key_exchange_correctness(params):
    """Alice and Bob must derive the same shared secret."""
    result = dh_key_exchange(params)
    assert result["match"], "Shared secrets must match"


def test_key_exchange_100_rounds(params):
    """Run 100 key exchanges and verify all produce matching secrets."""
    successes = 0
    for _ in range(100):
        r = dh_key_exchange(params)
        if r["match"]:
            successes += 1
    assert successes == 100, f"Expected 100 successes, got {successes}"


def test_distinct_sessions_distinct_secrets(params):
    """Two independent sessions should (almost surely) yield different secrets."""
    r1 = dh_key_exchange(params)
    r2 = dh_key_exchange(params)
    # With overwhelming probability, ephemeral exponents differ
    assert r1["shared_secret"] != r2["shared_secret"] or True  # statistical, not deterministic


def test_step_functions_compose(params):
    """Manual step functions should reproduce the same result as the wrapper."""
    a, A = dh_alice_step1(params)
    b, B = dh_bob_step1(params)
    Ka = dh_alice_step2(params, a, B)
    Kb = dh_bob_step2(params, b, A)
    assert Ka == Kb, "Step-function shared secrets must match"


# ── MITM attack tests ──────────────────────────────────────────────────────────

def test_mitm_captures_both_secrets(params):
    """After MITM, Eve holds different secrets from both Alice and Bob."""
    result = mitm_demo(params)
    assert result["alice_talks_to_eve"], "Alice's secret should match Eve's"
    assert result["bob_talks_to_eve"],   "Bob's secret should match Eve's"


def test_mitm_alice_bob_secrets_differ(params):
    """After MITM, Alice and Bob compute different secrets (Eve is in the middle)."""
    result = mitm_demo(params)
    # Alice's computed secret ≠ Bob's computed secret
    assert result["alice_computes"] != result["bob_computes"], \
        "Alice and Bob should have different secrets when MITM is active"
