"""
PA#11: Diffie-Hellman Key Exchange
Author: Shobhan

Protocol:
- Public params: prime p (safe prime), generator g of Z*_p
- Alice: samples a <- Z_q, sends A = g^a mod p
- Bob:   samples b <- Z_q, sends B = g^b mod p
- Shared secret: K = g^ab mod p  (both compute this)

Security: Hardness of Computational Diffie-Hellman (CDH) problem.
Note: Basic DH is NOT authenticated — vulnerable to MITM without signatures.
"""

from src.primality.miller_rabin import is_prime
from src.utils.mod_exp import square_and_multiply
from src.utils.random_utils import generate
from src.utils.ext_gcd import mod_inverse


# ============================================================================
# ROBUST PRIME HELPERS  (work-around for edge cases in Raj's gen_prime)
# ============================================================================

def _gen_prime_robust(bits: int, k: int = 40) -> int:
    """Generate a random probably-prime of exactly `bits` bits."""
    while True:
        num_bytes = (bits + 7) // 8
        raw = int.from_bytes(generate(num_bytes), 'big')
        raw |= (1 << (bits - 1))       # set MSB
        raw |= 1                        # set LSB (odd)
        raw &= (1 << bits) - 1          # mask to bits length
        if raw.bit_length() == bits and is_prime(raw, k):
            return raw


def _gen_prime_safe_robust(bits: int) -> int:
    """Generate safe prime p = 2q + 1 where both p and q are prime."""
    while True:
        q = _gen_prime_robust(bits - 1, k=40)
        p = 2 * q + 1
        if is_prime(p, k=40):
            return p


# ============================================================================
# GROUP PARAMETER GENERATION
# ============================================================================

def generate_dh_params(bits: int = 256) -> dict:
    """
    Generate Diffie-Hellman public parameters:
      - Safe prime p = 2q + 1
      - Generator g of the prime-order subgroup of Z*_p of order q

    Args:
        bits: bit length of the safe prime p

    Returns:
        dict with keys: p (safe prime), q (subgroup order), g (generator)
    """
    p = _gen_prime_safe_robust(bits)
    q = (p - 1) // 2

    # Find generator g of the subgroup of order q.
    # In a safe-prime group, any element != 1 and != p-1 generates order q.
    g_candidate = 2
    while True:
        if g_candidate in (1, p - 1):
            g_candidate += 1
            continue
        g_q = square_and_multiply(g_candidate, q, p)
        g_2 = square_and_multiply(g_candidate, 2, p)
        if g_q == 1 and g_2 != 1:
            break
        g_candidate += 1

    return {"p": p, "q": q, "g": g_candidate}


# ============================================================================
# ALICE AND BOB STEP FUNCTIONS
# ============================================================================

def _sample_exponent(q: int) -> int:
    """Sample a uniformly random integer in [1, q-1]."""
    byte_len = (q.bit_length() + 7) // 8
    while True:
        raw = int.from_bytes(generate(byte_len), 'big')
        raw &= (1 << q.bit_length()) - 1   # mask to q's bit width
        if 1 <= raw < q:
            return raw


def dh_alice_step1(params: dict) -> tuple:
    """
    Alice's first step: sample private exponent a, compute A = g^a mod p.

    Returns:
        (a, A) — a is private, A is sent to Bob
    """
    p, q, g = params["p"], params["q"], params["g"]
    a = _sample_exponent(q)
    A = square_and_multiply(g, a, p)
    return a, A


def dh_bob_step1(params: dict) -> tuple:
    """
    Bob's first step: sample private exponent b, compute B = g^b mod p.

    Returns:
        (b, B) — b is private, B is sent to Alice
    """
    p, q, g = params["p"], params["q"], params["g"]
    b = _sample_exponent(q)
    B = square_and_multiply(g, b, p)
    return b, B


def dh_alice_step2(params: dict, a: int, B: int) -> int:
    """Alice computes shared secret K = B^a mod p = g^{ab} mod p."""
    return square_and_multiply(B, a, params["p"])


def dh_bob_step2(params: dict, b: int, A: int) -> int:
    """Bob computes shared secret K = A^b mod p = g^{ab} mod p."""
    return square_and_multiply(A, b, params["p"])


# ============================================================================
# FULL KEY EXCHANGE (convenience wrapper)
# ============================================================================

def dh_key_exchange(params: dict) -> dict:
    """
    Simulate a complete DH key exchange between Alice and Bob.
    """
    a, A = dh_alice_step1(params)
    b, B = dh_bob_step1(params)

    K_alice = dh_alice_step2(params, a, B)
    K_bob   = dh_bob_step2(params, b, A)

    assert K_alice == K_bob, "Key exchange failed: shared secrets don't match!"
    return {
        "alice_private": a,
        "alice_public":  A,
        "bob_private":   b,
        "bob_public":    B,
        "shared_secret": K_alice,
        "match":         K_alice == K_bob,
    }


# ============================================================================
# MITM ATTACK DEMO
# ============================================================================

class Eve:
    """Active man-in-the-middle attacker."""

    def __init__(self, params: dict):
        self.params = params
        self.e = None
        self.E = None
        self.K_with_alice = None
        self.K_with_bob   = None

    def intercept_and_substitute(self, A: int, B: int) -> tuple:
        """
        Eve intercepts A and B, sends her own g^e to both.
        Returns (E_to_bob, E_to_alice).
        """
        p, q, g = self.params["p"], self.params["q"], self.params["g"]
        self.e = _sample_exponent(q)
        self.E = square_and_multiply(g, self.e, p)

        # Eve computes her shared secret with each party
        self.K_with_alice = square_and_multiply(A, self.e, p)  # = g^{ae}
        self.K_with_bob   = square_and_multiply(B, self.e, p)  # = g^{be}

        return self.E, self.E   # send same E to both


def mitm_demo(params: dict) -> dict:
    """Demonstrate MITM attack on unauthenticated DH."""
    a, A = dh_alice_step1(params)
    b, B = dh_bob_step1(params)

    eve = Eve(params)
    E_to_bob, E_to_alice = eve.intercept_and_substitute(A, B)

    # Alice and Bob each think they got the other's public value
    K_alice = dh_alice_step2(params, a, E_to_alice)
    K_bob   = dh_bob_step2(params, b, E_to_bob)

    return {
        "alice_computes":  K_alice,
        "bob_computes":    K_bob,
        "eve_with_alice":  eve.K_with_alice,
        "eve_with_bob":    eve.K_with_bob,
        "alice_talks_to_eve": K_alice == eve.K_with_alice,
        "bob_talks_to_eve":   K_bob   == eve.K_with_bob,
    }


# ============================================================================
# CDH HARDNESS DEMO (small parameters only)
# ============================================================================

def cdh_hardness_demo(bits: int = 32) -> dict:
    """
    For small parameters, show that recovering g^{ab} from g^a, g^b
    requires brute-force search over the exponent.
    Only feasible for bits <= 32.
    """
    params = generate_dh_params(bits)
    p, q, g = params["p"], params["q"], params["g"]

    a, A = dh_alice_step1(params)
    b, B = dh_bob_step1(params)
    real_K = dh_alice_step2(params, a, B)

    import time
    t0 = time.time()
    found_a = None
    limit = min(q, 2**20)
    for guess in range(1, limit):
        if square_and_multiply(g, guess, p) == A:
            found_a = guess
            break
    elapsed = time.time() - t0

    recovered_K = None
    if found_a is not None:
        recovered_K = square_and_multiply(B, found_a, p)

    return {
        "p_bits":               p.bit_length(),
        "q":                    q,
        "brute_force_found_a":  found_a is not None,
        "recovered_K_matches":  recovered_K == real_K,
        "time_seconds":         elapsed,
    }


if __name__ == "__main__":
    print("PA#11: Diffie-Hellman Key Exchange Demo")
    print("=" * 50)

    print("\nGenerating DH parameters (64-bit safe prime)...")
    params = generate_dh_params(bits=64)
    print(f"  p = {params['p']}")
    print(f"  q = {params['q']}")
    print(f"  g = {params['g']}")

    result = dh_key_exchange(params)
    print(f"\nKey exchange complete:")
    print(f"  Shared secret: {result['shared_secret']}")
    print(f"  Keys match: {result['match']}")

    mitm = mitm_demo(params)
    print(f"\nMITM attack:")
    print(f"  Alice talks to Eve: {mitm['alice_talks_to_eve']}")
    print(f"  Bob   talks to Eve: {mitm['bob_talks_to_eve']}")
