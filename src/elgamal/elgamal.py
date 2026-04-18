"""
PA#16: ElGamal Public-Key Cryptosystem
Author: Shobhan

Based on hardness of the Decisional Diffie-Hellman (DDH) problem.

Key Generation:
    - Cyclic group G of prime order q with generator g
    - Private key: x <- Z_q
    - Public key:  h = g^x mod p

Encryption of m ∈ G:
    - Sample r <- Z_q
    - C = (g^r mod p,  m * h^r mod p)

Decryption of (c1, c2):
    - m = c2 / c1^x = c2 * (c1^x)^{-1} mod p

Security: CPA-secure under DDH assumption.
WARNING: ElGamal is malleable — NOT CCA-secure.
"""

from src.dh.dh import generate_dh_params, dh_alice_step1, _sample_exponent
from src.utils.mod_exp import square_and_multiply
from src.utils.ext_gcd import mod_inverse
from src.utils.random_utils import generate


# ============================================================================
# KEY GENERATION
# ============================================================================

def elgamal_keygen(bits: int = 256) -> tuple:
    """
    Generate ElGamal key pair.

    Args:
        bits: bit length of the safe prime p

    Returns:
        (pk, sk) where:
            pk = {"p": p, "q": q, "g": g, "h": h}  (h = g^x mod p)
            sk = {"p": p, "q": q, "g": g, "x": x}
    """
    params = generate_dh_params(bits)
    p, q, g = params["p"], params["q"], params["g"]

    # Private key x <- Z_q (1 <= x <= q-1)
    x = _sample_exponent(q)   # sample x in [1, q-1]

    # Public key h = g^x mod p
    h = square_and_multiply(g, x, p)

    pk = {"p": p, "q": q, "g": g, "h": h}
    sk = {"p": p, "q": q, "g": g, "x": x}

    return pk, sk


# ============================================================================
# ENCRYPTION / DECRYPTION
# ============================================================================

def elgamal_enc(pk: dict, m: int) -> tuple:
    """
    ElGamal encryption of group element m.

    Args:
        pk: public key dict
        m:  plaintext integer (group element, 1 <= m < p)

    Returns:
        Ciphertext (c1, c2) where:
            c1 = g^r mod p
            c2 = m * h^r mod p
    """
    p, q, g, h = pk["p"], pk["q"], pk["g"], pk["h"]

    # Sample fresh r <- Z_q
    r = _sample_exponent(q)   # fresh r per encryption

    c1 = square_and_multiply(g, r, p)       # g^r
    hr = square_and_multiply(h, r, p)        # h^r
    c2 = (m * hr) % p                        # m * h^r

    return c1, c2


def elgamal_dec(sk: dict, c1: int, c2: int) -> int:
    """
    ElGamal decryption.

    m = c2 * (c1^x)^{-1} mod p

    Args:
        sk: private key dict
        c1, c2: ciphertext pair

    Returns:
        Plaintext integer m
    """
    p, x = sk["p"], sk["x"]

    # Compute shared DH value: c1^x = g^{rx}
    s   = square_and_multiply(c1, x, p)
    # Invert s mod p
    s_inv = mod_inverse(s, p)
    # Recover m
    m = (c2 * s_inv) % p

    return m


# ============================================================================
# MESSAGE ENCODING HELPERS
# ============================================================================

def encode_message(m_bytes: bytes, pk: dict) -> int:
    """
    Encode a byte string as a group element (simple embedding).
    Pads to fit within p.
    """
    p = pk["p"]
    m_int = int.from_bytes(m_bytes, 'big')
    if m_int >= p:
        raise ValueError("Message too large for this group. Use a larger key.")
    if m_int == 0:
        m_int = 1  # avoid 0 (not a group element)
    return m_int


def decode_message(m_int: int, length: int) -> bytes:
    """Decode a group element back to bytes."""
    return m_int.to_bytes(length, 'big')


# ============================================================================
# MALLEABILITY ATTACK DEMO
# ============================================================================

def malleability_attack_demo(pk: dict, sk: dict, m: int) -> dict:
    """
    Demonstrate ElGamal malleability:
    Given (c1, c2) encrypting m, we can produce (c1, 2*c2 mod p)
    which decrypts to 2*m — without knowing m or the private key x.

    This breaks CCA security.
    """
    c1, c2 = elgamal_enc(pk, m)

    # Attacker: multiply c2 by 2 (no knowledge of x or m)
    c2_tampered = (2 * c2) % pk["p"]

    # Decrypt both
    m_original  = elgamal_dec(sk, c1, c2)
    m_tampered  = elgamal_dec(sk, c1, c2_tampered)

    return {
        "original_m":  m_original,
        "tampered_m":  m_tampered,
        "ratio":       m_tampered * mod_inverse(m_original, pk["p"]) % pk["p"],  # should be 2
        "malleable":   m_tampered == (2 * m) % pk["p"],
    }


# ============================================================================
# IND-CPA GAME
# ============================================================================

def ind_cpa_game(pk: dict, m0: int, m1: int) -> dict:
    """
    Simulate a single round of the IND-CPA game for ElGamal.

    Challenger picks random b, returns Enc(m_b). Adversary guesses b.
    For large groups, advantage should be negligible.
    """
    import os
    b = int.from_bytes(os.urandom(1), 'big') % 2
    m_b = m0 if b == 0 else m1

    c1, c2 = elgamal_enc(pk, m_b)

    return {
        "challenge_bit": b,
        "c1": c1,
        "c2": c2,
        "message_b": m_b,
    }


if __name__ == "__main__":
    print("PA#16: ElGamal Public-Key Cryptosystem Demo")
    print("=" * 50)

    print("\nGenerating ElGamal key pair (64-bit group)...")
    pk, sk = elgamal_keygen(bits=64)
    print(f"  p = {pk['p']}")
    print(f"  g = {pk['g']}")
    print(f"  h = {pk['h']}  (public key)")

    m = 12345
    print(f"\nEncrypting m = {m}...")
    c1, c2 = elgamal_enc(pk, m)
    print(f"  c1 = {c1}, c2 = {c2}")

    m_dec = elgamal_dec(sk, c1, c2)
    print(f"  Decrypted: {m_dec}, match: {m == m_dec}")

    print("\nMalleability attack demo:")
    r = malleability_attack_demo(pk, sk, m)
    print(f"  Original m:  {r['original_m']}")
    print(f"  Tampered m:  {r['tampered_m']}  (should be 2*{m})")
    print(f"  Malleable:   {r['malleable']}")
