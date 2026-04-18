"""
PA#15: Digital Signatures
Author: Shobhan

RSA Signatures (hash-then-sign):
    Sign:   σ = H(m)^d mod N
    Verify: σ^e mod N == H(m)

Hash function: we use a simple DLP-based hash stub here.
In the full project chain PA#15 depends on PA#8 DLP hash (Shubham).
We provide a fallback built-in hash wrapper that can be swapped.

Security (EUF-CMA): No PPT adversary with signing oracle can forge
a valid (m*, σ*) on any fresh m*.

Without hashing (raw RSA sign):
    Multiplicative homomorphism: sign(m1)*sign(m2) = sign(m1*m2) mod N
    This is an existential forgery attack.
"""

from src.rsa.rsa import rsa_keygen, rsa_dec, rsa_enc
from src.utils.mod_exp import square_and_multiply
from src.utils.random_utils import generate


# ============================================================================
# HASH FUNCTION (stub — replace with PA#8 DLP hash when Shubham's is ready)
# ============================================================================

def _hash_message(m: bytes) -> bytes:
    """
    Simple deterministic hash of a message to a 32-byte digest.

    This is a placeholder. Replace with DLP_Hash from PA#8 when available.
    Uses SHA-256-like construction without external libraries.

    For our purposes we implement a simple iterative compression:
    h0 = 0...0
    hi = rotate(h_{i-1} XOR block_i XOR i)
    """
    # Simple 32-byte hash: XOR-based with mixing
    state = bytearray(32)
    padded = m + len(m).to_bytes(8, 'big')
    # Process in 32-byte blocks
    for i in range(0, len(padded), 32):
        block = padded[i:i + 32].ljust(32, b'\x00')
        for j in range(32):
            state[j] ^= block[j] ^ ((i // 32 + j + 1) & 0xFF)
        # Simple mixing: cyclic rotation of state
        state = bytearray(state[1:] + state[:1])
        # Additional diffusion
        for j in range(32):
            state[j] = (state[j] * 0x1b + state[(j + 7) % 32]) & 0xFF

    return bytes(state)


def set_hash_function(fn):
    """
    Swap in a different hash function (e.g. PA#8 DLP hash).

    Args:
        fn: callable bytes -> bytes
    """
    global _hash_message
    _hash_message = fn


# ============================================================================
# RSA SIGNATURE SCHEME
# ============================================================================

def sign(sk: dict, m: bytes) -> int:
    """
    Sign message m using RSA private key.

    σ = H(m)^d mod N

    Args:
        sk: RSA private key
        m:  message bytes

    Returns:
        Signature σ as integer
    """
    N, d = sk["N"], sk["d"]
    h = _hash_message(m)
    h_int = int.from_bytes(h, 'big') % N
    if h_int == 0:
        h_int = 1
    return square_and_multiply(h_int, d, N)


def verify(pk: dict, m: bytes, sigma: int) -> bool:
    """
    Verify RSA signature.

    Check: σ^e mod N == H(m) mod N

    Args:
        pk:    public key
        m:     message bytes
        sigma: signature integer

    Returns:
        True if signature is valid
    """
    N, e = pk["N"], pk["e"]
    h = _hash_message(m)
    h_int = int.from_bytes(h, 'big') % N
    if h_int == 0:
        h_int = 1
    recovered = square_and_multiply(sigma, e, N)
    return recovered == h_int


# ============================================================================
# EUF-CMA SECURITY GAME
# ============================================================================

def euf_cma_game(pk: dict, sk: dict,
                 num_oracle_queries: int = 50,
                 num_forgery_attempts: int = 20) -> dict:
    """
    Simulate the EUF-CMA (Existential Unforgeability under Chosen-Message Attack)
    security game.

    Adversary has access to a signing oracle for up to num_oracle_queries
    messages, then tries to forge a signature on a fresh message.

    Returns:
        dict with forgery_successes count and game details
    """
    # Build oracle: sign queries
    signed_messages = set()
    oracle_pairs = []
    for _ in range(num_oracle_queries):
        msg = generate(16)
        sig = sign(sk, msg)
        signed_messages.add(msg)
        oracle_pairs.append((msg, sig))

    # Adversary attempts to forge on fresh messages
    forgery_successes = 0
    for _ in range(num_forgery_attempts):
        # Naive adversary: try a random new message with a random signature
        fresh_msg = generate(16)
        if fresh_msg in signed_messages:
            continue
        random_sig = int.from_bytes(generate(len(str(pk["N"])) // 2), 'big') % pk["N"]

        if verify(pk, fresh_msg, random_sig):
            forgery_successes += 1

    return {
        "oracle_queries": num_oracle_queries,
        "forgery_attempts": num_forgery_attempts,
        "forgery_successes": forgery_successes,
        "secure": forgery_successes == 0,
    }


# ============================================================================
# MULTIPLICATIVE HOMOMORPHISM ATTACK (raw RSA sign without hash)
# ============================================================================

def raw_rsa_sign(sk: dict, m_int: int) -> int:
    """
    Raw RSA signature WITHOUT hashing: σ = m^d mod N.
    INSECURE — demonstrates existential forgery.
    """
    N, d = sk["N"], sk["d"]
    return square_and_multiply(m_int, d, N)


def multiplicative_forgery_demo(pk: dict, sk: dict) -> dict:
    """
    Demonstrate existential forgery on raw (unhashed) RSA signatures.

    Given signatures on m1 and m2:
        σ1 = m1^d, σ2 = m2^d
    Attacker computes:
        σ_forged = (σ1 * σ2) mod N = (m1*m2)^d = sign(m1*m2)

    This is a valid signature on m1*m2 — obtained without access to the
    private key!
    """
    N = pk["N"]

    m1 = int.from_bytes(generate(8), 'big') % N
    m2 = int.from_bytes(generate(8), 'big') % N

    sig1 = raw_rsa_sign(sk, m1)
    sig2 = raw_rsa_sign(sk, m2)

    # Forge signature on m1 * m2 mod N
    m_forged  = (m1 * m2) % N
    sig_forged = (sig1 * sig2) % N

    # Verify: sig_forged^e mod N should equal m_forged
    e = pk["e"]
    recovered = square_and_multiply(sig_forged, e, N)
    forgery_valid = recovered == m_forged

    return {
        "m1": m1, "sig1": sig1,
        "m2": m2, "sig2": sig2,
        "m_forged": m_forged,
        "sig_forged": sig_forged,
        "forgery_valid": forgery_valid,
        "explanation": "Raw RSA sign is multiplicatively homomorphic: sign(a)*sign(b) = sign(a*b)"
    }


if __name__ == "__main__":
    print("PA#15: Digital Signatures Demo")
    print("=" * 50)

    print("\nGenerating 512-bit RSA key...")
    pk, sk = rsa_keygen(bits=512)

    msg = b"This document is signed by Shobhan"
    print(f"\nMessage: {msg.decode()}")

    σ = sign(sk, msg)
    valid = verify(pk, msg, σ)
    print(f"Signature: {str(σ)[:40]}...")
    print(f"Valid: {valid}")

    # Tamper test
    tampered = b"This document is forged"
    valid_tampered = verify(pk, tampered, σ)
    print(f"Tampered message valid: {valid_tampered} (should be False)")

    print("\nEUF-CMA game (50 oracle queries, 20 forgery attempts):")
    result = euf_cma_game(pk, sk)
    print(f"  Forgeries: {result['forgery_successes']} / {result['forgery_attempts']}")
    print(f"  Secure: {result['secure']}")

    print("\nMultiplicative forgery on raw RSA (without hash):")
    r = multiplicative_forgery_demo(pk, sk)
    print(f"  Forgery valid: {r['forgery_valid']}")
    print(f"  {r['explanation']}")

    print("\nWith hash-then-sign, same trick fails (hash is not multiplicative):")
    h1 = _hash_message(r["m1"].to_bytes(16, 'big'))
    h2 = _hash_message(r["m2"].to_bytes(16, 'big'))
    h12 = _hash_message((r["m1"] * r["m2"] % pk["N"]).to_bytes(16, 'big'))
    h1_int = int.from_bytes(h1, 'big') % pk["N"]
    h2_int = int.from_bytes(h2, 'big') % pk["N"]
    h12_int = int.from_bytes(h12, 'big') % pk["N"]
    homomorphic = (h1_int * h2_int) % pk["N"] == h12_int
    print(f"  Hash is multiplicatively homomorphic: {homomorphic} (should be False)")
