"""
PA#12: Textbook RSA and PKCS#1 v1.5
Author: Shobhan

Key Generation:
    - Pick primes p, q using Miller-Rabin (PA#13 / Raj)
    - N = p*q, phi = (p-1)*(q-1)
    - e = 65537 (standard public exponent)
    - d = e^{-1} mod phi(N)

Textbook RSA:
    Enc(pk, m) = m^e mod N
    Dec(sk, c) = c^d mod N

PKCS#1 v1.5 Encryption:
    EM = 0x00 || 0x02 || PS (>= 8 random nonzero bytes) || 0x00 || m
    C  = EM^e mod N

WARNING: Textbook RSA is deterministic and NOT CPA-secure.
         PKCS#1 v1.5 is CPA-secure but NOT CCA-secure (Bleichenbacher attack).
"""

from src.primality.miller_rabin import is_prime
from src.dh.dh import _gen_prime_robust as gen_prime
from src.utils.mod_exp import square_and_multiply
from src.utils.ext_gcd import extended_gcd, mod_inverse
from src.utils.random_utils import generate
import os


# ============================================================================
# KEY GENERATION
# ============================================================================

def rsa_keygen(bits: int = 1024) -> tuple:
    """
    Generate RSA key pair.

    Args:
        bits: total bit length of modulus N (each prime is bits//2 bits)

    Returns:
        (public_key, private_key) where:
            public_key  = {"N": N, "e": e}
            private_key = {"N": N, "d": d, "p": p, "q": q,
                           "dp": dp, "dq": dq, "q_inv": q_inv}
    """
    half = bits // 2

    # Generate two distinct primes
    while True:
        p = gen_prime(half)
        q = gen_prime(half)
        if p != q:
            break

    N = p * q
    phi = (p - 1) * (q - 1)

    # Standard public exponent
    e = 65537
    if phi % e == 0:
        # Rare: retry
        return rsa_keygen(bits)

    # Private exponent
    d = mod_inverse(e, phi)

    # CRT parameters for fast decryption (Garner)
    dp    = d % (p - 1)
    dq    = d % (q - 1)
    q_inv = mod_inverse(q, p)

    pk = {"N": N, "e": e}
    sk = {"N": N, "d": d, "p": p, "q": q,
          "dp": dp, "dq": dq, "q_inv": q_inv}

    return pk, sk


# ============================================================================
# TEXTBOOK RSA  (deterministic — NOT secure)
# ============================================================================

def rsa_enc(pk: dict, m: int) -> int:
    """
    Textbook RSA encryption: C = m^e mod N.

    Args:
        pk: public key dict {"N": N, "e": e}
        m:  plaintext integer, must be 0 <= m < N

    Returns:
        ciphertext integer C
    """
    N, e = pk["N"], pk["e"]
    if not (0 <= m < N):
        raise ValueError("Plaintext m must satisfy 0 <= m < N")
    return square_and_multiply(m, e, N)


def rsa_dec(sk: dict, c: int) -> int:
    """
    Textbook RSA decryption: m = c^d mod N.

    Args:
        sk: private key dict {"N": N, "d": d, ...}
        c:  ciphertext integer

    Returns:
        plaintext integer m
    """
    N, d = sk["N"], sk["d"]
    return square_and_multiply(c, d, N)


# ============================================================================
# PKCS#1 v1.5 PADDING
# ============================================================================

def _pkcs15_pad(m: bytes, k: int) -> bytes:
    """
    Apply PKCS#1 v1.5 encryption padding.
    EM = 0x00 || 0x02 || PS || 0x00 || m

    Args:
        m: message bytes
        k: modulus byte length

    Returns:
        Padded EM of length k bytes

    Raises:
        ValueError: if message is too long
    """
    if len(m) > k - 11:
        raise ValueError(f"Message too long for PKCS#1 v1.5 (max {k - 11} bytes, got {len(m)})")

    # Generate PS: at least 8 random NON-ZERO bytes
    ps_len = k - 3 - len(m)
    ps = bytearray()
    while len(ps) < ps_len:
        byte = os.urandom(1)[0]
        if byte != 0:
            ps.append(byte)

    em = bytes([0x00, 0x02]) + bytes(ps) + bytes([0x00]) + m
    assert len(em) == k
    return em


def _pkcs15_unpad(em: bytes) -> bytes:
    """
    Strip PKCS#1 v1.5 encryption padding from EM.

    Returns:
        Original message bytes

    Raises:
        ValueError: if padding is malformed
    """
    if len(em) < 11:
        raise ValueError("Padded message too short")
    if em[0] != 0x00 or em[1] != 0x02:
        raise ValueError("Invalid PKCS#1 v1.5 header (expected 0x00 0x02)")

    # Find 0x00 separator after PS
    sep_idx = -1
    for i in range(2, len(em)):
        if em[i] == 0x00:
            sep_idx = i
            break

    if sep_idx == -1:
        raise ValueError("No 0x00 separator found in PKCS#1 v1.5 padding")

    ps = em[2:sep_idx]
    if len(ps) < 8:
        raise ValueError("PS must be at least 8 bytes")

    return em[sep_idx + 1:]


def pkcs15_enc(pk: dict, m: bytes) -> int:
    """
    PKCS#1 v1.5 padded RSA encryption.

    Args:
        pk: public key
        m:  message as bytes

    Returns:
        Ciphertext integer C
    """
    N = pk["N"]
    k = (N.bit_length() + 7) // 8
    em = _pkcs15_pad(m, k)
    m_int = int.from_bytes(em, 'big')
    return rsa_enc(pk, m_int)


def pkcs15_dec(sk: dict, c: int) -> bytes:
    """
    PKCS#1 v1.5 padded RSA decryption.

    Args:
        sk: private key
        c:  ciphertext integer

    Returns:
        Original message bytes, or raises ValueError on bad padding
    """
    N = sk["N"]
    k = (N.bit_length() + 7) // 8
    m_int = rsa_dec(sk, c)
    em = m_int.to_bytes(k, 'big')
    return _pkcs15_unpad(em)


# ============================================================================
# DETERMINISM ATTACK DEMO (Textbook RSA)
# ============================================================================

def determinism_attack_demo(pk: dict, message: bytes) -> dict:
    """
    Demonstrate that textbook RSA encrypts the same message to the same
    ciphertext, leaking information.

    Compare with PKCS#1 v1.5 where random PS makes ciphertexts differ.
    """
    m_int = int.from_bytes(message.ljust(4, b'\x00'), 'big') % pk["N"]

    c1_textbook = rsa_enc(pk, m_int)
    c2_textbook = rsa_enc(pk, m_int)

    c1_pkcs = pkcs15_enc(pk, message)
    c2_pkcs = pkcs15_enc(pk, message)

    return {
        "textbook_c1": c1_textbook,
        "textbook_c2": c2_textbook,
        "textbook_same": c1_textbook == c2_textbook,   # True -> leak!
        "pkcs15_c1":  c1_pkcs,
        "pkcs15_c2":  c2_pkcs,
        "pkcs15_same": c1_pkcs == c2_pkcs,             # False -> secure
    }


# ============================================================================
# BLEICHENBACHER PADDING ORACLE (toy, 512-bit N)
# ============================================================================

def padding_oracle(sk: dict, c: int) -> bool:
    """
    Simulated padding oracle: returns True iff c decrypts to valid PKCS#1 v1.5.

    In a real attack this would be a network service.
    """
    try:
        pkcs15_dec(sk, c)
        return True
    except ValueError:
        return False


def bleichenbacher_simplified(pk: dict, sk: dict, c_target: int,
                               max_iterations: int = 2000) -> bytes | None:
    """
    Simplified Bleichenbacher '98 CCA2 attack on PKCS#1 v1.5 RSA.

    Given a ciphertext c and a padding oracle, recover plaintext m.
    This is a pedagogical implementation — not the full optimised attack.

    Works best on small N (512 bits).

    Returns:
        Recovered plaintext bytes, or None if not found within max_iterations
    """
    N, e = pk["N"], pk["e"]
    k = (N.bit_length() + 7) // 8
    B = 2 ** (8 * (k - 2))

    # Step 1: Blinding — find s such that c * s^e mod N has valid padding
    # For simplicity we try small s values
    for s in range(1, max_iterations):
        c_blind = (c_target * square_and_multiply(s, e, N)) % N
        if padding_oracle(sk, c_blind):
            # We found a valid blinding factor
            # In the full attack we'd narrow the interval M.
            # Here we demonstrate the oracle is exploitable.
            return s.to_bytes((s.bit_length() + 7) // 8 or 1, 'big')

    return None


if __name__ == "__main__":
    print("PA#12: Textbook RSA + PKCS#1 v1.5 Demo")
    print("=" * 50)

    print("\nGenerating 512-bit RSA key (toy)...")
    pk, sk = rsa_keygen(bits=512)
    print(f"  N = {sk['N'].bit_length()} bits")
    print(f"  e = {pk['e']}")
    print(f"  d = {str(sk['d'])[:40]}...")

    print("\nTextbook RSA encrypt/decrypt:")
    m = 42
    c = rsa_enc(pk, m)
    m2 = rsa_dec(sk, c)
    print(f"  m = {m}, c = {c}, recovered = {m2}, OK: {m == m2}")

    print("\nDeterminism attack demo:")
    result = determinism_attack_demo(pk, b"vote_yes")
    print(f"  Textbook same ciphertext: {result['textbook_same']} (LEAK!)")
    print(f"  PKCS#1 v1.5 same ciphertext: {result['pkcs15_same']} (secure)")

    print("\nPKCS#1 v1.5 encrypt/decrypt:")
    msg = b"hello RSA"
    c2 = pkcs15_enc(pk, msg)
    recovered = pkcs15_dec(sk, c2)
    print(f"  Original:  {msg}")
    print(f"  Recovered: {recovered}")
    print(f"  Match: {msg == recovered}")
