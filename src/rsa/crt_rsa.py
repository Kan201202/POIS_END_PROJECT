"""
PA#14: Chinese Remainder Theorem & Breaking Textbook RSA
Author: Shobhan

Two roles of CRT:
1. CRT-based RSA decryption (Garner's algorithm) — ~4x faster
2. Håstad's Broadcast Attack — recover m when same m is sent to e recipients
   each using the same small exponent e (e.g. e=3)

CRT Theorem:
    Given pairwise coprime moduli n1,...,nk and residues a1,...,ak,
    there is a unique x mod N = n1*...*nk such that x ≡ ai (mod ni).
"""

from src.utils.mod_exp import square_and_multiply
from src.utils.ext_gcd import mod_inverse, extended_gcd
from src.utils.int_root import integer_root
from src.rsa.rsa import rsa_keygen, rsa_enc, rsa_dec, pkcs15_enc


# ============================================================================
# CRT SOLVER
# ============================================================================

def crt(residues: list[int], moduli: list[int]) -> int:
    """
    Chinese Remainder Theorem solver.

    Given (a1, n1), (a2, n2), ..., (ak, nk) with pairwise coprime ni,
    returns unique x mod N = n1*n2*...*nk satisfying x ≡ ai (mod ni).

    Args:
        residues: list of remainders [a1, a2, ..., ak]
        moduli:   list of moduli    [n1, n2, ..., nk] (must be pairwise coprime)

    Returns:
        x in [0, N) satisfying all congruences

    Raises:
        ValueError: if moduli are not pairwise coprime
    """
    if len(residues) != len(moduli):
        raise ValueError("residues and moduli must have the same length")

    N = 1
    for n in moduli:
        N *= n

    x = 0
    for ai, ni in zip(residues, moduli):
        Mi = N // ni
        Mi_inv = mod_inverse(Mi, ni)   # Mi^{-1} mod ni
        x += ai * Mi * Mi_inv

    return x % N


# ============================================================================
# GARNER'S ALGORITHM — CRT-BASED RSA DECRYPTION
# ============================================================================

def rsa_dec_crt(sk: dict, c: int) -> int:
    """
    RSA decryption using CRT (Garner's algorithm) — ~4x faster.

    Instead of computing c^d mod N directly (large exponent, large modulus),
    compute:
        mp = c^{dp} mod p   (dp = d mod p-1, half-size exponent & modulus)
        mq = c^{dq} mod q   (dq = d mod q-1)
    Then recombine with CRT.

    Args:
        sk: private key with fields N, d, p, q, dp, dq, q_inv
        c:  ciphertext integer

    Returns:
        Plaintext integer m
    """
    p, q   = sk["p"],   sk["q"]
    dp, dq = sk["dp"],  sk["dq"]
    q_inv  = sk["q_inv"]

    mp = square_and_multiply(c % p, dp, p)   # c^dp mod p
    mq = square_and_multiply(c % q, dq, q)   # c^dq mod q

    # Garner recombination
    h = (q_inv * (mp - mq)) % p
    m = mq + h * q

    return m


def benchmark_rsa_dec(sk: dict, messages: list[int]) -> dict:
    """
    Benchmark standard vs CRT RSA decryption.

    Returns:
        dict with times and speedup ratio
    """
    import time

    pk = {"N": sk["N"], "e": 65537}
    ciphertexts = [rsa_enc(pk, m % sk["N"]) for m in messages]

    # Standard decryption
    t0 = time.time()
    for c in ciphertexts:
        rsa_dec(sk, c)
    t_standard = time.time() - t0

    # CRT decryption
    t0 = time.time()
    for c in ciphertexts:
        rsa_dec_crt(sk, c)
    t_crt = time.time() - t0

    return {
        "standard_time": t_standard,
        "crt_time": t_crt,
        "speedup": t_standard / t_crt if t_crt > 0 else float('inf'),
        "n_messages": len(messages),
    }


# ============================================================================
# HÅSTAD'S BROADCAST ATTACK
# ============================================================================

def hastad_attack(ciphertexts: list[int], moduli: list[int], e: int) -> int:
    """
    Håstad's Broadcast Attack on textbook RSA with small public exponent e.

    Given: ci = m^e mod Ni for i = 0,...,e-1 (same m, different moduli)
    
    Attack:
        1. Use CRT to find x = m^e mod (N0 * N1 * ... * N_{e-1})
        2. Since m < Ni for all i, we have m^e < product, so x = m^e exactly
        3. Take e-th integer root to recover m

    Args:
        ciphertexts: [c0, c1, ..., c_{e-1}] where ci = m^e mod Ni
        moduli:      [N0, N1, ..., N_{e-1}]
        e:           public exponent (number of recipients = e)

    Returns:
        Recovered plaintext m

    Raises:
        ValueError: if attack fails (m^e >= product of moduli, i.e. m too large)
    """
    if len(ciphertexts) != e or len(moduli) != e:
        raise ValueError(f"Need exactly {e} ciphertexts and moduli for e={e}")

    # Step 1: CRT to get m^e
    me = crt(ciphertexts, moduli)

    # Step 2: integer e-th root
    m = integer_root(me, e)

    # Verify
    if m ** e != me:
        raise ValueError(
            "Attack failed: m^e >= N0*N1*...*N_{e-1} (message too large for this attack). "
            "Try shorter messages or larger moduli."
        )

    return m


def hastad_attack_demo(bits: int = 128, e: int = 3) -> dict:
    """
    Full demo of Håstad's broadcast attack.

    Generates e independent RSA key pairs all with exponent e,
    encrypts the same short message m to all e recipients,
    and recovers m using the attack.

    Args:
        bits: bit length of each modulus (use small values for speed)
        e:    public exponent / number of recipients

    Returns:
        dict with original message, recovered message, and success flag
    """
    # Generate e independent key pairs
    key_pairs = []
    for _ in range(e):
        # Force small e by regenerating if needed
        while True:
            pk, sk = rsa_keygen(bits=bits)
            # Override e to the desired small value
            pk["e"] = e
            phi = (sk["p"] - 1) * (sk["q"] - 1)
            if phi % e != 0:
                try:
                    sk["d"] = mod_inverse(e, phi)
                    break
                except ValueError:
                    continue

        key_pairs.append((pk, sk))

    moduli = [kp[0]["N"] for kp in key_pairs]

    # Choose a message small enough: m^e < product of moduli
    # Max safe message: m < (min(Ni))^{1/e}
    min_N = min(moduli)
    max_m = integer_root(min_N, e) - 1
    m = max_m - 1  # safe choice
    if m < 2:
        m = 2

    # Encrypt m to each recipient
    ciphertexts = []
    for pk, _ in key_pairs:
        c = square_and_multiply(m, e, pk["N"])
        ciphertexts.append(c)

    # Attack
    recovered = hastad_attack(ciphertexts, moduli, e)

    return {
        "original_m": m,
        "recovered_m": recovered,
        "success": m == recovered,
        "e": e,
        "n_bits": bits,
    }


def hastad_padding_defeat_demo(bits: int = 128, e: int = 3) -> dict:
    """
    Show that PKCS#1 v1.5 padding defeats Håstad's attack.

    Each recipient pads m differently (random PS bytes), so CRT recovers
    garbage and the integer root step fails.
    """
    key_pairs = []
    for _ in range(e):
        while True:
            pk, sk = rsa_keygen(bits=bits)
            pk["e"] = e
            phi = (sk["p"] - 1) * (sk["q"] - 1)
            if phi % e != 0:
                try:
                    sk["d"] = mod_inverse(e, phi)
                    break
                except ValueError:
                    continue
        key_pairs.append((pk, sk))

    m_bytes = b"hello"

    # PKCS#1 v1.5: each recipient gets a differently padded ciphertext
    padded_ciphertexts = []
    padded_moduli = []
    for pk, _ in key_pairs:
        c = pkcs15_enc(pk, m_bytes)
        padded_ciphertexts.append(c)
        padded_moduli.append(pk["N"])

    # Try the attack
    try:
        me = crt(padded_ciphertexts, padded_moduli)
        recovered = integer_root(me, e)
        if recovered ** e == me:
            attack_succeeded = True
            recovered_bytes = recovered.to_bytes((recovered.bit_length() + 7) // 8, 'big')
        else:
            attack_succeeded = False
            recovered_bytes = b"<garbage: not a perfect e-th root>"
    except Exception as ex:
        attack_succeeded = False
        recovered_bytes = f"<error: {ex}>".encode()

    return {
        "original_m": m_bytes,
        "attack_succeeded": attack_succeeded,
        "recovered_garbage": recovered_bytes if not attack_succeeded else None,
        "explanation": "Random PKCS padding differs per recipient, so CRT result != m^e",
    }


if __name__ == "__main__":
    print("PA#14: CRT + Håstad Broadcast Attack Demo")
    print("=" * 50)

    print("\nCRT solver test:")
    x = crt([2, 3, 2], [3, 5, 7])
    print(f"  x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7)  => x = {x}")
    assert x % 3 == 2 and x % 5 == 3 and x % 7 == 2

    print("\nHåstad broadcast attack (e=3, 128-bit moduli):")
    result = hastad_attack_demo(bits=128, e=3)
    print(f"  Original m:  {result['original_m']}")
    print(f"  Recovered m: {result['recovered_m']}")
    print(f"  Attack succeeded: {result['success']}")

    print("\nPadding defeats Håstad attack:")
    pad_result = hastad_padding_defeat_demo(bits=128, e=3)
    print(f"  Attack succeeded with PKCS#1 v1.5: {pad_result['attack_succeeded']}")
    print(f"  {pad_result['explanation']}")
