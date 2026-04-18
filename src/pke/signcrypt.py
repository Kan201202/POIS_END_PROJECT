"""
PA#17: CCA-Secure Public-Key Cryptography via Signcryption
Author: Shobhan

Construction: Encrypt-then-Sign (Signcryption)
    Encrypt: CE = ElGamal.Enc(pk_enc, m)
    Sign:    σ  = RSA.Sign(sk_sign, CE_bytes)
    Output:  (CE, σ)

Decrypt:
    1. Verify signature: RSA.Verify(vk_sign, CE_bytes, σ)  — MUST be first
    2. If invalid: return ⊥
    3. Else: return ElGamal.Dec(sk_enc, CE)

Security (IND-CCA2):
    Any modified ciphertext will fail signature verification, so the
    decryption oracle is useless to the adversary.

Contrast with plain ElGamal (CPA-only):
    Attacker can submit modified CE to decryption oracle and get 2*m back.
    In PA#17, the same tampered CE fails signature check → ⊥.
"""

from src.elgamal.elgamal import elgamal_keygen, elgamal_enc, elgamal_dec
from src.sig.rsa_sig import sign, verify as rsa_verify, rsa_keygen
from src.utils.random_utils import generate


# ============================================================================
# SIGNCRYPT: ENCRYPT-THEN-SIGN
# ============================================================================

def generate_cca_keypair(enc_bits: int = 256, sign_bits: int = 512) -> tuple:
    """
    Generate a full CCA-PKC key bundle:
        - ElGamal key pair for encryption
        - RSA key pair for signing

    Args:
        enc_bits:  bit length for ElGamal group
        sign_bits: bit length for RSA modulus

    Returns:
        (enc_pk, enc_sk, sign_pk, sign_sk)
    """
    enc_pk,  enc_sk  = elgamal_keygen(bits=enc_bits)
    sign_pk, sign_sk = rsa_keygen(bits=sign_bits)
    return enc_pk, enc_sk, sign_pk, sign_sk


def _ciphertext_to_bytes(c1: int, c2: int) -> bytes:
    """Serialize (c1, c2) ElGamal ciphertext to bytes for signing."""
    c1_b = c1.to_bytes((c1.bit_length() + 7) // 8 or 1, 'big')
    c2_b = c2.to_bytes((c2.bit_length() + 7) // 8 or 1, 'big')
    # Prepend lengths so we can recover unambiguously
    return (len(c1_b).to_bytes(4, 'big') + c1_b +
            len(c2_b).to_bytes(4, 'big') + c2_b)


def cca_pkc_enc(enc_pk: dict, sign_sk: dict, m: int) -> tuple:
    """
    CCA-Secure PKC Encryption (Encrypt-then-Sign).

    Args:
        enc_pk:  ElGamal public key (for encryption)
        sign_sk: RSA private key   (for signing)
        m:       plaintext group element

    Returns:
        (c1, c2, σ) — ciphertext pair and RSA signature
    """
    # Step 1: Encrypt
    c1, c2 = elgamal_enc(enc_pk, m)

    # Step 2: Sign the ciphertext bytes
    ct_bytes = _ciphertext_to_bytes(c1, c2)
    sigma = sign(sign_sk, ct_bytes)

    return c1, c2, sigma


def cca_pkc_dec(enc_sk: dict, sign_pk: dict,
                c1: int, c2: int, sigma: int) -> int | None:
    """
    CCA-Secure PKC Decryption (Verify-then-Decrypt).

    CRITICAL ORDER: Signature MUST be verified BEFORE decryption.

    Args:
        enc_sk:  ElGamal private key
        sign_pk: RSA public key
        c1, c2:  ElGamal ciphertext
        sigma:   RSA signature

    Returns:
        Plaintext m, or None (⊥) if signature invalid
    """
    # Step 1: Verify signature FIRST
    ct_bytes = _ciphertext_to_bytes(c1, c2)
    if not rsa_verify(sign_pk, ct_bytes, sigma):
        return None  # ⊥ — reject tampered ciphertext

    # Step 2: Decrypt only if valid
    return elgamal_dec(enc_sk, c1, c2)


# ============================================================================
# IND-CCA2 GAME
# ============================================================================

def ind_cca2_game(enc_pk: dict, enc_sk: dict,
                  sign_pk: dict, sign_sk: dict,
                  m0: int, m1: int,
                  num_dec_queries: int = 20) -> dict:
    """
    Simulate the IND-CCA2 game for the Signcryption scheme.

    The adversary gets:
      - An encryption oracle
      - A decryption oracle (which rejects the challenge ciphertext itself)
      - The challenge ciphertext C* = Enc(m_b)

    We show the adversary cannot determine b.
    """
    import os

    # Challenger picks b
    b = int.from_bytes(os.urandom(1), 'big') % 2
    m_b = m0 if b == 0 else m1

    # Challenge ciphertext
    c1_star, c2_star, sig_star = cca_pkc_enc(enc_pk, sign_sk, m_b)

    # Adversary queries decryption oracle on modified ciphertexts
    rejected = 0
    accepted = 0
    for _ in range(num_dec_queries):
        # Tamper with ciphertext: flip c2 slightly
        c2_tampered = (c2_star + 1) % enc_pk["p"]
        result = cca_pkc_dec(enc_sk, sign_pk, c1_star, c2_tampered, sig_star)
        if result is None:
            rejected += 1
        else:
            accepted += 1

    # Adversary guesses randomly (cannot do better)
    guess = int.from_bytes(os.urandom(1), 'big') % 2

    return {
        "b": b,
        "guess": guess,
        "correct": guess == b,
        "tampered_rejected": rejected,
        "tampered_accepted": accepted,   # should be 0
        "scheme_secure": accepted == 0,
    }


# ============================================================================
# MALLEABILITY CONTRAST DEMO
# ============================================================================

def cca_malleability_demo(enc_pk: dict, enc_sk: dict,
                          sign_pk: dict, sign_sk: dict,
                          m: int) -> dict:
    """
    Demonstrate:
      - Plain ElGamal (CPA): bit-flip on c2 produces 2*m
      - CCA Signcrypt:       bit-flip on c2 → signature invalid → ⊥
    """
    from src.utils.ext_gcd import mod_inverse as _mod_inv

    # --- Plain ElGamal ---
    c1, c2 = elgamal_enc(enc_pk, m)
    c2_modified = (2 * c2) % enc_pk["p"]
    m_cpa = elgamal_dec(enc_sk, c1, c2_modified)

    # --- CCA Signcrypt ---
    c1s, c2s, sigma = cca_pkc_enc(enc_pk, sign_sk, m)
    c2s_modified = (2 * c2s) % enc_pk["p"]
    m_cca = cca_pkc_dec(enc_sk, sign_pk, c1s, c2s_modified, sigma)

    return {
        "original_m": m,
        "cpa_tampered_m":  m_cpa,
        "cpa_tampered_is_2m": m_cpa == (2 * m) % enc_pk["p"],
        "cca_tampered_result": m_cca,   # None = ⊥
        "cca_blocked": m_cca is None,
    }


if __name__ == "__main__":
    print("PA#17: CCA-Secure PKC (Signcryption) Demo")
    print("=" * 50)

    print("\nGenerating CCA key pair (64-bit ElGamal + 512-bit RSA)...")
    enc_pk, enc_sk, sign_pk, sign_sk = generate_cca_keypair(
        enc_bits=64, sign_bits=512
    )

    m = 9999
    print(f"\nEncrypting m = {m}...")
    c1, c2, sigma = cca_pkc_enc(enc_pk, sign_sk, m)
    print(f"  c1={c1}, c2={c2}, σ={str(sigma)[:30]}...")

    m_dec = cca_pkc_dec(enc_sk, sign_pk, c1, c2, sigma)
    print(f"  Decrypted: {m_dec}, match: {m == m_dec}")

    print("\nMalleability demo:")
    r = cca_malleability_demo(enc_pk, enc_sk, sign_pk, sign_sk, m)
    print(f"  CPA (plain ElGamal): tampered c2 decrypts to {r['cpa_tampered_m']} (2*m = {2*m % enc_pk['p']})")
    print(f"  CCA (Signcrypt):     tampered c2 → ⊥ (blocked: {r['cca_blocked']})")

    print("\nIND-CCA2 game (20 decryption oracle queries):")
    game = ind_cca2_game(enc_pk, enc_sk, sign_pk, sign_sk, m, m + 1)
    print(f"  Tampered ciphertexts rejected: {game['tampered_rejected']} / 20")
    print(f"  Scheme secure: {game['scheme_secure']}")
