"""
PA#6: CCA-Secure Symmetric Encryption (Encrypt-then-MAC)
Author: Kanishk

Construction:
  kE, kM — independent keys (NEVER reuse the same key for both)
  Enc: CE = CPA_Enc(kE, m),  t = MAC(kM, CE)  -> (CE, t)
  Dec: verify MAC first; if invalid return None; else decrypt CE

Security: IND-CCA2 secure if CPA-Enc is CPA-secure AND MAC is EUF-CMA secure.
The MAC check means any tampered ciphertext is REJECTED before decryption,
neutralizing the decryption oracle in the CCA game.
"""

from src.enc.cpa_enc import CPA_Enc, _xor
from src.mac.cbc_mac import CBC_MAC
from src.interfaces.sym_enc import SymEnc
from src.interfaces.mac import MAC
from src.utils.random_utils import generate


class CCA_Enc:
    """
    CCA-Secure Encryption via Encrypt-then-MAC.

    Uses Kanishk's CPA_Enc (PA#3) + Shubham's CBC_MAC (PA#5).
    """

    def __init__(self, cpa_enc: SymEnc = None, mac: MAC = None):
        self.cpa_enc = cpa_enc or CPA_Enc()
        self.mac     = mac     or CBC_MAC()

    # ------------------------------------------------------------------

    def encrypt(self, kE: bytes, kM: bytes, m: bytes) -> tuple:
        """
        CCA encryption of message m.

        Args:
            kE: encryption key
            kM: MAC key  (must differ from kE)
            m:  plaintext

        Returns:
            ((r, c), tag)  — the CPA ciphertext tuple and MAC tag
        """
        if kE == kM:
            raise ValueError("kE and kM must be distinct — key separation required")

        # Step 1: CPA encrypt
        r, c = self.cpa_enc.encrypt(kE, m)

        # Step 2: MAC over the ENTIRE ciphertext (nonce + ciphertext body)
        serialized = r + c
        tag = self.mac.tag(kM, serialized)

        return (r, c), tag

    def decrypt(self, kE: bytes, kM: bytes, ct: tuple, tag: bytes) -> bytes | None:
        """
        CCA decryption.

        Verifies MAC FIRST. Returns None (⊥) if verification fails —
        the plaintext is NEVER seen by an attacker who sends a forged ciphertext.

        Args:
            kE:  encryption key
            kM:  MAC key
            ct:  (r, c) tuple from encrypt()
            tag: MAC tag from encrypt()

        Returns:
            plaintext bytes, or None on MAC failure
        """
        r, c = ct
        serialized = r + c

        # Step 1: Verify MAC — MUST come before decryption
        if not self.mac.verify(kM, serialized, tag):
            return None   # ⊥ — reject

        # Step 2: Only decrypt if authentic
        return self.cpa_enc.decrypt(kE, (r, c))


# ===========================================================================
# MALLEABILITY ATTACK DEMO (CPA only — no MAC)
# ===========================================================================

def malleability_attack_demo(cpa_enc: CPA_Enc, k: bytes, m: bytes) -> tuple[bytes, bool]:
    """
    Demonstrates that CPA-secure encryption is MALLEABLE.

    Given C = (r, F_k(r) XOR m), an attacker can flip bit i of c to produce
    a ciphertext for m with bit i flipped — WITHOUT knowing k or m.

    Returns:
        (recovered plaintext with flipped bit, attack_succeeded)
    """
    r, c = cpa_enc.encrypt(k, m)

    # Attacker flips bit 0 of the ciphertext
    c_tampered = bytearray(c)
    c_tampered[0] ^= 0x01   # flip LSB of first byte
    c_tampered = bytes(c_tampered)

    # Decryption succeeds (no integrity check) — plaintext is predictably corrupted
    m_corrupted = cpa_enc.decrypt(k, (r, c_tampered))

    # Verify: m_corrupted[0] differs from m[0] by exactly 1 bit
    attack_succeeded = (m_corrupted[0] ^ m[0]) == 0x01
    return m_corrupted, attack_succeeded


def malleability_cca_demo(cca_enc: CCA_Enc, kE: bytes, kM: bytes, m: bytes) -> bool:
    """
    Shows same bit-flip attack FAILS on CCA-Enc.

    Returns True if the attack was correctly rejected (⊥ returned).
    """
    (r, c), tag = cca_enc.encrypt(kE, kM, m)

    # Attacker flips bit 0 of ciphertext body
    c_tampered = bytearray(c)
    c_tampered[0] ^= 0x01
    c_tampered = bytes(c_tampered)

    # Attempt decryption with tampered ciphertext (but original tag)
    result = cca_enc.decrypt(kE, kM, (r, c_tampered), tag)

    # Should be rejected: result is None
    return result is None


# ===========================================================================
# IND-CCA2 GAME SIMULATION
# ===========================================================================

def ind_cca2_game(cca_enc: CCA_Enc, num_rounds: int = 50) -> float:
    """
    IND-CCA2 game simulation.

    Adversary gets:
      - Encryption oracle
      - Decryption oracle (rejects the challenge ciphertext itself)

    Adversary strategy here: submit tampered challenge to decryption oracle
    (should get ⊥), then random guess.

    Returns adversary advantage (should be ~0).
    """
    kE = generate(16)
    kM = generate(16)
    while kM == kE:
        kM = generate(16)

    correct = 0
    for _ in range(num_rounds):
        m0 = generate(16)
        m1 = generate(16)

        b = int.from_bytes(generate(1), 'big') % 2
        (r_star, c_star), tag_star = cca_enc.encrypt(kE, kM, m0 if b == 0 else m1)

        # Adversary attempts: tamper challenge and query decryption oracle
        c_tampered = bytes([c_star[0] ^ 1]) + c_star[1:]
        oracle_result = cca_enc.decrypt(kE, kM, (r_star, c_tampered), tag_star)
        # oracle_result is None (rejected) — attack fails

        # Adversary just guesses
        guess = int.from_bytes(generate(1), 'big') % 2
        if guess == b:
            correct += 1

    return abs(correct / num_rounds - 0.5)


# ===========================================================================
# Demo
# ===========================================================================

if __name__ == "__main__":
    print("PA#6: CCA-Secure Encryption Demo")
    print("=" * 45)

    cca = CCA_Enc()
    cpa = CPA_Enc()

    kE = generate(16)
    kM = generate(16)
    while kM == kE:
        kM = generate(16)

    m = b"Sensitive data!!"
    print(f"\nPlaintext: {m}")

    # Encrypt & decrypt correctly
    ct, tag = cca.encrypt(kE, kM, m)
    dec = cca.decrypt(kE, kM, ct, tag)
    print(f"Decrypted correctly: {dec == m}")

    # Tampered ciphertext rejected
    r, c = ct
    c_bad = bytes([c[0] ^ 1]) + c[1:]
    rejected = cca.decrypt(kE, kM, (r, c_bad), tag)
    print(f"Tampered ciphertext rejected (⊥): {rejected is None}")

    # Key reuse raises error
    try:
        cca.encrypt(kE, kE, m)
    except ValueError as e:
        print(f"Key reuse caught: {e}")

    print("\n--- Malleability: CPA (no MAC) ---")
    m_corrupt, ok = malleability_attack_demo(cpa, kE, m)
    print(f"Attack succeeded on CPA: {ok}  (got: {m_corrupt[:4]}...)")

    print("\n--- Malleability: CCA (with MAC) ---")
    blocked = malleability_cca_demo(cca, kE, kM, m)
    print(f"Attack blocked by CCA: {blocked}")

    print("\n--- IND-CCA2 game (50 rounds) ---")
    adv = ind_cca2_game(cca)
    print(f"Adversary advantage: {adv:.3f} (expected ~0)")
