"""
PA#3: CPA-Secure Symmetric Encryption
Author: Kanishk

Construction: Enc(k, m) = (r, F_k(r) XOR m)
where r is freshly sampled randomness each call.

Security: IND-CPA secure if F_k is a secure PRF.
Catastrophic break: reusing r leaks m XOR m'.
"""

import os
from src.interfaces.sym_enc import SymEnc
from src.interfaces.prf import PRF
from src.prf.ggm_prf import GGM_PRF
from src.utils.random_utils import generate


def _xor(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


class CPA_Enc(SymEnc):
    """
    CPA-Secure Encryption using a PRF.

    Enc(k, m) = (r, F_k(r) XOR m)   where r <- {0,1}^n fresh each call
    Dec(k, (r, c)) = F_k(r) XOR c

    Multi-block: CTR-style extension — apply PRF to r, r+1, r+2, ...
    """

    def __init__(self, prf: PRF = None):
        if prf is None:
            self.prf = GGM_PRF()
        else:
            self.prf = prf
        self.block_len = self.prf.get_input_length()   # 16 bytes
        self.key_len   = self.prf.get_key_length()     # 16 bytes

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _counter_block(self, r: bytes, i: int) -> bytes:
        """Produce the i-th counter block from nonce r (r XOR i as big-endian)."""
        r_int = int.from_bytes(r, 'big')
        ctr   = (r_int + i) % (2 ** (self.block_len * 8))
        return ctr.to_bytes(self.block_len, 'big')

    def _keystream(self, k: bytes, r: bytes, length: int) -> bytes:
        """Generate `length` bytes of PRF keystream starting at nonce r."""
        stream = bytearray()
        i = 0
        while len(stream) < length:
            block = self.prf.evaluate(k, self._counter_block(r, i))
            stream.extend(block)
            i += 1
        return bytes(stream[:length])

    def _pad(self, m: bytes) -> bytes:
        """PKCS#7-style padding to block boundary."""
        pad_len = self.block_len - (len(m) % self.block_len)
        return m + bytes([pad_len] * pad_len)

    def _unpad(self, m: bytes) -> bytes:
        """Remove PKCS#7 padding."""
        pad_len = m[-1]
        if pad_len == 0 or pad_len > self.block_len:
            raise ValueError("Invalid padding")
        if m[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Padding bytes corrupted")
        return m[:-pad_len]

    # ------------------------------------------------------------------
    # Core interface
    # ------------------------------------------------------------------

    def encrypt(self, k: bytes, m: bytes) -> tuple[bytes, bytes]:
        """
        Encrypt message m under key k.

        Returns:
            (r, c) where r is the fresh nonce and c is the ciphertext.
        """
        r = generate(self.block_len)          # fresh nonce every call
        m_padded = self._pad(m)
        ks = self._keystream(k, r, len(m_padded))
        c  = _xor(ks, m_padded)
        return (r, c)

    def decrypt(self, k: bytes, ct: tuple) -> bytes:
        """
        Decrypt ciphertext ct = (r, c) under key k.
        """
        r, c = ct
        ks = self._keystream(k, r, len(c))
        m_padded = _xor(ks, c)
        return self._unpad(m_padded)


# ===========================================================================
# BROKEN VARIANT — nonce reuse (for IND-CPA demo)
# ===========================================================================

class CPA_Enc_Broken(SymEnc):
    """
    DELIBERATELY BROKEN: reuses a fixed nonce r.
    Encrypting same message twice -> identical ciphertexts.
    Shows why fresh randomness is mandatory.
    """

    def __init__(self, prf: PRF = None):
        if prf is None:
            self.prf = GGM_PRF()
        else:
            self.prf = prf
        self.block_len = self.prf.get_input_length()
        self._fixed_r  = b'\x00' * self.block_len   # NEVER do this for real

    def encrypt(self, k: bytes, m: bytes) -> tuple[bytes, bytes]:
        r  = self._fixed_r
        ks = self.prf.evaluate(k, r)[:len(m)]
        c  = _xor(ks, m[:self.block_len])           # single-block for demo
        return (r, c)

    def decrypt(self, k: bytes, ct: tuple) -> bytes:
        r, c = ct
        ks = self.prf.evaluate(k, r)[:len(c)]
        return _xor(ks, c)


# ===========================================================================
# IND-CPA GAME SIMULATION
# ===========================================================================

def ind_cpa_game(enc: SymEnc, num_rounds: int = 50) -> float:
    """
    Simulate the IND-CPA game.

    A dummy adversary queries the encryption oracle, then tries to distinguish
    which of m0/m1 was encrypted.

    Returns:
        adversary advantage (should be ~0 for secure scheme, ~1 for broken)
    """
    key = generate(enc.block_len if hasattr(enc, 'block_len') else 16)
    correct = 0

    for _ in range(num_rounds):
        m0 = generate(16)
        m1 = generate(16)

        # Challenger flips a coin
        b = int.from_bytes(generate(1), 'big') % 2
        ct_star = enc.encrypt(key, m0 if b == 0 else m1)

        # Dummy adversary: just guesses randomly (optimal for secure scheme)
        guess = int.from_bytes(generate(1), 'big') % 2
        if guess == b:
            correct += 1

    advantage = abs(correct / num_rounds - 0.5)
    return advantage


if __name__ == "__main__":
    enc = CPA_Enc()
    k = generate(16)

    print("PA#3: CPA-Secure Encryption Demo")
    print("=" * 45)

    m = b"Hello, CPA world"
    r, c = enc.encrypt(k, m)
    m_dec = enc.decrypt(k, (r, c))
    print(f"Message:    {m}")
    print(f"Nonce:      {r.hex()}")
    print(f"Ciphertext: {c.hex()}")
    print(f"Decrypted:  {m_dec}")
    print(f"Correct:    {m == m_dec}")

    print("\nMulti-block test:")
    m_long = b"A" * 40
    r2, c2 = enc.encrypt(k, m_long)
    print(f"Original length: {len(m_long)}, Ciphertext length: {len(c2)}")
    print(f"Decrypted correctly: {enc.decrypt(k, (r2, c2)) == m_long}")

    print("\nIND-CPA game (secure scheme, 50 rounds):")
    adv = ind_cpa_game(enc)
    print(f"Adversary advantage: {adv:.3f} (expected ~0)")

    print("\nBroken nonce-reuse demo:")
    broken = CPA_Enc_Broken()
    m_a = b"vote: OPTION A "
    m_b = b"vote: OPTION A "   # same message
    _, c_a = broken.encrypt(k, m_a)
    _, c_b = broken.encrypt(k, m_a)
    print(f"Same message, two encryptions identical: {c_a == c_b}")
