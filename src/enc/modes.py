"""
PA#4: Modes of Operation — CBC, OFB, Randomized CTR
Author: Kanishk

All three modes use Raj's GGM_PRF as the underlying block cipher.
Unified API: encrypt(mode, k, M) / decrypt(mode, k, C)

Security properties:
  CBC  — sequential enc, parallel dec, random IV required
  OFB  — keystream independent of plaintext, enc == dec
  CTR  — fully parallel, random nonce per message
"""

import os
from src.interfaces.prf import PRF
from src.prf.ggm_prf import GGM_PRF
from src.utils.random_utils import generate


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Padding (PKCS#7)
# ---------------------------------------------------------------------------

def _pad(m: bytes, block_len: int) -> bytes:
    pad_len = block_len - (len(m) % block_len)
    return m + bytes([pad_len] * pad_len)

def _unpad(m: bytes) -> bytes:
    pad_len = m[-1]
    if pad_len == 0 or m[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Bad padding")
    return m[:-pad_len]


# ===========================================================================
# MODE 1: CBC (Cipher Block Chaining)
# ===========================================================================

class CBC:
    """
    CBC Mode:  C_i = E_k(C_{i-1} XOR M_i),  C_0 = IV (random)
    Decryption: M_i = D_k(C_i) XOR C_{i-1}

    Properties:
      - Sequential encryption (cannot parallelise enc)
      - Parallel decryption
      - 2-block error propagation on a flipped ciphertext bit
      - IV reuse is catastrophic (leaks whether M_i == M'_i)
    """

    def __init__(self, prf: PRF = None):
        self.prf = prf or GGM_PRF()
        self.block_len = self.prf.get_input_length()

    def encrypt(self, k: bytes, m: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
        """
        Returns (IV, ciphertext).
        IV is randomly generated unless provided (used for attack demo).

        Construction: C_i = PRF_k(C_{i-1}) XOR M_i  (C_0 = IV)
        This is CBC-style chaining: each keystream block depends on the previous
        ciphertext, so identical plaintext blocks produce different ciphertext blocks.
        Decryptable with PRF forward only (no block cipher inverse needed).
        """
        iv = iv or generate(self.block_len)
        m_padded = _pad(m, self.block_len)
        blocks = [m_padded[i:i+self.block_len]
                  for i in range(0, len(m_padded), self.block_len)]

        prev = iv
        ct_blocks = []
        for block in blocks:
            # keystream = PRF_k(previous ciphertext block)
            ks = self.prf.evaluate(k, prev)
            ct_block = _xor(ks, block)
            ct_blocks.append(ct_block)
            prev = ct_block          # chain: next PRF input is this ciphertext block

        return iv, b''.join(ct_blocks)

    def decrypt(self, k: bytes, iv: bytes, c: bytes) -> bytes:
        """
        Decrypt: M_i = PRF_k(C_{i-1}) XOR C_i
        Parallel decryption is possible since each C_{i-1} is known immediately.
        """
        blocks = [c[i:i+self.block_len]
                  for i in range(0, len(c), self.block_len)]
        prev = iv
        pt_blocks = []
        for block in blocks:
            ks = self.prf.evaluate(k, prev)
            pt_block = _xor(ks, block)
            pt_blocks.append(pt_block)
            prev = block
        return _unpad(b''.join(pt_blocks))

    # ------------------------------------------------------------------
    # Attack demos
    # ------------------------------------------------------------------

    def iv_reuse_attack_demo(self, k: bytes, m0: bytes, m1: bytes) -> bool:
        """
        Demonstrates IV reuse: if same IV used and M0[:block] == M1[:block],
        then C0[:block] == C1[:block] because PRF_k(IV) XOR M0 == PRF_k(IV) XOR M1
        when M0 == M1 for that block.
        Returns True if attack succeeds (matching first ciphertext blocks detected).
        """
        fixed_iv = generate(self.block_len)
        _, c0 = self.encrypt(k, m0, iv=fixed_iv)
        _, c1 = self.encrypt(k, m1, iv=fixed_iv)
        # With same IV and same first plaintext block, first ciphertext blocks match
        return c0[:self.block_len] == c1[:self.block_len]


# ===========================================================================
# MODE 2: OFB (Output Feedback)
# ===========================================================================

class OFB:
    """
    OFB Mode:  keystream_i = E_k(keystream_{i-1}),  keystream_0 = IV
               C_i = M_i XOR keystream_i

    Enc == Dec (same XOR operation).
    Keystream is independent of plaintext — can be pre-computed.
    Bit flip in C_i causes same bit flip in M_i only (no error propagation).
    IV reuse leaks M XOR M'.
    """

    def __init__(self, prf: PRF = None):
        self.prf = prf or GGM_PRF()
        self.block_len = self.prf.get_input_length()

    def _keystream(self, k: bytes, iv: bytes, length: int) -> bytes:
        """Generate OFB keystream of `length` bytes."""
        stream = bytearray()
        state  = iv
        while len(stream) < length:
            state = self.prf.evaluate(k, state)
            stream.extend(state)
        return bytes(stream[:length])

    def encrypt(self, k: bytes, m: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
        """Returns (IV, ciphertext). IV randomly generated if not provided."""
        iv = iv or generate(self.block_len)
        ks = self._keystream(k, iv, len(m))
        return iv, _xor(ks, m)

    def decrypt(self, k: bytes, iv: bytes, c: bytes) -> bytes:
        """OFB decryption is identical to encryption."""
        ks = self._keystream(k, iv, len(c))
        return _xor(ks, c)

    # ------------------------------------------------------------------
    # Attack demo
    # ------------------------------------------------------------------

    def keystream_reuse_attack_demo(self, k: bytes, m0: bytes, m1: bytes) -> bytes:
        """
        If same IV reused: C0 XOR C1 = M0 XOR M1.
        Given C0, C1 and knowing M0, recovers M1.
        Returns recovered M1.
        """
        fixed_iv = generate(self.block_len)
        _, c0 = self.encrypt(k, m0, iv=fixed_iv)
        _, c1 = self.encrypt(k, m1, iv=fixed_iv)
        # Attacker XORs ciphertexts to get M0 XOR M1
        xored = _xor(c0[:len(m1)], c1[:len(m1)])
        # Knowing M0, recover M1
        recovered_m1 = _xor(xored, m0[:len(m1)])
        return recovered_m1


# ===========================================================================
# MODE 3: Randomized CTR (Counter Mode)
# ===========================================================================

class CTR:
    """
    Randomized CTR Mode:
      r <- random nonce
      C_i = M_i XOR F_k(r + i)

    Fully parallelizable (both enc and dec).
    Same nonce r must NEVER be reused with same key.
    No padding needed (stream cipher mode).
    """

    def __init__(self, prf: PRF = None):
        self.prf = prf or GGM_PRF()
        self.block_len = self.prf.get_input_length()

    def _counter_block(self, r: bytes, i: int) -> bytes:
        r_int = int.from_bytes(r, 'big')
        ctr   = (r_int + i) % (2 ** (self.block_len * 8))
        return ctr.to_bytes(self.block_len, 'big')

    def _keystream(self, k: bytes, r: bytes, length: int) -> bytes:
        stream = bytearray()
        i = 0
        while len(stream) < length:
            stream.extend(self.prf.evaluate(k, self._counter_block(r, i)))
            i += 1
        return bytes(stream[:length])

    def encrypt(self, k: bytes, m: bytes) -> tuple[bytes, bytes]:
        """Returns (r, ciphertext). Nonce r sampled internally."""
        r  = generate(self.block_len)
        ks = self._keystream(k, r, len(m))
        return r, _xor(ks, m)

    def decrypt(self, k: bytes, r: bytes, c: bytes) -> bytes:
        """CTR decryption is identical to encryption."""
        ks = self._keystream(k, r, len(c))
        return _xor(ks, c)


# ===========================================================================
# UNIFIED API
# ===========================================================================

class ModesOfOperation:
    """
    Unified encrypt(mode, k, M) / decrypt(mode, k, C) router.
    mode in {'CBC', 'OFB', 'CTR'}
    """

    def __init__(self, prf: PRF = None):
        self.cbc = CBC(prf)
        self.ofb = OFB(prf)
        self.ctr = CTR(prf)

    def encrypt(self, mode: str, k: bytes, m: bytes) -> tuple:
        """
        Returns:
          CBC -> (iv, ciphertext)
          OFB -> (iv, ciphertext)
          CTR -> (nonce, ciphertext)
        """
        mode = mode.upper()
        if mode == 'CBC':
            return self.cbc.encrypt(k, m)
        elif mode == 'OFB':
            return self.ofb.encrypt(k, m)
        elif mode == 'CTR':
            return self.ctr.encrypt(k, m)
        else:
            raise ValueError(f"Unknown mode: {mode}. Use CBC, OFB, or CTR.")

    def decrypt(self, mode: str, k: bytes, ct: tuple) -> bytes:
        """
        ct is (iv_or_nonce, ciphertext) as returned by encrypt().
        """
        mode = mode.upper()
        iv_or_nonce, c = ct
        if mode == 'CBC':
            return self.cbc.decrypt(k, iv_or_nonce, c)
        elif mode == 'OFB':
            return self.ofb.decrypt(k, iv_or_nonce, c)
        elif mode == 'CTR':
            return self.ctr.decrypt(k, iv_or_nonce, c)
        else:
            raise ValueError(f"Unknown mode: {mode}.")


# ===========================================================================
# Demo
# ===========================================================================

if __name__ == "__main__":
    from src.utils.random_utils import generate
    k = generate(16)
    modes = ModesOfOperation()

    test_messages = [b"short", b"exactly16bytes!!", b"a longer message that spans multiple blocks here"]

    for mode in ['CBC', 'OFB', 'CTR']:
        print(f"\n--- {mode} Mode ---")
        for m in test_messages:
            ct   = modes.encrypt(mode, k, m)
            dec  = modes.decrypt(mode, k, ct)
            ok   = dec == m
            print(f"  len={len(m):2d}  decrypted_ok={ok}")

    print("\n--- OFB keystream-reuse attack ---")
    ofb = OFB()
    m0 = b"my secret msg!!!"
    m1 = b"your secret msg!"
    recovered = ofb.keystream_reuse_attack_demo(k, m0, m1)
    print(f"  Recovered m1: {recovered}")
    print(f"  Attack success: {recovered == m1}")

    print("\n--- CBC IV-reuse attack ---")
    cbc = CBC()
    # Two messages with same first block
    m_same   = b"SAME FIRST BLOCK"
    m_differ = b"SAME FIRST BLOCK"
    success = cbc.iv_reuse_attack_demo(k, m_same, m_differ)
    print(f"  Equal first blocks detected: {success}")
