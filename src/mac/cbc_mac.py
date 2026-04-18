"""
PA#5: Variable-length CBC-MAC
Author: Shubham

Implements CBC-MAC for arbitrary-length messages by chaining the PRF.
"""

from src.interfaces.mac import MAC
from src.interfaces.prf import PRF
from src.prf.ggm_prf import GGM_PRF

class CBC_MAC(MAC):
    """
    CBC-MAC handles arbitrary-length messages.
    """

    def __init__(self, prf: PRF = None):
        if prf is None:
            self.prf = GGM_PRF()
        else:
            self.prf = prf
        self.block_len = self.prf.get_input_length()

    def _pad(self, m: bytes) -> bytes:
        """
        Pad message to a multiple of block_len.
        Uses a simple padding: append 0x80, then 0x00 bytes.
        """
        pad_len = self.block_len - (len(m) % self.block_len)
        return m + b'\x80' + b'\x00' * (pad_len - 1)

    def tag(self, k: bytes, m: bytes) -> bytes:
        m_padded = self._pad(m)
        num_blocks = len(m_padded) // self.block_len
        
        # IV = 0^n
        chain_val = b'\x00' * self.block_len
        
        for i in range(num_blocks):
            block = m_padded[i * self.block_len : (i + 1) * self.block_len]
            # XOR with chain value
            xor_block = bytes(a ^ b for a, b in zip(chain_val, block))
            chain_val = self.prf.evaluate(k, xor_block)
            
        return chain_val

    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        expected_tag = self.tag(k, m)
        if len(expected_tag) != len(t):
            return False
            
        result = 0
        for x, y in zip(expected_tag, t):
            result |= x ^ y
        return result == 0
