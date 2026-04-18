"""
PA#5: PRF-based Message Authentication Code
Author: Shubham

Implements a fixed-length MAC using a PRF: Mac_k(m) = F_k(m)
"""

from src.interfaces.mac import MAC
from src.interfaces.prf import PRF
from src.prf.ggm_prf import GGM_PRF
from src.utils.random_utils import generate


class PRF_MAC(MAC):
    """
    Fixed-length PRF-based MAC.
    Handles messages of exactly one block length (configurable, typically 16 bytes).
    """

    def __init__(self, prf: PRF = None):
        """
        Initialize with a PRF instance.
        """
        if prf is None:
            self.prf = GGM_PRF()
        else:
            self.prf = prf

    def tag(self, k: bytes, m: bytes) -> bytes:
        """
        Produce tag for message m under key k.
        
        Args:
            k: key (length matching PRF key_length)
            m: message (length matching PRF input_length)
            
        Returns:
            Tag: F_k(m)
        """
        if len(m) != self.prf.get_input_length():
            raise ValueError(f"Message length {len(m)} does not match PRF input length {self.prf.get_input_length()}")
        return self.prf.evaluate(k, m)

    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        """
        Verify that t is a valid tag for m.
        """
        try:
            expected_tag = self.tag(k, m)
        except ValueError:
            return False
            
        # Constant-time comparison is good practice
        if len(expected_tag) != len(t):
            return False
        
        result = 0
        for x, y in zip(expected_tag, t):
            result |= x ^ y
        return result == 0

class PRF_from_MAC(PRF):
    """
    Backward direction: PRF from MAC.
    A secure EUF-CMA MAC on uniformly random messages acts as a PRF.
    """
    def __init__(self, mac: MAC, key_len: int = 16, block_len: int = 16):
        self.mac = mac
        self.key_len = key_len
        self.block_len = block_len

    def evaluate(self, key: bytes, x: bytes) -> bytes:
        # Use MAC to act as PRF
        return self.mac.tag(key, x)
        
    def get_key_length(self) -> int:
        return self.key_len

    def get_input_length(self) -> int:
        return self.block_len

    def get_output_length(self) -> int:
        # Assumes tag matches block_len
        return self.block_len
