"""
PA#10: HMAC
Author: Shubham

Implements HMAC using the Hash interface (DLP Hash).
HMAC_k(m) = H((k ^ opad) || H((k ^ ipad) || m))
"""

from src.interfaces.mac import MAC
from src.interfaces.hash import Hash

class HMAC(MAC):
    def __init__(self, hash_algo: Hash, block_size: int = 16):
        """
        Initialize HMAC with a given hash algorithm.
        block_size must match the block size of the hash function's compression step.
        """
        self.hash_algo = hash_algo
        self.block_size = block_size
        self.ipad = b'\x36' * block_size
        self.opad = b'\x5c' * block_size

    def _prepare_key(self, k: bytes) -> bytes:
        if len(k) > self.block_size:
            k = self.hash_algo.hash(k)
        if len(k) < self.block_size:
            k = k + b'\x00' * (self.block_size - len(k))
        return k

    def tag(self, k: bytes, m: bytes) -> bytes:
        k_padded = self._prepare_key(k)
        
        k_ipad = bytes(x ^ y for x, y in zip(k_padded, self.ipad))
        k_opad = bytes(x ^ y for x, y in zip(k_padded, self.opad))
        
        inner_hash = self.hash_algo.hash(k_ipad + m)
        outer_hash = self.hash_algo.hash(k_opad + inner_hash)
        
        return outer_hash

    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        expected_tag = self.tag(k, m)
        if len(expected_tag) != len(t):
            return False
            
        result = 0
        for x, y in zip(expected_tag, t):
            result |= x ^ y
        return result == 0

class MAC_Hash(Hash):
    """
    Backward direction: MAC -> CRHF
    Uses HMAC as a compression function inside Merkle-Damgard.
    """
    def __init__(self, hmac: HMAC, key: bytes, iv: bytes):
        from src.hash.merkle_damgard import MerkleDamgard
        
        self.hmac = hmac
        self.key = key
        # h'(cv, block) = HMAC_k(cv || block)
        def compress(cv: bytes, block: bytes) -> bytes:
            return self.hmac.tag(self.key, cv + block)
            
        self.md = MerkleDamgard(compress, iv, hmac.block_size)
        
    def hash(self, msg: bytes) -> bytes:
        return self.md.hash(msg)
