"""
PA#8: DLP-Based Collision-Resistant Hash Function
Author: Shubham

Instantiates the Merkle-Damgard framework using a DLP-based compression function.
"""

from src.interfaces.hash import Hash
from src.hash.merkle_damgard import MerkleDamgard
from src.primality.miller_rabin import gen_prime_safe
from src.utils.mod_exp import square_and_multiply
from src.utils.random_utils import generate
import random

class DLPHash(Hash):
    """
    DLP Hash using h(x,y) = g^x * h_hat^y (mod p).
    """

    def __init__(self, p: int = None, g: int = None, h_hat: int = None, out_len: int = 16):
        """
        out_len is the length of the digest in bytes.
        If p, g, h_hat are not provided, it generates a small toy group for speed,
        but can be parameterized with a secure group.
        """
        if p is None:
            # Generate a toy safe prime (e.g. 64-bit) for tests and fast execution.
            # Generate a safe prime of 128 bits so that the group element is 16 bytes.
            self.p = gen_prime_safe(128)
            # Find a generator g
            # For p = 2q+1, elements of order q are squares
            self.g = square_and_multiply(2, 2, self.p)
            q = (self.p - 1) // 2
            alpha = random.randint(2, q - 1)
            self.h_hat = square_and_multiply(self.g, alpha, self.p)
        else:
            self.p = p
            self.g = g
            self.h_hat = h_hat
            
        self.out_len = out_len
        self.block_size = out_len  # 16 bytes by default
        
        # IV = 0
        iv = b'\x00' * self.out_len
        self.md = MerkleDamgard(self._compress, iv, self.block_size)

    def _compress(self, z: bytes, block: bytes) -> bytes:
        """
        h(z, block) = g^z * h_hat^block (mod p)
        """
        z_int = int.from_bytes(z, 'big')
        b_int = int.from_bytes(block, 'big')
        
        # g^z (mod p)
        gz = square_and_multiply(self.g, z_int, self.p)
        # h_hat^block (mod p)
        hb = square_and_multiply(self.h_hat, b_int, self.p)
        
        res = (gz * hb) % self.p
        
        # return fixed length bytes
        # mask to out_len bytes
        return res.to_bytes((self.p.bit_length() + 7) // 8, 'big')[-self.out_len:]

    def hash(self, msg: bytes) -> bytes:
        return self.md.hash(msg)
    
    def get_digest_size(self) -> int:
        return self.out_len
