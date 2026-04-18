"""
PA#7: Merkle-Damgard Transform
Author: Shubham
"""

from typing import Callable

class MerkleDamgard:
    """
    Generic Merkle-Damgard framework.
    """
    
    def __init__(self, compress_fn: Callable[[bytes, bytes], bytes], iv: bytes, block_size: int):
        """
        Args:
            compress_fn: h(chain_val, block) -> next_chain_val
            iv: Initialization Vector
            block_size: Block size in bytes
        """
        self.compress_fn = compress_fn
        self.iv = iv
        self.block_size = block_size
        self.out_len = len(iv)

    def _pad(self, msg: bytes) -> bytes:
        """
        MD-strengthening padding:
        append 1 bit (0x80), enough 0 bits, and a 64-bit big-endian original length.
        """
        original_len_bits = len(msg) * 8
        msg_padded = msg + b'\x80'
        
        # We need the final length to be 0 mod block_size
        # reserve 8 bytes for length
        rem = len(msg_padded) % self.block_size
        if (self.block_size - rem) < 8:
            # Need an extra block
            pad_len = self.block_size - rem + self.block_size - 8
        else:
            pad_len = self.block_size - rem - 8
            
        msg_padded += b'\x00' * pad_len
        msg_padded += original_len_bits.to_bytes(8, 'big')
        return msg_padded

    def hash(self, msg: bytes) -> bytes:
        padded = self._pad(msg)
        num_blocks = len(padded) // self.block_size
        
        z = self.iv
        for i in range(num_blocks):
            block = padded[i * self.block_size : (i + 1) * self.block_size]
            z = self.compress_fn(z, block)
            
        return z

def dummy_xor_compression(z: bytes, block: bytes) -> bytes:
    """
    Toy XOR compression function for testing PA#7 in isolation.
    """
    # Simply XOR the first len(z) bytes of block with z
    res = bytearray(len(z))
    for i in range(len(z)):
        res[i] = z[i] ^ block[i % len(block)]
    return bytes(res)

