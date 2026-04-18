import pytest
from src.hash.merkle_damgard import MerkleDamgard, dummy_xor_compression
from src.utils.random_utils import generate

def test_merkle_damgard_padding():
    iv = b'\x00' * 8
    md = MerkleDamgard(dummy_xor_compression, iv, 8)
    
    # 5 bytes msg -> 5*8 = 40 bits
    msg = b'hello'
    padded = md._pad(msg)
    
    assert len(padded) % 8 == 0
    # Original length in bits
    assert int.from_bytes(padded[-8:], 'big') == 40
    
def test_merkle_damgard_hash():
    iv = b'\x00' * 8
    md = MerkleDamgard(dummy_xor_compression, iv, 8)
    
    msg1 = b'hello world, welcome to hashing'
    h1 = md.hash(msg1)
    
    msg2 = b'hello world, welcome to hashing'
    h2 = md.hash(msg2)
    
    assert h1 == h2
    assert len(h1) == 8

def test_md_collision_propagation():
    """
    If we find a collision in the compression function, it propagates.
    But for our trivial XOR compression, collisions are easily found.
    Just checking two different messages have different hashes typically.
    """
    iv = b'\x00' * 8
    md = MerkleDamgard(dummy_xor_compression, iv, 8)
    h1 = md.hash(b'hello')
    h2 = md.hash(b'world')
    assert h1 != h2
