import pytest
from src.attack.birthday import birthday_attack_naive, birthday_attack_floyd
from src.hash.dlp_hash import DLPHash
from src.utils.random_utils import generate
import math

def test_birthday_attack():
    """
    Test birthday attack against a truncated DLP hash (e.g., 10 bits).
    We use a small bit size to keep tests fast.
    """
    hasher = DLPHash(out_len=16)
    n_bits = 10
    
    # Run Naive
    msg1, msg2 = birthday_attack_naive(hasher.hash, n_bits)
    h1 = hasher.hash(msg1)
    h2 = hasher.hash(msg2)
    mask = (1 << n_bits) - 1
    assert (int.from_bytes(h1, 'big') & mask) == (int.from_bytes(h2, 'big') & mask)
    assert msg1 != msg2
    
def test_birthday_floyd():
    """
    Test Floyd's cycle detection.
    """
    hasher = DLPHash(out_len=16)
    n_bits = 10
    start_x = b'\x12' * max(1, (n_bits + 7) // 8) # Pad appropriately
    
    msg1, msg2 = birthday_attack_floyd(hasher.hash, n_bits, start_x)
    h1 = hasher.hash(msg1)
    h2 = hasher.hash(msg2)
    mask = (1 << n_bits) - 1
    assert (int.from_bytes(h1, 'big') & mask) == (int.from_bytes(h2, 'big') & mask)
    assert msg1 != msg2
