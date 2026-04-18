import pytest
from src.hash.dlp_hash import DLPHash

def test_dlp_hash_distinct():
    """
    PA#8 Integration test: Hash at least five messages of different lengths
    and confirm distinct inputs produce distinct digests.
    """
    hasher = DLPHash(out_len=16) 
    
    msgs = [
        b'a',
        b'hello world',
        b'this is a much longer message to test length padding',
        b'',
        b'\x01' * 64
    ]
    
    digests = [hasher.hash(m) for m in msgs]
    
    # Assert all distinct
    assert len(set(digests)) == len(msgs)
    
    # Assert length is correct
    for d in digests:
        assert len(d) == 16
