import pytest
from src.mac.prf_mac import PRF_MAC, PRF_from_MAC
from src.mac.cbc_mac import CBC_MAC
from src.utils.random_utils import generate

def test_prf_mac():
    mac = PRF_MAC()
    k = generate(16)
    m = generate(16)
    t = mac.tag(k, m)
    
    assert mac.verify(k, m, t)
    
    # Tampering test
    m_tampered = bytearray(m)
    m_tampered[0] ^= 1
    assert not mac.verify(k, bytes(m_tampered), t)

def test_cbc_mac():
    mac = CBC_MAC()
    k = generate(16)
    m = generate(40) # Larger than block size (16)
    t = mac.tag(k, m)
    
    assert mac.verify(k, m, t)
    
    m_tampered = bytearray(m)
    m_tampered[-1] ^= 1
    assert not mac.verify(k, bytes(m_tampered), t)

def test_euf_cma_forgery():
    mac = CBC_MAC()
    k = generate(16)
    
    # Adversary gets 50 valid tags
    queries = []
    for _ in range(50):
        # random message lengths
        msg = generate(20)
        t = mac.tag(k, msg)
        queries.append((msg, t))
        
    # Attempt forgery on a new message
    m_forged = generate(20)
    # the adversary tries to guess the tag
    t_guessed = generate(16)
    assert not mac.verify(k, m_forged, t_guessed)
    
def test_mac_to_prf():
    mac = PRF_MAC()
    prf = PRF_from_MAC(mac)
    k = generate(16)
    m = generate(16)
    t1 = prf.evaluate(k, m)
    t2 = mac.tag(k, m)
    assert t1 == t2
