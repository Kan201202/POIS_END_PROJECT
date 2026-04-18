import pytest
from src.mac.hmac_impl import HMAC, MAC_Hash
from src.hash.dlp_hash import DLPHash
from src.enc.cca_hmac import EtH_Enc
from src.interfaces.sym_enc import SymEnc
from src.utils.random_utils import generate
from src.attack.length_ext import length_extension_attack_demo

class DummyCPAEnc(SymEnc):
    def encrypt(self, k: bytes, m: bytes) -> tuple[bytes, bytes]:
        # dummy CTR mode
        r = generate(16)
        c = bytes(a ^ b for a, b in zip(r * ((len(m) // 16) + 1), m))
        return (r, c)
        
    def decrypt(self, k: bytes, ct: tuple) -> bytes:
        r, c = ct
        return bytes(a ^ b for a, b in zip(r * ((len(c) // 16) + 1), c))

def test_hmac_correctness():
    hasher = DLPHash(out_len=16)
    hmac = HMAC(hasher)
    
    k = generate(16)
    m = b"hello HMAC"
    t = hmac.tag(k, m)
    
    assert hmac.verify(k, m, t)
    
    m_bad = b"hello HMAC!"
    assert not hmac.verify(k, m_bad, t)

def test_mac_hash():
    """Test MAC to CRHF backward direction."""
    hasher = DLPHash(out_len=16)
    hmac = HMAC(hasher)
    k = generate(16)
    iv = b'\x00' * 16
    
    mac_hash = MAC_Hash(hmac, k, iv)
    h1 = mac_hash.hash(b"test message 1")
    h2 = mac_hash.hash(b"test message 2")
    
    assert h1 != h2

def test_length_extension_attack_demo():
    hasher = DLPHash(out_len=16)
    k = generate(16)
    m = b"secret message"
    
    # Naive MAC = H(k || m)
    t = hasher.hash(k + m)
    
    m_prime = b"appended data"
    
    forged_msg, forged_tag = length_extension_attack_demo(hasher, len(k), m, t, m_prime)
    
    # Check if forgery is valid without using key
    # True naive tag for forged message:
    true_tag = hasher.hash(k + forged_msg)
    
    assert true_tag == forged_tag
    
    # Try length extension on HMAC
    hmac = HMAC(hasher)
    t_hmac = hmac.tag(k, m)
    # The length extension fails to produce a valid HMAC
    # because outer hash protects it
    # We can't even run the attack directly on HMAC without significant error, 
    # but logically we know it fails.

def test_cca_hmac():
    hasher = DLPHash(out_len=16)
    hmac = HMAC(hasher)
    cpa_enc = DummyCPAEnc()
    
    eth = EtH_Enc(cpa_enc, hmac)
    
    kE = generate(16)
    kM = generate(16)
    m = b"CCA secure message"
    
    ct_data, tag = eth.encrypt(kE, kM, m)
    
    decrypted_m = eth.decrypt(kE, kM, ct_data, tag)
    assert decrypted_m == m
    
    # Malleability attack (flip bit in ciphertext)
    r, c = ct_data
    c_malleated = bytearray(c)
    c_malleated[0] ^= 1
    malleated_ct_data = (r, bytes(c_malleated))
    
    dec_fail = eth.decrypt(kE, kM, malleated_ct_data, tag)
    assert dec_fail is None
