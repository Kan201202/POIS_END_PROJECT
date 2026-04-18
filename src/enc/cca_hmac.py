"""
PA#10: Encrypt-then-HMAC (CCA-Secure Symmetric Encryption)
Author: Shubham

Assembles CPA-Encryption and HMAC to yield a CCA-secure construction.
"""

from typing import Tuple
from src.interfaces.sym_enc import SymEnc
from src.mac.hmac_impl import HMAC

class EtH_Enc:
    """
    Encrypt-then-HMAC construction.
    Provides CCA2-secure encryption.
    """
    
    def __init__(self, cpa_enc: SymEnc, hmac: HMAC):
        self.cpa_enc = cpa_enc
        self.hmac = hmac
        
    def encrypt(self, kE: bytes, kM: bytes, m: bytes) -> Tuple[tuple, bytes]:
        """
        Encrypts the message and authenticates the ciphertext.
        Returns ((nonce, ciphertext), tag)
        """
        if kE == kM:
            raise ValueError("Encryption and MAC keys must be distinct")
            
        # 1. Encrypt
        ct_data = self.cpa_enc.encrypt(kE, m)
        
        # We need to authenticate *all* ciphertext data, including nonce/IV.
        # ct_data is assumed to be (r, c)
        serialized_ct = ct_data[0] + ct_data[1]
        
        # 2. MAC
        tag = self.hmac.tag(kM, serialized_ct)
        
        return ct_data, tag
        
    def decrypt(self, kE: bytes, kM: bytes, ct_data: tuple, tag: bytes) -> bytes:
        """
        Verifies the HMAC over the ciphertext and then decrypts it.
        Returns the message or None/error if authentication fails.
        """
        serialized_ct = ct_data[0] + ct_data[1]
        
        # 1. Verify MAC first!
        if not self.hmac.verify(kM, serialized_ct, tag):
            return None # Authentication failed! Reject ciphertext.
            
        # 2. Decrypt
        return self.cpa_enc.decrypt(kE, ct_data)
