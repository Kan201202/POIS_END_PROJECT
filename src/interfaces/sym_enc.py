from abc import ABC, abstractmethod
from typing import Tuple

class SymEnc(ABC):
    """
    Symmetric Encryption interface.
    """

    @abstractmethod
    def encrypt(self, k: bytes, m: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt a message with key k.
        Returns a tuple of (nonce/IV/randomness, ciphertext).
        For some modes an IV might be packed into the ciphertext, but the interface 
        signature from the specs uses Tuple[bytes, bytes] for CPA.
        """
        pass

    @abstractmethod
    def decrypt(self, k: bytes, ct: tuple) -> bytes:
        """
        Decrypt ciphertext using key k.
        """
        pass
