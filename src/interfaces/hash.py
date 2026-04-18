from abc import ABC, abstractmethod

class Hash(ABC):
    """
    Cryptographic Hash Function interface.
    """

    @abstractmethod
    def hash(self, msg: bytes) -> bytes:
        """
        Compute hash digest of the given message.
        """
        pass
