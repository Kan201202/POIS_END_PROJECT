from abc import ABC, abstractmethod

class MAC(ABC):
    """
    Message Authentication Code interface.
    """

    @abstractmethod
    def tag(self, k: bytes, m: bytes) -> bytes:
        """
        Generate MAC tag for message m using key k.
        """
        pass

    @abstractmethod
    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        """
        Verify MAC tag t for message m using key k.
        """
        pass
