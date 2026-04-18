"""
Abstract base class for One-Way Functions (OWF).
"""
from abc import ABC, abstractmethod


class OWF(ABC):
    """
    A One-Way Function f: {0,1}* -> {0,1}* that is:
    - Easy to compute: f(x) is computable in polynomial time
    - Hard to invert: for random x, no PPT adversary can find x' with f(x') = f(x)
    """

    @abstractmethod
    def evaluate(self, x: bytes) -> bytes:
        """
        Evaluate the OWF on input x.
        
        Args:
            x: input bytes
            
        Returns:
            f(x) as bytes
        """
        pass

    @abstractmethod
    def verify_hardness_demo(self) -> bool:
        """
        Demonstration that random inversion fails.
        (For testing purposes only)
        """
        pass
