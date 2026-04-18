"""
Abstract base class for Pseudorandom Functions (PRF).
"""
from abc import ABC, abstractmethod


class PRF(ABC):
    """
    A Pseudorandom Function F_k: {0,1}^n -> {0,1}^n
    
    For every PPT distinguisher D making q queries:
    | Pr[D^{F_k(·)}(1^n) = 1] - Pr[D^{f(·)}(1^n) = 1] | <= negl(n)
    where f is a uniformly random function.
    """

    @abstractmethod
    def evaluate(self, key: bytes, x: bytes) -> bytes:
        """
        Evaluate the PRF on input x with key.
        
        Args:
            key: PRF key
            x: input bytes
            
        Returns:
            F_key(x) as bytes
        """
        pass

    @abstractmethod
    def get_key_length(self) -> int:
        """Returns the required key length in bytes."""
        pass

    @abstractmethod
    def get_input_length(self) -> int:
        """Returns the required input length in bytes."""
        pass

    @abstractmethod
    def get_output_length(self) -> int:
        """Returns the output length in bytes."""
        pass
