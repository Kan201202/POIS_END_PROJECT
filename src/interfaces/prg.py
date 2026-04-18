"""
Abstract base class for Pseudorandom Generators (PRG).
"""
from abc import ABC, abstractmethod


class PRG(ABC):
    """
    A Pseudorandom Generator G: {0,1}^n -> {0,1}^{n+l(n)}
    
    For every PPT distinguisher D:
    | Pr[D(G(s)) = 1] - Pr[D(r) = 1] | <= negl(n)
    where s is a random seed and r is uniform random.
    """

    @abstractmethod
    def expand(self, seed: bytes, out_len: int) -> bytes:
        """
        Expand a seed into pseudorandom bits.
        
        Args:
            seed: input seed (must be n bits)
            out_len: desired output length in bytes
            
        Returns:
            Pseudorandom bytes of length out_len
        """
        pass

    @abstractmethod
    def get_seed_length(self) -> int:
        """Returns the required seed length in bytes."""
        pass
