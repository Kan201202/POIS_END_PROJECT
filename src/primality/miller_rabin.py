"""
PA#13: Miller-Rabin Primality Testing
Author: Raj

Miller-Rabin is a fast probabilistic primality test.
- If it returns COMPOSITE: the number is definitely composite
- If it returns PROBABLY_PRIME: the number is prime with probability >= 1 - 4^(-k)
  where k is the number of rounds

For k=40: error probability < 2^(-80), which is cryptographically secure.
"""

from src.utils.mod_exp import square_and_multiply
from src.utils.random_utils import generate
import random


class MillerRabinResult:
    """Result of Miller-Rabin test."""
    
    COMPOSITE = "COMPOSITE"
    PROBABLY_PRIME = "PROBABLY_PRIME"


def is_prime(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin primality test.
    
    Args:
        n: positive integer to test (must be odd and > 2)
        k: number of rounds (default 40 gives error probability < 2^(-80))
        
    Returns:
        False if n is definitely composite
        True if n is probably prime (with error probability <= 4^(-k))
        
    Raises:
        ValueError: if n is not valid
    """
    if not isinstance(n, int) or n < 2:
        raise ValueError("n must be an integer >= 2")
    
    # Handle small cases
    if n == 2:
        return True
    if n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n - 1 = 2^s * d where d is odd
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    
    # Run k rounds of testing
    for _ in range(k):
        # Choose random witness a in [2, n-2]
        a = random.randint(2, n - 2)
        
        # Compute x = a^d mod n
        x = square_and_multiply(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        # Square x repeatedly s-1 times
        composite = True
        for _ in range(s - 1):
            x = square_and_multiply(x, 2, n)
            if x == n - 1:
                composite = False
                break
        
        if composite:
            return False
    
    return True


def gen_prime(bits: int, k: int = 40) -> int:
    """
    Generate a random probably-prime integer of exactly 'bits' bits.
    
    Args:
        bits: desired bit length (must be >= 2)
        k: Miller-Rabin rounds (default 40)
        
    Returns:
        Random integer p such that:
        - p is odd and has exactly 'bits' bits
        - p passes Miller-Rabin test with k rounds
        - 2^(bits-1) <= p < 2^bits
        
    Raises:
        ValueError: if bits < 2
    """
    if bits < 2:
        raise ValueError("bits must be >= 2")
    
    # Generate random odd number with exactly 'bits' bits
    while True:
        # Start with a random number with the high bit set
        candidate = int.from_bytes(generate((bits + 7) // 8), 'big')
        
        # If the random value has fewer bits than requested, retry
        if candidate.bit_length() < bits:
            continue

        # Mask to exactly 'bits' bits and ensure it's odd
        candidate = (candidate >> (candidate.bit_length() - bits)) | (1 << (bits - 1)) | 1
        
        # Ensure it's exactly 'bits' bits
        if candidate.bit_length() != bits:
            continue
        
        # Check primality
        if is_prime(candidate, k):
            return candidate


def gen_prime_safe(bits: int) -> int:
    """
    Generate a safe prime p = 2q + 1 where q is also prime.
    
    Used for DH and DLP-based protocols.
    
    Args:
        bits: bit length for p (q will have bits-1 bits)
        
    Returns:
        Safe prime p where p = 2q + 1 and both p and q are probably prime
    """
    if bits < 3:
        raise ValueError("bits must be >= 3 for safe primes")
    
    while True:
        # Generate q as a bits-1 bit probably-prime
        q = gen_prime(bits - 1, k=40)
        
        # Compute p = 2q + 1
        p = 2 * q + 1
        
        # Check if p is also probably-prime
        if is_prime(p, k=40):
            return p


# ============================================================================
# Test/Demo Code Below
# ============================================================================

def carmichael_number_demo():
    """
    Demonstrate that 561 (smallest Carmichael number) is correctly identified
    as composite by Miller-Rabin, despite passing Fermat test.
    
    561 = 3 * 11 * 17
    """
    n = 561
    
    print(f"\n=== Carmichael Number Demo ===")
    print(f"Testing n = {n} (3 × 11 × 17)")
    print(f"Carmichael number: passes Fermat test but is composite")
    
    result = is_prime(n, k=5)
    print(f"Miller-Rabin result (5 rounds): {result}")
    print(f"Expected: False (composite)")
    
    assert not result, "Miller-Rabin should reject Carmichael numbers"
    print("✓ Test passed: Carmichael number correctly identified as composite\n")


def prime_generation_demo():
    """
    Demonstrate prime generation for different bit lengths.
    """
    print("\n=== Prime Generation Demo ===")
    
    for bits in [8, 16, 32]:
        p = gen_prime(bits)
        print(f"Generated {bits}-bit probable prime: {p}")
        print(f"  Bit length: {p.bit_length()}")
        print(f"  Is probably prime (40 rounds): {is_prime(p, k=40)}")


if __name__ == "__main__":
    carmichael_number_demo()
    prime_generation_demo()
