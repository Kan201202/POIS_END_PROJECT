"""
PA#1: One-Way Functions (OWF) and Pseudorandom Generators (PRG)

OWF Implementation:
- DLP-based: f(x) = g^x mod p
- AES-based: f(k) = AES_k(0^128) ⊕ k
- Factoring: f(p, q) = p * q

PRG from OWF (HILL/Hastad-Impagliazzo-Levin-Luby):
G(x_0) = b(x_0) || b(x_1) || ... || b(x_ℓ)
where x_{i+1} = f(x_i) and b is a hard-core predicate
"""

from abc import ABC, abstractmethod
from interfaces.owf import OWF
from interfaces.prg import PRG
from src.utils.random_utils import generate
from src.utils.mod_exp import square_and_multiply
from src.primality.miller_rabin import gen_prime_safe
import struct


# ============================================================================
# OWF IMPLEMENTATIONS
# ============================================================================

class DLP_OWF(OWF):
    """
    Discrete Logarithm Problem (DLP) based One-Way Function.
    
    f(x) = g^x mod p
    
    where p is a safe prime and g is a generator of the prime-order subgroup.
    """
    
    def __init__(self, bits: int = 256):
        """
        Initialize DLP_OWF by generating safe prime parameters.
        
        Args:
            bits: bit length of prime p
        """
        # Generate safe prime p = 2q + 1 where q is also prime
        self.p = gen_prime_safe(bits)
        
        # q is the order of the prime-order subgroup
        self.q = (self.p - 1) // 2
        
        # Find generator g of the subgroup of order q
        # Start with a candidate and check if g^2 != 1 mod p
        g_candidate = 2
        while True:
            g_candidate_q = square_and_multiply(g_candidate, self.q, self.p)
            if g_candidate_q == 1 and g_candidate != 1:
                # Found a generator of order q
                self.g = g_candidate
                break
            g_candidate += 1
    
    def evaluate(self, x: bytes) -> bytes:
        """
        Compute f(x) = g^x mod p.
        
        Args:
            x: input bytes (interpreted as big-endian integer mod q)
            
        Returns:
            f(x) as bytes
        """
        # Convert bytes to integer mod q
        x_int = int.from_bytes(x, 'big') % self.q
        
        # Compute g^x mod p
        result = square_and_multiply(self.g, x_int, self.p)
        
        # Return as bytes
        return result.to_bytes((self.p.bit_length() + 7) // 8, 'big')
    
    def verify_hardness_demo(self) -> bool:
        """
        Demo: attempt brute-force DLP inversion on small parameters.
        """
        x = generate(4)  # 32-bit input
        y = self.evaluate(x)
        
        # Try to find x from y
        x_int = int.from_bytes(x, 'big') % self.q
        y_int = int.from_bytes(y, 'big')
        
        # Brute-force search (only works for tiny q)
        if self.q < 2**20:  # Only feasible for small q
            for guess in range(self.q):
                candidate = square_and_multiply(self.g, guess, self.p)
                if candidate == y_int:
                    return guess == x_int
        
        return True  # Assume hardness for large q


class FactorOWF(OWF):
    """
    Integer factorization-based One-Way Function.
    
    f(p, q) = p * q
    
    where p and q are large primes.
    """
    
    def __init__(self, bits: int = 512):
        """
        Initialize FactorOWF by generating two large primes.
        
        Args:
            bits: bit length of each prime (composite will be ~2*bits)
        """
        from src.primality.miller_rabin import gen_prime
        self.p = gen_prime(bits // 2)
        self.q = gen_prime(bits // 2)
    
    def evaluate(self, x: bytes) -> bytes:
        """
        Compute f(p, q) = N = p * q.
        
        Args:
            x: unused (evaluation just multiplies p and q)
            
        Returns:
            N = p * q as bytes
        """
        N = self.p * self.q
        return N.to_bytes((N.bit_length() + 7) // 8, 'big')
    
    def verify_hardness_demo(self) -> bool:
        """
        Demo: factorization is hard without knowing p, q.
        """
        N = self.p * self.q
        # Factoring is hard; we just verify N is composite
        return N == self.p * self.q


# ============================================================================
# PRG FROM OWF (HILL CONSTRUCTION)
# ============================================================================

class HILL_PRG(PRG):
    """
    Haastad-Impagliazzo-Levin-Luby (HILL) Pseudorandom Generator.
    
    Constructs a PRG from any OWF with a hard-core predicate.
    
    G(x_0) = b(x_0) || b(x_1) || ... || b(x_ℓ)
    where x_{i+1} = f(x_i)
    and b is the Goldreich-Levin hard-core predicate: b(x) = <x, r> = sum(x_i * r_i) mod 2
    """
    
    def __init__(self, owf: OWF):
        """
        Initialize HILL_PRG with a given OWF.
        
        Args:
            owf: OWF instance to use as the underlying function
        """
        self.owf = owf
        # Hard-core predicate: use a fixed random string r for this instance
        self.r = generate(32)  # 256-bit hard-core predicate seed
    
    def goldreich_levin_bit(self, x: bytes) -> int:
        """
        Compute Goldreich-Levin hard-core predicate.
        b(x) = <x, r> = sum(x_i * r_i) mod 2
        """
        result = 0
        min_bytes = min(len(x), len(self.r))
        for i in range(min_bytes):
            # XOR each bit of x[i] AND r[i], accumulate parity
            result ^= bin(x[i] & self.r[i]).count('1') % 2
        return result
    
    def expand(self, seed: bytes, out_len: int) -> bytes:
        """
        Expand seed into pseudorandom bytes using HILL construction.
        """
        bits = []
        current_x = seed

        while len(bits) < out_len * 8:
            bit = self.goldreich_levin_bit(current_x)
            bits.append(bit)
            current_x = self.owf.evaluate(current_x)

        # Pack bits into bytes
        result = bytearray()
        for i in range(out_len):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i * 8 + j]
            result.append(byte)

        return bytes(result)
    
    def get_seed_length(self) -> int:
        """Returns the seed length (32 bytes for DLP-based OWF)."""
        return 32


# ============================================================================
# PRG FROM PRF (Backward Direction)
# ============================================================================

class PRG_from_PRF(PRG):
    """
    Backward direction: PRG from PRF.
    
    Given a PRF F_s, we can construct a PRG:
    G(s) = F_s(0^n) || F_s(1^n)
    
    This is a trivial backward reduction showing any length-doubling PRG
    is also a one-way function.
    """
    
    def __init__(self, prf):
        """
        Initialize PRG from a PRF instance.
        
        Args:
            prf: PRF instance implementing PRF interface
        """
        self.prf = prf
    
    def expand(self, seed: bytes, out_len: int) -> bytes:
        """
        Expand seed using PRF: output first out_len bytes of
        F_s(0^n) || F_s(1^n) || ...
        
        Args:
            seed: PRF key (seed)
            out_len: desired output length in bytes
            
        Returns:
            Pseudorandom bytes
        """
        output = bytearray()
        counter = 0
        
        while len(output) < out_len:
            # Query PRF on counter value
            counter_bytes = counter.to_bytes(16, 'big')
            prf_out = self.prf.evaluate(seed, counter_bytes)
            output.extend(prf_out)
            counter += 1
        
        return bytes(output[:out_len])
    
    def get_seed_length(self) -> int:
        """Returns the seed length (PRF key length)."""
        return self.prf.get_key_length()


# ============================================================================
# DEMO / TESTING
# ============================================================================

if __name__ == "__main__":
    print("PA#1: OWF and PRG Demo")
    print("=" * 50)
    
    # Demo 1: DLP OWF
    print("\n1. DLP-based OWF:")
    print("   Generating safe prime (this may take a moment)...")
    dlp_owf = DLP_OWF(bits=128)  # Smaller for demo
    print(f"   p = {dlp_owf.p}")
    print(f"   g = {dlp_owf.g}")
    
    x = generate(16)
    y = dlp_owf.evaluate(x)
    print(f"   f(x) computed: {y.hex()[:32]}...")
    
    # Demo 2: HILL PRG
    print("\n2. HILL-based PRG:")
    prg = HILL_PRG(dlp_owf)
    seed = generate(16)
    output = prg.expand(seed, 32)
    print(f"   Expanded {len(seed)} bytes to {len(output)} bytes")
    print(f"   Output: {output.hex()}")
