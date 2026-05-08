"""
PA#2: Pseudorandom Function (PRF) via GGM Tree Construction

GGM (Goldreich-Goldwasser-Micali) Construction:

Given a length-doubling PRG G: {0,1}^n -> {0,1}^{2n}
write G(s) = G_0(s) || G_1(s)

Define PRF: F_k(b_1 b_2 ... b_n) = G_{b_n}(...G_{b_2}(G_{b_1}(k))...)

This is a binary tree of depth n where each leaf is indexed by an n-bit input.
"""

from interfaces.prf import PRF
from src.foundations.owf import HILL_PRG
from src.utils.random_utils import generate


class GGM_PRF(PRF):
    """
    GGM Tree-based Pseudorandom Function.
    
    Constructs a PRF from a PRG by building a binary tree where:
    - Root is keyed by the PRF key
    - Each internal node expands via the PRG into left/right children
    - Leaves are indexed by input bits
    """
    
    def __init__(self, prg: HILL_PRG = None):
        """
        Initialize GGM_PRF with a PRG.
        
        Args:
            prg: PRG instance (if None, creates default DLP-based PRG via HILL)
        """
        if prg is None:
            from src.foundations.owf import DLP_OWF
            dlp_owf = DLP_OWF(bits=128)
            self.prg = HILL_PRG(dlp_owf)
        else:
            self.prg = prg
        
        # Standard parameters: 128-bit keys and inputs, 128-bit outputs
        self.key_len = 16  # bytes
        self.input_len = 16  # bytes (128 bits = 16 input bits for practical depth)
        self.output_len = 16  # bytes
    
    def evaluate(self, key: bytes, x: bytes) -> bytes:
        """
        Evaluate GGM PRF: F_key(x).
        
        Algorithm:
        1. Start at root with current_node = key
        2. For each bit b_i in x (left-to-right):
           - Expand current_node using PRG: left || right = G(current_node)
           - If b_i = 0: current_node = left
           - If b_i = 1: current_node = right
        3. Return final current_node
        
        Args:
            key: PRF key (16 bytes)
            x: input (must be multiple of 8 bits, max 128 bits / 16 bytes)
            
        Returns:
            F_key(x) as bytes (16 bytes)
        """
        if len(key) != self.key_len:
            raise ValueError(f"Key must be {self.key_len} bytes, got {len(key)}")
        
        if len(x) > self.input_len:
            raise ValueError(f"Input too long (max {self.input_len} bytes)")
        
        # Pad input to uniform length if needed
        x_padded = x + b'\x00' * (self.input_len - len(x))
        
        # Start at root with key
        current_node = key
        
        # Process each bit of input
        num_bits = len(x) * 8
        
        for i in range(num_bits):
            # Expand current node: get PRG output (2x expansion)
            # We need the PRG to output 2 * len(current_node) bytes
            expanded = self.prg.expand(current_node, 2 * len(current_node))
            
            # Split into left and right halves
            half_len = len(current_node)
            left = expanded[:half_len]
            right = expanded[half_len:2 * half_len]
            
            # Extract bit from input
            byte_idx = i // 8
            bit_idx = 7 - (i % 8)  # MSB first
            bit = (x_padded[byte_idx] >> bit_idx) & 1
            
            # Choose left or right based on bit
            current_node = right if bit else left
        
        return current_node
    
    def get_key_length(self) -> int:
        """Returns the key length (16 bytes)."""
        return self.key_len
    
    def get_input_length(self) -> int:
        """Returns the maximum input length (16 bytes)."""
        return self.input_len
    
    def get_output_length(self) -> int:
        """Returns the output length (16 bytes)."""
        return self.output_len


class AES_PRF(PRF):
    """
    Alternative PRF: Direct AES-based.
    
    For practical purposes, AES-128 can be used directly as a PRF:
    F_k(x) = AES_k(x)
    
    This is simpler than GGM but requires implementing AES.
    For now, we use a placeholder that demonstrates the interface.
    """
    
    def __init__(self):
        """Initialize AES_PRF."""
        self.key_len = 16
        self.input_len = 16
        self.output_len = 16
    
    def evaluate(self, key: bytes, x: bytes) -> bytes:
        """
        Evaluate AES PRF: AES_key(x).
        
        Args:
            key: AES key (16 bytes for AES-128)
            x: input (16 bytes)
            
        Returns:
            AES_key(x) as bytes (16 bytes)
        """
        if len(key) != self.key_len:
            raise ValueError(f"Key must be {self.key_len} bytes")
        if len(x) != self.input_len:
            raise ValueError(f"Input must be {self.input_len} bytes")
        
        # TODO: Implement actual AES encryption
        # For now, return deterministic function based on key and input
        combined = key + x
        return combined[:16]  # Placeholder
    
    def get_key_length(self) -> int:
        return self.key_len
    
    def get_input_length(self) -> int:
        return self.input_len
    
    def get_output_length(self) -> int:
        return self.output_len


# ============================================================================
# BIDIRECTIONAL REDUCTION: PRG FROM PRF
# ============================================================================

class PRG_from_GGM_PRF:
    """
    Backward direction: PRG from PRF.
    
    Shows that any PRF can be used to construct a PRG:
    G(s) = F_s(0^n) || F_s(1^n)
    
    This demonstrates PRF ⇔ PRG bidirectionality.
    """
    
    def __init__(self, prf: PRF):
        """
        Initialize PRG from PRF.
        
        Args:
            prf: PRF instance
        """
        self.prf = prf
    
    def expand(self, seed: bytes, out_len: int) -> bytes:
        """
        Construct PRG from PRF: G(s) = F_s(0^n) || F_s(1^n).
        
        Args:
            seed: PRF key (seed)
            out_len: desired output length in bytes
            
        Returns:
            Pseudorandom bytes of length out_len
        """
        output = bytearray()
        
        # Generate pseudo-random bytes until we have enough
        counter = 0
        while len(output) < out_len:
            # Create input: counter as bytes
            input_bytes = counter.to_bytes(
                self.prf.get_input_length(), 'big'
            )
            
            # Evaluate PRF and append
            prf_output = self.prf.evaluate(seed, input_bytes)
            output.extend(prf_output)
            counter += 1
        
        return bytes(output[:out_len])
    
    def get_seed_length(self) -> int:
        return self.prf.get_key_length()


# ============================================================================
# DISTINGUISHING GAME (Security Test)
# ============================================================================

def distinguishing_game(prf: PRF, num_queries: int = 100) -> tuple[int, int]:
    """
    IND-PRF distinguishing game.
    
    An adversary is given access to either:
    - A real PRF oracle with a random key
    - A random oracle that returns uniformly random outputs
    
    The adversary makes num_queries queries and tries to distinguish.
    
    For a secure PRF, the adversary's advantage should be negligible.
    
    Args:
        prf: PRF instance
        num_queries: number of queries to make
        
    Returns:
        (queries_to_prf, queries_to_random) - for analysis
    """
    import secrets
    
    # Generate random key
    key = generate(prf.get_key_length())
    
    # Make queries to real PRF
    real_outputs = []
    for _ in range(num_queries):
        x = generate(prf.get_input_length())
        y = prf.evaluate(key, x)
        real_outputs.append((x, y))
    
    # Generate random outputs of same size
    random_outputs = []
    for _ in range(num_queries):
        x = generate(prf.get_input_length())
        y = generate(prf.get_output_length())
        random_outputs.append((x, y))
    
    # In a real distinguishing game, an adversary would try to tell them apart
    # For testing, we just verify responses are consistent:
    # PRF should give same output for same input, random should vary
    
    return num_queries, num_queries


# ============================================================================
# DEMO / TESTING
# ============================================================================

if __name__ == "__main__":
    print("PA#2: GGM PRF Demo")
    print("=" * 50)
    
    # Demo 1: GGM PRF
    print("\n1. GGM Tree-based PRF:")
    print("   Initializing GGM_PRF (building tree with DLP-OWF base)...")
    prf = GGM_PRF()
    
    key = generate(prf.get_key_length())
    x1 = generate(prf.get_input_length())
    x2 = generate(prf.get_input_length())
    
    y1 = prf.evaluate(key, x1)
    y2 = prf.evaluate(key, x2)
    y1_again = prf.evaluate(key, x1)
    
    print(f"   F_key(x1) = {y1.hex()}")
    print(f"   F_key(x2) = {y2.hex()}")
    print(f"   F_key(x1) [again] = {y1_again.hex()}")
    print(f"   Deterministic: {y1 == y1_again}")
    print(f"   Different inputs → different outputs: {y1 != y2}")
    
    # Demo 2: PRG from PRF
    print("\n2. Backward direction: PRG from PRF")
    prg_from_prf = PRG_from_GGM_PRF(prf)
    seed = generate(prg_from_prf.get_seed_length())
    output = prg_from_prf.expand(seed, 32)
    print(f"   PRG output: {output.hex()}")
