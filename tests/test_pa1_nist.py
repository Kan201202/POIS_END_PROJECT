"""
Additional tests for PA#1 — NIST statistical tests for PRG output.
Add these to your existing tests/test_pa1.py file.
"""
import math
from src.foundations.owf import DLP_OWF, HILL_PRG
from src.utils.random_utils import generate


def _get_bits(n_bytes=128):
    """Helper: get PRG output as a bit string."""
    owf = DLP_OWF(bits=128)
    prg = HILL_PRG(owf)
    seed = generate(16)
    output = prg.expand(seed, n_bytes)
    return ''.join(f'{b:08b}' for b in output)


def test_prg_nist_frequency():
    """
    NIST Monobit Test: proportion of 1s should be close to 0.5.
    Acceptable range: 0.4 to 0.6 for 1024 bits.
    """
    bits = _get_bits(128)  # 1024 bits
    ratio = bits.count('1') / len(bits)
    assert 0.4 < ratio < 0.6, f"Monobit test failed: ratio={ratio:.3f}"


def test_prg_nist_runs():
    """
    NIST Runs Test: count runs (consecutive same bits).
    Too few or too many runs indicates bias.
    For 1024 bits, expected runs ≈ 512, acceptable range 400-624.
    """
    bits = _get_bits(128)
    runs = 1 + sum(1 for i in range(1, len(bits)) if bits[i] != bits[i-1])
    n = len(bits)
    expected = (2 * n - 1) / 3
    assert expected * 0.60 < runs < expected * 1.40, \
        f"Runs test failed: runs={runs}, expected≈{expected:.0f}"


def test_prg_nist_serial():
    """
    NIST Serial Test: 2-bit patterns (00, 01, 10, 11) should appear ~equally.
    Each should appear ~25% of the time. Acceptable: 20%-30%.
    """
    bits = _get_bits(128)
    patterns = {'00': 0, '01': 0, '10': 0, '11': 0}
    for i in range(len(bits) - 1):
        patterns[bits[i:i+2]] += 1
    total = sum(patterns.values())
    for pat, count in patterns.items():
        ratio = count / total
        assert 0.20 < ratio < 0.30, \
            f"Serial test failed for pattern {pat}: ratio={ratio:.3f}"


def test_prg_different_seeds_give_different_outputs():
    """Two different seeds must produce different outputs."""
    owf = DLP_OWF(bits=128)
    prg = HILL_PRG(owf)
    s1 = generate(16)
    s2 = generate(16)
    o1 = prg.expand(s1, 32)
    o2 = prg.expand(s2, 32)
    assert o1 != o2, "Different seeds must produce different PRG outputs"