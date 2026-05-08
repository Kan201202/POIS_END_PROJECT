"""
PA#19: Secure AND, XOR, NOT gates
AND uses OT: Alice sends (0, a), Bob uses choice bit b, gets a AND b
XOR is free via additive secret sharing
NOT is free (local flip)
"""
from src.mpc.ot import OT

ot = OT()

def secure_and(a: int, b: int) -> int:
    """Secure AND gate using OT."""
    # Alice is sender with messages (0, a)
    # Bob is receiver with choice bit b
    m0 = (0).to_bytes(16, 'big')
    m1 = (a).to_bytes(16, 'big')

    pk0, pk1, state = ot.receiver_step1(b)
    c0, c1 = ot.sender_step(pk0, pk1, m0, m1)
    result_bytes = ot.receiver_step2(state, c0, c1)
    return int.from_bytes(result_bytes, 'big') & 1

def secure_xor(a: int, b: int) -> int:
    """Secure XOR — free, no communication needed."""
    return a ^ b

def secure_not(a: int) -> int:
    """Secure NOT — free, local flip."""
    return 1 - a