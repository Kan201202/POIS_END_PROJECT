"""
PA#9: Birthday Attack (Collision Finding)
Author: Shubham

Implements collision finding algorithms (Naive and Floyd cycle detection).
"""

from typing import Callable, Tuple

def birthday_attack_naive(hash_fn: Callable[[bytes], bytes], n_bits: int, max_trials: int = 1000000) -> Tuple[bytes, bytes]:
    """
    Naive dictionary-based birthday attack.
    Args:
        hash_fn: The hash function to attack
        n_bits: Number of bits of output to consider for collision
        max_trials: Safety limit
    Returns:
        (msg1, msg2) that collide
    """
    seen = {}
    from src.utils.random_utils import generate
    
    for i in range(max_trials):
        # Generate random input
        x = generate(16)
        
        # Hash and truncate to n_bits
        h = hash_fn(x)
        
        # Extract lower n_bits
        h_int = int.from_bytes(h, 'big')
        h_trunc = h_int & ((1 << n_bits) - 1)
        
        if h_trunc in seen:
            if seen[h_trunc] != x:
                return seen[h_trunc], x
        seen[h_trunc] = x
        
    raise RuntimeError(f"No collision found after {max_trials} trials")

def birthday_attack_floyd(hash_fn: Callable[[bytes], bytes], n_bits: int, start_x: bytes) -> Tuple[bytes, bytes]:
    """
    Floyd's cycle-finding algorithm for collision detection.
    Treats the hash function as f(x), where the output loops back as input.
    """
    def f(x: bytes) -> bytes:
        h = hash_fn(x)
        h_int = int.from_bytes(h, 'big')
        h_trunc = h_int & ((1 << n_bits) - 1)
        # Pad back to length of x
        res = h_trunc.to_bytes(max(1, (n_bits + 7) // 8), 'big')
        # We need input and output domains to match for cycle finding
        # So we pad res to match len(x)
        if len(res) < len(x):
            res = b'\x00' * (len(x) - len(res)) + res
        elif len(res) > len(x):
            res = res[-len(x):]
        return res

    tortoise = f(start_x)
    hare = f(f(start_x))
    
    while tortoise != hare:
        tortoise = f(tortoise)
        hare = f(f(hare))
        
    tortoise = start_x
    while tortoise != hare:
        tortoise = f(tortoise)
        hare = f(hare)
        
    # By this point, tortoise == hare, this is the start of the cycle.
    # To find the exact inputs that collided to reach this node:
    tortoise = start_x
    hare = start_x
    
    # Advance hare by the cycle length (which we need first)
    # Actually wait: The standard Floyd finds the collision of f(t) == f(h) right before they join
    # Alternative to find the collision pairs: 
    # Just run tortoise = start_x; hare = meetup_node; 
    # while f(tortoise) != f(hare): tortoise = f(tortoise); hare = f(hare)
    # return tortoise, hare
    # Let's find cycle length 
    mu = 0
    tortoise = start_x
    hare_meet = hare  # meetup point
    
    while tortoise != hare:
        tortoise = f(tortoise)
        hare = f(hare)
        mu += 1
        
    # The meeting point is tortoise. We need the step right before.
    tortoise = start_x
    hare = hare_meet
    for i in range(mu):
        hare = f(hare) # advance by cycle length? Wait, mu is not cycle length.
    
    # Correct standard Floyd's:
    tortoise = f(start_x)
    hare = f(f(start_x))
    while tortoise != hare:
        tortoise = f(tortoise)
        hare = f(f(hare))
    
    # Tortoise and hare meet. 
    # Let's move tortoise to start
    tortoise = start_x
    prev_tortoise = start_x
    prev_hare = hare
    while tortoise != hare:
        prev_tortoise = tortoise
        prev_hare = hare
        tortoise = f(tortoise)
        hare = f(hare)
    
    return prev_tortoise, prev_hare
