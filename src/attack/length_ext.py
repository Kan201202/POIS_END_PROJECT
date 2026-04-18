"""
PA#10: Length Extension Attack Demo
Author: Shubham
"""

from src.interfaces.hash import Hash

def length_extension_attack_demo(hash_algo: Hash, k_len: int, m: bytes, t: bytes, m_prime: bytes) -> tuple[bytes, bytes]:
    """
    Demonstrates a length extension attack on a naive MAC: tag = H(k || m).
    
    Given:
      - m: original message
      - t: tag for m, i.e., H(k || m)
      - k_len: length of the secret key
      - m_prime: the suffix we want to append
      
    Returns:
      (forged_message, forged_tag)
      where forged_message = m || padding || m_prime
      and forged_tag is the tag for the forged message, computed WITHOUT k.
      
    Note: For a Merkle-Damgard hash, the hash digest `t` is actually the state after 
    processing `k || m || padding`. By continuing the MD process with `t` as the IV,
    we can hash `m_prime` and get a valid hash for `k || m || padding || m_prime`.
    """
    # 1. Reconstruct the padding that was used for H(k || m)
    # The length of the original hashed data was k_len + len(m)
    orig_len = k_len + len(m)
    
    # MD padding: append 0x80, then 0s, then 64-bit length
    # This requires knowing the block size of the hash, usually via MD framework
    # Because we're simulating the attack abstractly, we just construct the padding
    block_size = hash_algo.md.block_size
    pad = b'\x80'
    rem = (orig_len + 1) % block_size
    if (block_size - rem) < 8:
        pad += b'\x00' * (block_size - rem + block_size - 8)
    else:
        pad += b'\x00' * (block_size - rem - 8)
    pad += (orig_len * 8).to_bytes(8, 'big')
    
    forged_message = m + pad + m_prime
    
    # 2. Forge the tag by initializing a new MD chain with `t` as the IV
    # and hashing m_prime.
    # We must patch the length inside the padding to reflect the new total length.
    # 
    # For demonstration, we directly invoke the compress function on the remaining blocks.
    # The new length string for the final padding:
    total_len = orig_len + len(pad) + len(m_prime)
    
    m_prime_padded = hash_algo.md._pad(m_prime)
    # But wait! _pad will use len(m_prime) for the length block.
    # A true length extension attack needs to substitute the total length into the final block.
    # Let's manually do MD-strengthening for the extended message:
    m_prime_ext_pad = m_prime + b'\x80'
    rem = len(m_prime_ext_pad) % block_size
    if (block_size - rem) < 8:
        m_prime_ext_pad += b'\x00' * (block_size - rem + block_size - 8)
    else:
        m_prime_ext_pad += b'\x00' * (block_size - rem - 8)
    m_prime_ext_pad += (total_len * 8).to_bytes(8, 'big')
    
    # Now compress from state t
    z = t
    num_blocks = len(m_prime_ext_pad) // block_size
    for i in range(num_blocks):
        block = m_prime_ext_pad[i * block_size : (i + 1) * block_size]
        z = hash_algo._compress(z, block)
        
    forged_tag = z
    return forged_message, forged_tag
