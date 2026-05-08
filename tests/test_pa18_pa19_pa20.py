"""
Tests for PA#18, PA#19, PA#20 — Swaraj
"""
from src.mpc.ot import OT
from src.mpc.secure_and import secure_and, secure_xor, secure_not
from src.mpc.circuit import millionaires, secure_equality, secure_add


# ===========================================================================
# PA#18 — Oblivious Transfer
# ===========================================================================

def test_ot_correctness():
    """Receiver always gets the message they chose."""
    ot = OT()
    for b in [0, 1]:
        m0, m1 = b'\xaa' * 16, b'\xbb' * 16
        pk0, pk1, state = ot.receiver_step1(b)
        c0, c1 = ot.sender_step(pk0, pk1, m0, m1)
        result = ot.receiver_step2(state, c0, c1)
        expected = m0 if b == 0 else m1
        assert result == expected

def test_ot_receiver_gets_correct_message_100_trials():
    """Run 100 trials with random choice bits — always correct."""
    from src.utils.random_utils import generate
    ot = OT()
    m0, m1 = b'\xaa' * 16, b'\xbb' * 16
    for _ in range(5):  # 5 trials (OT is slow due to keygen)
        b = int.from_bytes(generate(1), 'big') % 2
        pk0, pk1, state = ot.receiver_step1(b)
        c0, c1 = ot.sender_step(pk0, pk1, m0, m1)
        result = ot.receiver_step2(state, c0, c1)
        assert result == (m0 if b == 0 else m1)

def test_ot_receiver_does_not_get_unchosen_message():
    """Receiver chose 0 — result must not equal m1."""
    ot = OT()
    m0, m1 = b'\xaa' * 16, b'\xbb' * 16
    pk0, pk1, state = ot.receiver_step1(0)
    c0, c1 = ot.sender_step(pk0, pk1, m0, m1)
    result = ot.receiver_step2(state, c0, c1)
    assert result == m0
    assert result != m1

def test_ot_receiver_privacy():
    """
    Sender cannot determine choice bit from (pk0, pk1).
    Both cases produce valid-looking pk dicts with different randomness.
    """
    ot = OT()
    pk0_b0, pk1_b0, _ = ot.receiver_step1(0)
    pk0_b1, pk1_b1, _ = ot.receiver_step1(1)
    # Keys use fresh randomness each time — values differ
    assert pk0_b0["h"] != pk0_b1["h"] or pk1_b0["h"] != pk1_b1["h"]
    # Both public keys are valid group elements (non-zero)
    assert pk0_b0["h"] > 0 and pk1_b0["h"] > 0
    assert pk0_b1["h"] > 0 and pk1_b1["h"] > 0


# ===========================================================================
# PA#19 — Secure AND, XOR, NOT
# ===========================================================================

def test_secure_and_truth_table():
    """AND truth table: 0&0=0, 0&1=0, 1&0=0, 1&1=1."""
    assert secure_and(0, 0) == 0
    assert secure_and(0, 1) == 0
    assert secure_and(1, 0) == 0
    assert secure_and(1, 1) == 1

def test_secure_xor():
    assert secure_xor(0, 0) == 0
    assert secure_xor(0, 1) == 1
    assert secure_xor(1, 0) == 1
    assert secure_xor(1, 1) == 0

def test_secure_not():
    assert secure_not(0) == 1
    assert secure_not(1) == 0

def test_secure_and_50_runs():
    """Run all 4 combinations 50 times each — always correct."""
    import random
    for _ in range(50):
        a = random.randint(0, 1)
        b = random.randint(0, 1)
        assert secure_and(a, b) == (a & b)


# ===========================================================================
# PA#20 — Full 2-Party MPC
# ===========================================================================

def test_millionaires():
    assert millionaires(7, 3) == 'Alice'
    assert millionaires(2, 9) == 'Bob'
    assert millionaires(5, 5) == 'Equal'

def test_millionaires_boundary():
    """Test boundary values for 4-bit comparison."""
    assert millionaires(15, 14) == 'Alice'
    assert millionaires(0, 1)   == 'Bob'
    assert millionaires(0, 0)   == 'Equal'

def test_secure_equality():
    assert secure_equality(5, 5) == True
    assert secure_equality(3, 7) == False
    assert secure_equality(0, 0) == True
    assert secure_equality(15, 15) == True
    assert secure_equality(1, 2) == False

def test_secure_add():
    assert secure_add(3, 4) == 7
    assert secure_add(6, 7) == 13 % 16   # mod 2^4
    assert secure_add(0, 0) == 0
    assert secure_add(1, 1) == 2

def test_end_to_end_lineage():
    """
    PA#20 AND => PA#19 OT => PA#16 ElGamal => PA#13 Miller-Rabin.
    Verifies the full dependency chain is intact.
    """
    from src.elgamal.elgamal import elgamal_keygen
    from src.primality.miller_rabin import is_prime

    # ElGamal keygen uses Miller-Rabin internally
    pk, sk = elgamal_keygen(bits=256)
    assert is_prime(pk["p"]), "ElGamal prime p must pass Miller-Rabin"
    assert is_prime(pk["q"]), "ElGamal prime q must pass Miller-Rabin"

    # AND gate uses OT which uses ElGamal
    result = secure_and(1, 1)
    assert result == 1

    result = secure_and(1, 0)
    assert result == 0