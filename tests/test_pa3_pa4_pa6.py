"""
Tests for PA#3, PA#4, PA#6 — Kanishk
Run: pytest tests/test_pa3_pa4_pa6.py -v
"""

import pytest
from src.enc.cpa_enc import CPA_Enc, CPA_Enc_Broken, ind_cpa_game
from src.enc.modes import CBC, OFB, CTR, ModesOfOperation
from src.enc.cca_enc import CCA_Enc, malleability_attack_demo, malleability_cca_demo, ind_cca2_game
from src.utils.random_utils import generate


# ---------------------------------------------------------------------------
# Fast stub PRF — avoids GGM slowness in unit tests.
# GGM correctness is already verified in test_pa2.py.
# Slow GGM-backed tests belong in integration/demo runs.
# ---------------------------------------------------------------------------

class FastStubPRF:
    """XOR-based stub PRF for fast CI testing."""
    def evaluate(self, k, x): return bytes(a ^ b for a, b in zip(k, x))
    def get_key_length(self): return 16
    def get_input_length(self): return 16
    def get_output_length(self): return 16


# ===========================================================================
# PA#3: CPA-Secure Encryption
# ===========================================================================

class TestCPA_Enc:

    def setup_method(self):
        self.enc = CPA_Enc()
        self.k   = generate(16)

    def test_encrypt_decrypt_single_block(self):
        m = b"exactly16bytes!!"
        r, c = self.enc.encrypt(self.k, m)
        assert self.enc.decrypt(self.k, (r, c)) == m

    def test_encrypt_decrypt_short(self):
        m = b"short"
        r, c = self.enc.encrypt(self.k, m)
        assert self.enc.decrypt(self.k, (r, c)) == m

    def test_encrypt_decrypt_multiblock(self):
        m = b"A" * 50
        r, c = self.enc.encrypt(self.k, m)
        assert self.enc.decrypt(self.k, (r, c)) == m

    def test_fresh_nonce_each_call(self):
        """Same message encrypted twice should give different ciphertexts."""
        m = b"same message!!!!"
        r1, c1 = self.enc.encrypt(self.k, m)
        r2, c2 = self.enc.encrypt(self.k, m)
        # Nonces should differ (with overwhelming probability)
        assert r1 != r2 or c1 != c2

    def test_wrong_key_fails(self):
        m = b"test message!!!!"
        r, c = self.enc.encrypt(self.k, m)
        k_wrong = generate(16)
        # Decryption with wrong key should either fail or give wrong plaintext
        try:
            dec = self.enc.decrypt(k_wrong, (r, c))
            assert dec != m
        except Exception:
            pass  # padding error is also acceptable

    def test_ind_cpa_advantage_negligible(self):
        """
        IND-CPA game: adversary with random guessing has advantage ~0.
        We verify the game logic is correct using a fast stub PRF
        (GGM is intentionally slow; full game demoed in cpa_enc.py __main__).
        """
        # Use a fast XOR-stub PRF to verify game logic without GGM slowness
        class FastStubPRF:
            def evaluate(self, k, x): return bytes(a ^ b for a, b in zip(k, x))
            def get_key_length(self): return 16
            def get_input_length(self): return 16
            def get_output_length(self): return 16

        from src.enc.cpa_enc import CPA_Enc
        enc_fast = CPA_Enc(prf=FastStubPRF())
        adv = ind_cpa_game(enc_fast, num_rounds=100)
        assert adv < 0.2, f"IND-CPA advantage too high: {adv}"

    def test_broken_nonce_reuse(self):
        """Broken scheme: same nonce -> same ciphertext for same message."""
        broken = CPA_Enc_Broken()
        k = generate(16)
        m = b"vote: OPTION A !!"[:16]
        _, c1 = broken.encrypt(k, m)
        _, c2 = broken.encrypt(k, m)
        assert c1 == c2, "Nonce-reuse broken scheme must produce identical ciphertexts"


# ===========================================================================
# PA#4: Modes of Operation
# ===========================================================================

class TestCBCMode:

    def setup_method(self):
        self.cbc = CBC()
        self.k   = generate(16)

    def _roundtrip(self, m):
        iv, c = self.cbc.encrypt(self.k, m)
        return self.cbc.decrypt(self.k, iv, c)

    def test_short_message(self):
        assert self._roundtrip(b"short") == b"short"

    def test_exact_block(self):
        m = b"exactly16bytes!!"
        assert self._roundtrip(m) == m

    def test_multiblock(self):
        m = b"B" * 48
        assert self._roundtrip(m) == m

    def test_random_iv_each_call(self):
        m = b"same plaintext!!"
        iv1, c1 = self.cbc.encrypt(self.k, m)
        iv2, c2 = self.cbc.encrypt(self.k, m)
        assert iv1 != iv2 or c1 != c2


class TestOFBMode:

    def setup_method(self):
        self.ofb = OFB()
        self.k   = generate(16)

    def test_short(self):
        m = b"hi"
        iv, c = self.ofb.encrypt(self.k, m)
        assert self.ofb.decrypt(self.k, iv, c) == m

    def test_exact_block(self):
        m = b"exactly16bytes!!"
        iv, c = self.ofb.encrypt(self.k, m)
        assert self.ofb.decrypt(self.k, iv, c) == m

    def test_multiblock(self):
        m = b"C" * 40
        iv, c = self.ofb.encrypt(self.k, m)
        assert self.ofb.decrypt(self.k, iv, c) == m

    def test_enc_equals_dec(self):
        """OFB encrypt and decrypt are the same XOR operation."""
        m = b"test message!!!!"
        iv = generate(16)
        _, c = self.ofb.encrypt(self.k, m, iv=iv)
        # Decrypting the ciphertext with same IV gives back plaintext
        assert self.ofb.decrypt(self.k, iv, c) == m

    def test_keystream_reuse_attack(self):
        m0 = b"secret message!!"
        m1 = b"another secret!!"
        recovered = self.ofb.keystream_reuse_attack_demo(self.k, m0, m1)
        assert recovered == m1


class TestCTRMode:

    def setup_method(self):
        self.ctr = CTR(prf=FastStubPRF())
        self.k   = generate(16)

    def test_short(self):
        m = b"hi"
        r, c = self.ctr.encrypt(self.k, m)
        assert self.ctr.decrypt(self.k, r, c) == m

    def test_exact_block(self):
        m = b"exactly16bytes!!"
        r, c = self.ctr.encrypt(self.k, m)
        assert self.ctr.decrypt(self.k, r, c) == m

    def test_multiblock(self):
        m = b"D" * 50
        r, c = self.ctr.encrypt(self.k, m)
        assert self.ctr.decrypt(self.k, r, c) == m

    def test_no_padding_needed(self):
        """CTR works for any length without padding."""
        for length in [1, 7, 15, 16, 17, 31, 32, 33]:
            m = bytes(range(length % 256)) * (length // 256 + 1)
            m = m[:length]
            r, c = self.ctr.encrypt(self.k, m)
            assert len(c) == len(m)
            assert self.ctr.decrypt(self.k, r, c) == m


class TestUnifiedAPI:

    def setup_method(self):
        prf = FastStubPRF()
        self.modes = ModesOfOperation(prf=prf)
        self.k     = generate(16)

    @pytest.mark.parametrize("mode,msg", [
        ("CBC", b"short"),
        ("CBC", b"exactly16bytes!!"),
        ("CBC", b"E" * 40),
        ("OFB", b"short"),
        ("OFB", b"exactly16bytes!!"),
        ("OFB", b"F" * 40),
        ("CTR", b"short"),
        ("CTR", b"exactly16bytes!!"),
        ("CTR", b"G" * 40),
    ])
    def test_roundtrip(self, mode, msg):
        ct  = self.modes.encrypt(mode, self.k, msg)
        dec = self.modes.decrypt(mode, self.k, ct)
        assert dec == msg

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError):
            self.modes.encrypt("GCM", self.k, b"test")


# ===========================================================================
# PA#6: CCA-Secure Encryption
# ===========================================================================

class TestCCA_Enc:

    def setup_method(self):
        self.cca = CCA_Enc()
        self.kE  = generate(16)
        self.kM  = generate(16)
        # ensure keys are distinct
        while self.kM == self.kE:
            self.kM = generate(16)

    def test_encrypt_decrypt(self):
        m = b"CCA test msg!!!!"
        ct, tag = self.cca.encrypt(self.kE, self.kM, m)
        assert self.cca.decrypt(self.kE, self.kM, ct, tag) == m

    def test_multiblock(self):
        m = b"H" * 50
        ct, tag = self.cca.encrypt(self.kE, self.kM, m)
        assert self.cca.decrypt(self.kE, self.kM, ct, tag) == m

    def test_tampered_ciphertext_rejected(self):
        m = b"sensitive data!!"
        (r, c), tag = self.cca.encrypt(self.kE, self.kM, m)
        c_bad = bytes([c[0] ^ 1]) + c[1:]
        result = self.cca.decrypt(self.kE, self.kM, (r, c_bad), tag)
        assert result is None, "Tampered ciphertext must return ⊥"

    def test_tampered_nonce_rejected(self):
        m = b"sensitive data!!"
        (r, c), tag = self.cca.encrypt(self.kE, self.kM, m)
        r_bad = bytes([r[0] ^ 1]) + r[1:]
        result = self.cca.decrypt(self.kE, self.kM, (r_bad, c), tag)
        assert result is None

    def test_tampered_tag_rejected(self):
        m = b"sensitive data!!"
        ct, tag = self.cca.encrypt(self.kE, self.kM, m)
        tag_bad = bytes([tag[0] ^ 1]) + tag[1:]
        result = self.cca.decrypt(self.kE, self.kM, ct, tag_bad)
        assert result is None

    def test_key_reuse_raises(self):
        with pytest.raises(ValueError):
            self.cca.encrypt(self.kE, self.kE, b"test")

    def test_malleability_cpa_succeeds(self):
        """Malleability attack WORKS on plain CPA encryption."""
        from src.enc.cpa_enc import CPA_Enc
        cpa = CPA_Enc()
        m = b"vote:yes!!!!!!!!!"[:16]
        _, ok = malleability_attack_demo(cpa, self.kE, m)
        assert ok, "Malleability attack must succeed on CPA-only scheme"

    def test_malleability_cca_blocked(self):
        """Malleability attack is BLOCKED by CCA-Enc."""
        blocked = malleability_cca_demo(self.cca, self.kE, self.kM, b"vote:yes!!!!!!!!!"[:16])
        assert blocked, "Malleability attack must be rejected by CCA scheme"

    def test_ind_cca2_advantage_negligible(self):
        """
        IND-CCA2 game: adversary cannot gain advantage even with decryption oracle.
        Uses fast stub PRF to avoid GGM slowness in CI.
        """
        class FastStubPRF:
            def evaluate(self, k, x): return bytes(a ^ b for a, b in zip(k, x))
            def get_key_length(self): return 16
            def get_input_length(self): return 16
            def get_output_length(self): return 16

        from src.enc.cpa_enc import CPA_Enc
        from src.mac.cbc_mac import CBC_MAC
        cpa_fast = CPA_Enc(prf=FastStubPRF())
        mac_fast = CBC_MAC(prf=FastStubPRF())
        cca_fast = CCA_Enc(cpa_enc=cpa_fast, mac=mac_fast)
        adv = ind_cca2_game(cca_fast, num_rounds=100)
        assert adv < 0.2, f"IND-CCA2 advantage too high: {adv}"
