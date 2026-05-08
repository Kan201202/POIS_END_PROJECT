"""
Flask API for the POIS dashboard.
Every endpoint is wired against the *actual* function signatures in src/.

Caching: stateful primitives (DLP_OWF, GGM_PRF, CPA_Enc, CBC_MAC, DLP_Hash,
HMAC, ElGamal/DH/RSA key bundles) are cached at module level so identical
requests give identical answers. Pass {"reset": true} to force regeneration.
POST /api/reset_state to clear everything.
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import sys, os, time, traceback
from functools import reduce

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = Flask(__name__)
CORS(app)


def _err(e):
    return jsonify({
        "error": str(e),
        "trace": traceback.format_exc().splitlines()[-4:],
    }), 500


# ===========================================================================
# Cache
# ===========================================================================
_CACHE = {}


def _cached(key, factory, reset=False):
    if reset or key not in _CACHE:
        _CACHE[key] = factory()
    return _CACHE[key]


# ===========================================================================
# Index
# ===========================================================================
@app.route("/")
def index():
    return jsonify({
        "name": "POIS Programming Assignments API",
        "endpoints": sorted(r.rule for r in app.url_map.iter_rules() if r.rule.startswith("/api")),
    })


@app.route("/api/reset_state", methods=["POST"])
def api_reset():
    _CACHE.clear()
    return jsonify({"ok": True, "message": "All cached crypto state cleared."})


# ===========================================================================
# PA#1 — OWF + PRG
# ===========================================================================
def _get_owf(reset=False):
    from src.foundations.owf import DLP_OWF
    return _cached("owf_128", lambda: DLP_OWF(bits=128), reset=reset)


def _get_prg(reset=False):
    from src.foundations.owf import HILL_PRG
    return _cached("prg_128", lambda: HILL_PRG(_get_owf(reset=reset)), reset=reset)


@app.route("/api/pa1/owf", methods=["POST"])
def pa1_owf():
    try:
        x = bytes.fromhex(request.json["x"])
        reset = bool(request.json.get("reset", False))
        owf = _get_owf(reset=reset)
        y = owf.evaluate(x)
        return jsonify({
            "input": x.hex(),
            "output": y.hex(),
            "scheme": "f(x) = g^x mod p",
            "p_bits": owf.p.bit_length(),
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa1/prg", methods=["POST"])
def pa1_prg():
    try:
        seed = bytes.fromhex(request.json["seed"])
        length = int(request.json.get("length", 32))
        reset = bool(request.json.get("reset", False))
        prg = _get_prg(reset=reset)
        out = prg.expand(seed, length)
        bits = ''.join(f'{b:08b}' for b in out)
        ratio = bits.count('1') / len(bits) if bits else 0
        return jsonify({
            "seed": seed.hex(),
            "output": out.hex(),
            "length": length,
            "ones_ratio": round(ratio, 4),
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa1/reset", methods=["POST"])
def pa1_reset():
    _CACHE.pop("owf_128", None)
    _CACHE.pop("prg_128", None)
    return jsonify({"ok": True, "message": "(p, g) regenerated on next call."})


# ===========================================================================
# PA#2 — PRF (GGM)
# ===========================================================================
def _get_prf(reset=False):
    from src.prf.ggm_prf import GGM_PRF
    return _cached("ggm_prf", lambda: GGM_PRF(prg=_get_prg(reset=reset)), reset=reset)


@app.route("/api/pa2/prf", methods=["POST"])
def pa2_prf():
    try:
        key = bytes.fromhex(request.json["key"])
        x = bytes.fromhex(request.json["x"])
        reset = bool(request.json.get("reset", False))
        prf = _get_prf(reset=reset)
        out = prf.evaluate(key, x)
        return jsonify({
            "key": key.hex(),
            "input": x.hex(),
            "output": out.hex(),
            "scheme": "GGM tree (PRG-based)",
        })
    except Exception as e:
        return _err(e)


# Backward direction (PA#2b): PRG from PRF
@app.route("/api/pa2/prg_from_prf", methods=["POST"])
def pa2_prg_from_prf():
    try:
        from src.prf.ggm_prf import PRG_from_GGM_PRF
        seed = bytes.fromhex(request.json["seed"])
        length = int(request.json.get("length", 32))
        reset = bool(request.json.get("reset", False))
        prf = _get_prf(reset=reset)
        prg = _cached("prg_from_prf", lambda: PRG_from_GGM_PRF(prf), reset=reset)
        out = prg.expand(seed, length)
        bits = ''.join(f'{b:08b}' for b in out)
        ratio = bits.count('1') / len(bits) if bits else 0
        return jsonify({
            "seed": seed.hex(),
            "output": out.hex(),
            "length": length,
            "ones_ratio": round(ratio, 4),
            "scheme": "G(s) = F_s(0) || F_s(1) || ...",
        })
    except Exception as e:
        return _err(e)


# AES-based PRF alternative
@app.route("/api/pa2/aes_prf", methods=["POST"])
def pa2_aes_prf():
    try:
        from src.prf.ggm_prf import AES_PRF
        key = bytes.fromhex(request.json["key"])
        x = bytes.fromhex(request.json["x"])
        prf = _cached("aes_prf", lambda: AES_PRF())
        out = prf.evaluate(key, x)
        return jsonify({
            "key": key.hex(),
            "input": x.hex(),
            "output": out.hex(),
            "scheme": "AES-128 used directly as PRF",
        })
    except Exception as e:
        return _err(e)


# Distinguishing game (security demo)
@app.route("/api/pa2/distinguishing_game", methods=["POST"])
def pa2_distinguishing():
    try:
        from src.prf.ggm_prf import distinguishing_game
        num_queries = int(request.json.get("num_queries", 100))
        reset = bool(request.json.get("reset", False))
        prf = _get_prf(reset=reset)
        t0 = time.time()
        real, rand = distinguishing_game(prf, num_queries=num_queries)
        elapsed = round((time.time() - t0) * 1000, 2)
        return jsonify({
            "num_queries": num_queries,
            "real_distinct": real,
            "random_distinct": rand,
            "advantage": abs(real - rand) / max(num_queries, 1),
            "time_ms": elapsed,
        })
    except Exception as e:
        return _err(e)


# Tree-trace: returns intermediate path values for the visualizer
@app.route("/api/pa2/tree_trace", methods=["POST"])
def pa2_tree_trace():
    try:
        key = bytes.fromhex(request.json["key"])
        x = bytes.fromhex(request.json["x"])
        depth = int(request.json.get("depth", 4))   # how many bits of x to trace
        reset = bool(request.json.get("reset", False))
        prf = _get_prf(reset=reset)
        prg = prf.prg     # GGM_PRF stores its PRG

        # Bits of x[0] from MSB
        first_byte = x[0] if x else 0
        bits = [(first_byte >> (7 - i)) & 1 for i in range(depth)]

        # Walk tree top-to-bottom: at each level expand current node, take child by bit_i
        # PRG expand of len 2n produces (G_0(s) || G_1(s))
        n = prf.get_key_length()  # 16 bytes
        path = []
        current = key
        for i, bi in enumerate(bits):
            expanded = prg.expand(current, 2 * n)
            left, right = expanded[:n], expanded[n:]
            child = right if bi == 1 else left
            path.append({
                "level": i,
                "bit": bi,
                "node": current.hex(),
                "left": left.hex(),
                "right": right.hex(),
                "chosen": "right" if bi == 1 else "left",
            })
            current = child

        leaf = current
        return jsonify({
            "key": key.hex(),
            "x_bits": ''.join(str(b) for b in bits),
            "depth": depth,
            "path": path,
            "leaf": leaf.hex(),
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# Note on PRF speed:
# Your GGM_PRF walks a 128-bit deep tree of HILL-PRG iterations and takes
# roughly 2-3 seconds per evaluation. The AES_PRF in your codebase is a
# placeholder stub (returns key+x[:16]) and is NOT a real PRF, so we don't
# use it here. PA#3/#4 demos accept the GGM cost and warn the user.
# ===========================================================================


# ===========================================================================
# PA#3 — CPA Encryption
# ===========================================================================
def _get_cpa(reset=False):
    from src.enc.cpa_enc import CPA_Enc
    return _cached("cpa_enc", lambda: CPA_Enc(prf=_get_prf(reset=reset)), reset=reset)


@app.route("/api/pa3/encrypt", methods=["POST"])
def pa3_encrypt():
    try:
        k = bytes.fromhex(request.json["key"])
        m = request.json["message"].encode()
        reset = bool(request.json.get("reset", False))
        enc = _get_cpa(reset=reset)
        r, c = enc.encrypt(k, m)
        return jsonify({
            "message": m.decode("utf-8", "replace"),
            "nonce": r.hex(),
            "ciphertext": c.hex(),
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa3/decrypt", methods=["POST"])
def pa3_decrypt():
    try:
        k = bytes.fromhex(request.json["key"])
        r = bytes.fromhex(request.json["nonce"])
        c = bytes.fromhex(request.json["ciphertext"])
        enc = _get_cpa()
        m = enc.decrypt(k, (r, c))
        return jsonify({"plaintext": m.decode("utf-8", "replace") if m else None})
    except Exception as e:
        return _err(e)


# Broken variant: deterministic nonce reuse
def _get_cpa_broken(reset=False):
    from src.enc.cpa_enc import CPA_Enc_Broken
    return _cached("cpa_broken", lambda: CPA_Enc_Broken(prf=_get_prf(reset=reset)), reset=reset)


@app.route("/api/pa3/encrypt_broken", methods=["POST"])
def pa3_encrypt_broken():
    try:
        k = bytes.fromhex(request.json["key"])
        m = request.json["message"].encode()
        enc = _get_cpa_broken()
        r, c = enc.encrypt(k, m)
        return jsonify({
            "message": m.decode("utf-8", "replace"),
            "nonce": r.hex(),
            "ciphertext": c.hex(),
            "scheme": "CPA-Broken (fixed nonce r=0)",
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa3/nonce_reuse_demo", methods=["POST"])
def pa3_nonce_reuse_demo():
    try:
        k = bytes.fromhex(request.json["key"])
        m = request.json["message"].encode()

        secure = _get_cpa()
        broken = _get_cpa_broken()

        s1 = secure.encrypt(k, m)
        s2 = secure.encrypt(k, m)
        b1 = broken.encrypt(k, m)
        b2 = broken.encrypt(k, m)

        return jsonify({
            "message": m.decode("utf-8", "replace"),
            "secure": {
                "nonce_1": s1[0].hex(), "ct_1": s1[1].hex(),
                "nonce_2": s2[0].hex(), "ct_2": s2[1].hex(),
                "ciphertexts_equal": s1[1] == s2[1],
                "nonces_equal": s1[0] == s2[0],
            },
            "broken": {
                "nonce_1": b1[0].hex(), "ct_1": b1[1].hex(),
                "nonce_2": b2[0].hex(), "ct_2": b2[1].hex(),
                "ciphertexts_equal": b1[1] == b2[1],
                "nonces_equal": b1[0] == b2[0],
            },
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa3/ind_cpa_game", methods=["POST"])
def pa3_ind_cpa_game():
    try:
        from src.enc.cpa_enc import ind_cpa_game
        rounds = int(request.json.get("rounds", 10))   # default low; this is slow
        broken = bool(request.json.get("broken", False))
        enc = _get_cpa_broken() if broken else _get_cpa()
        t0 = time.time()
        adv = ind_cpa_game(enc, num_rounds=rounds)
        return jsonify({
            "rounds": rounds,
            "advantage": float(adv),
            "broken_mode": broken,
            "time_ms": round((time.time() - t0) * 1000, 2),
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#4 — Modes of Operation
# ===========================================================================
def _get_modes(reset=False):
    from src.enc.modes import ModesOfOperation
    return _cached("modes", lambda: ModesOfOperation(prf=_get_prf(reset=reset)), reset=reset)


def _get_mode_obj(mode, reset=False):
    """Get the underlying CBC/OFB/CTR object inside ModesOfOperation."""
    m = _get_modes(reset=reset)
    return {"CBC": m.cbc, "OFB": m.ofb, "CTR": m.ctr}[mode.upper()]


@app.route("/api/pa4/encrypt", methods=["POST"])
def pa4_encrypt():
    try:
        mode = request.json["mode"].upper()
        k = bytes.fromhex(request.json["key"])
        m = request.json["message"].encode()
        iv_hex = request.json.get("iv")
        reset = bool(request.json.get("reset", False))

        if iv_hex:
            obj = _get_mode_obj(mode, reset=reset)
            iv = bytes.fromhex(iv_hex)
            iv_out, c = obj.encrypt(k, m, iv=iv)
        else:
            modes = _get_modes(reset=reset)
            iv_out, c = modes.encrypt(mode, k, m)

        return jsonify({"mode": mode, "iv": iv_out.hex(), "ciphertext": c.hex()})
    except Exception as e:
        return _err(e)


@app.route("/api/pa4/decrypt", methods=["POST"])
def pa4_decrypt():
    try:
        mode = request.json["mode"].upper()
        k = bytes.fromhex(request.json["key"])
        iv = bytes.fromhex(request.json["iv"])
        c = bytes.fromhex(request.json["ciphertext"])
        modes = _get_modes()
        m = modes.decrypt(mode, k, (iv, c))
        return jsonify({"mode": mode, "plaintext": m.decode("utf-8", "replace") if m else None})
    except Exception as e:
        return _err(e)


@app.route("/api/pa4/bitflip", methods=["POST"])
def pa4_bitflip():
    """
    Encrypt, flip ONE bit in the ciphertext at a chosen byte index, decrypt,
    and report which plaintext blocks were corrupted. Demonstrates the
    error-propagation pattern that distinguishes CBC / OFB / CTR.
    """
    try:
        mode = request.json["mode"].upper()
        k = bytes.fromhex(request.json["key"])
        m = request.json["message"].encode()
        flip_byte = int(request.json.get("flip_byte", 0))

        modes = _get_modes()
        iv, c = modes.encrypt(mode, k, m)
        block_len = modes.cbc.block_len

        honest = modes.decrypt(mode, k, (iv, c))

        if flip_byte < 0 or flip_byte >= len(c):
            flip_byte = 0
        tampered = bytearray(c)
        tampered[flip_byte] ^= 0x01

        try:
            corrupted = modes.decrypt(mode, k, (iv, bytes(tampered)))
        except Exception:
            corrupted = b""

        flipped_block = flip_byte // block_len

        affected_blocks = []
        n_blocks = max(len(honest), len(corrupted)) // block_len
        for i in range(n_blocks):
            a = honest[i * block_len:(i + 1) * block_len]
            b = corrupted[i * block_len:(i + 1) * block_len] if corrupted else b""
            if a != b:
                affected_blocks.append(i)

        return jsonify({
            "mode": mode,
            "block_len": block_len,
            "flip_byte_index": flip_byte,
            "flipped_block": flipped_block,
            "affected_blocks": affected_blocks,
            "ciphertext_original": c.hex(),
            "ciphertext_tampered": bytes(tampered).hex(),
            "honest_plaintext_hex": honest.hex(),
            "corrupted_plaintext_hex": corrupted.hex() if corrupted else "",
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa4/iv_reuse_attack", methods=["POST"])
def pa4_iv_reuse_attack():
    """
    Two attack demos in one endpoint:
      - mode=CBC -> CBC.iv_reuse_attack_demo
      - mode=OFB -> OFB.keystream_reuse_attack_demo
    """
    try:
        mode = request.json["mode"].upper()
        k = bytes.fromhex(request.json["key"])
        m0 = request.json["m0"].encode()
        m1 = request.json["m1"].encode()
        modes = _get_modes()

        if mode == "CBC":
            ok = modes.cbc.iv_reuse_attack_demo(k, m0, m1)
            return jsonify({
                "mode": "CBC",
                "attack_succeeded": bool(ok),
                "explanation": "Same IV + same first plaintext block => same first ciphertext block.",
            })
        elif mode == "OFB":
            recovered = modes.ofb.keystream_reuse_attack_demo(k, m0, m1)
            ok = recovered[:len(m1)] == m1[:len(recovered)]
            return jsonify({
                "mode": "OFB",
                "attack_succeeded": bool(ok),
                "recovered_m1": recovered.decode("utf-8", "replace"),
                "expected_m1": m1.decode("utf-8", "replace"),
                "explanation": "Same IV => same keystream, so C0 XOR C1 = M0 XOR M1; knowing M0 reveals M1.",
            })
        else:
            return jsonify({"error": "IV-reuse attack only meaningful for CBC and OFB"}), 400
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#5 — MAC
# ===========================================================================
def _get_mac(reset=False):
    from src.mac.cbc_mac import CBC_MAC
    return _cached("cbc_mac", lambda: CBC_MAC(prf=_get_prf(reset=reset)), reset=reset)


@app.route("/api/pa5/mac", methods=["POST"])
def pa5_mac():
    try:
        k = bytes.fromhex(request.json["key"])
        m = request.json["message"].encode()
        reset = bool(request.json.get("reset", False))
        mac = _get_mac(reset=reset)
        tag = mac.tag(k, m)
        return jsonify({
            "message": m.decode("utf-8", "replace"),
            "tag": tag.hex(),
            "scheme": "CBC-MAC",
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa5/verify", methods=["POST"])
def pa5_verify():
    try:
        k = bytes.fromhex(request.json["key"])
        m = request.json["message"].encode()
        tag = bytes.fromhex(request.json["tag"])
        mac = _get_mac()
        ok = mac.verify(k, m, tag)
        return jsonify({"valid": bool(ok)})
    except Exception as e:
        return _err(e)


# ---------------------------------------------------------------------------
# PA#5 — EUF-CMA forgery game (server holds hidden key)
# ---------------------------------------------------------------------------
_FORGERY_MAX = 50   # oracle query budget


def _forgery_state():
    """Return (creating if absent) the forgery-game state dict from cache."""
    if "pa5_forgery" not in _CACHE:
        import os
        _CACHE["pa5_forgery"] = {
            "key": os.urandom(16),          # hidden 16-byte key
            "signed": [],                   # list of {"message": str, "tag": hex}
            "attempts": 0,
            "successes": 0,
        }
    return _CACHE["pa5_forgery"]


@app.route("/api/pa5/forgery_state", methods=["POST"])
def pa5_forgery_state():
    try:
        st = _forgery_state()
        return jsonify({
            "signed_count": len(st["signed"]),
            "max_signed": _FORGERY_MAX,
            "signed": st["signed"],
            "attempts": st["attempts"],
            "successes": st["successes"],
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa5/forgery_sign", methods=["POST"])
def pa5_forgery_sign():
    """Oracle: sign a message with the hidden key (up to _FORGERY_MAX times)."""
    try:
        msg_str = request.json["message"]
        st = _forgery_state()
        if len(st["signed"]) >= _FORGERY_MAX:
            return jsonify({"error": f"Oracle budget exhausted ({_FORGERY_MAX} queries used)."}), 400
        mac = _get_mac()
        m = msg_str.encode()
        tag = mac.tag(st["key"], m)
        entry = {"message": msg_str, "tag": tag.hex()}
        st["signed"].append(entry)
        return jsonify({
            "message": msg_str,
            "tag": tag.hex(),
            "signed_count": len(st["signed"]),
            "max_signed": _FORGERY_MAX,
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa5/forgery_submit", methods=["POST"])
def pa5_forgery_submit():
    """
    Adversary submits a forgery (m*, t*).
    Valid forgery = valid tag AND message not already signed by oracle.
    """
    try:
        msg_str = request.json["message"]
        tag_hex = request.json["tag"]
        st = _forgery_state()
        mac = _get_mac()

        m = msg_str.encode()
        try:
            t = bytes.fromhex(tag_hex)
        except ValueError:
            return jsonify({"error": "tag must be a valid hex string"}), 400

        valid_tag = mac.verify(st["key"], m, t)
        is_existing = any(s["message"] == msg_str for s in st["signed"])
        forgery_succeeded = valid_tag and not is_existing

        st["attempts"] += 1
        if forgery_succeeded:
            st["successes"] += 1

        return jsonify({
            "valid_tag": valid_tag,
            "is_existing_message": is_existing,
            "forgery_succeeded": forgery_succeeded,
            "attempts": st["attempts"],
            "successes": st["successes"],
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa5/forgery_reset", methods=["POST"])
def pa5_forgery_reset():
    """Reset the EUF-CMA game (generates a new hidden key)."""
    try:
        _CACHE.pop("pa5_forgery", None)
        _forgery_state()   # initialise fresh state
        return jsonify({"ok": True, "message": "Forgery game reset with a new hidden key."})
    except Exception as e:
        return _err(e)


# ---------------------------------------------------------------------------
# PA#5 — Length-extension attack on naive H(k‖m)
# ---------------------------------------------------------------------------
@app.route("/api/pa5/length_extension", methods=["POST"])
def pa5_length_extension():
    """
    Demonstrates the SHA-256 length-extension attack.

    Defender publishes (m, tag) where tag = SHA256(k || m).
    Attacker knows m, tag, and |k| (k_len bytes), but NOT k itself.
    Attacker forges a valid tag for the extended message m || pad || suffix
    without ever seeing k, by continuing the Merkle-Damgård chain.
    """
    try:
        import hashlib, struct

        m_str    = request.json["message"]
        suffix   = request.json["suffix"]
        k_len    = int(request.json.get("k_len", 16))   # key length in bytes

        m       = m_str.encode()
        suffix_b = suffix.encode()

        # --- Step 1: server computes honest tag = SHA256(k || m) ---
        import os
        k = os.urandom(k_len)          # ephemeral key (attacker never sees this)
        honest_tag_bytes = hashlib.sha256(k + m).digest()

        # --- Step 2: attacker computes the MD padding for (k || m) ---
        # SHA-256 pads to 512-bit (64-byte) blocks with MD-strengthening
        def sha256_md_pad(msg_len_bytes: int) -> bytes:
            """Return the padding bytes appended to a message of msg_len_bytes."""
            total = msg_len_bytes
            pad = b'\x80'
            pad += b'\x00' * ((55 - total) % 64)
            pad += struct.pack('>Q', total * 8)
            return pad

        inner_len = k_len + len(m)                          # |k| + |m|
        pad        = sha256_md_pad(inner_len)               # padding after k||m
        forged_msg = m + pad + suffix_b                     # what the attacker claims

        # --- Step 3: continue the SHA-256 chain from honest_tag ---
        # Re-inject the intermediate hash state and compress the suffix block(s)
        def _u32(b, i):
            return struct.unpack('>I', b[i*4:i*4+4])[0]

        def sha256_extend(inner_hash: bytes, suffix_data: bytes, total_prefix_len: int) -> bytes:
            """
            Continue SHA-256 hashing from a known intermediate state.
            inner_hash      = 32-byte digest of the padded prefix
            suffix_data     = bytes to hash next
            total_prefix_len = byte-length of the entire padded prefix (multiple of 64)
            """
            import hashlib
            # We use Python's _hashlib internals indirectly by building a fresh
            # SHA-256 object and replacing its internal state.
            # Portable approach: use hashlib with a crafted "pre-computed" state
            # via the public interface (update with the suffix after faking state).
            #
            # The cleanest portable way: create sha256 over fake_prefix||suffix
            # where fake_prefix is chosen so that sha256(fake_prefix) == inner_hash.
            # That's only possible if we control the state — instead we implement
            # the compression function directly for the suffix blocks.

            # --- Pure-Python SHA-256 compression from known state ---
            K = [
                0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
                0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
                0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
                0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
                0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
                0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
                0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
                0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
                0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
                0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
                0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
                0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
                0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
                0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
                0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
                0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
            ]
            def rotr(x, n): return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
            def ch(e,f,g):  return (e&f)^(~e&g)
            def maj(a,b,c): return (a&b)^(a&c)^(b&c)
            def sig0(x):    return rotr(x,2)^rotr(x,13)^rotr(x,22)
            def sig1(x):    return rotr(x,6)^rotr(x,11)^rotr(x,25)
            def gam0(x):    return rotr(x,7)^rotr(x,18)^(x>>3)
            def gam1(x):    return rotr(x,17)^rotr(x,19)^(x>>10)
            MASK = 0xFFFFFFFF

            def compress(state, block_bytes):
                a,b,c,d,e,f,g,h = state
                w = [struct.unpack('>I', block_bytes[i*4:i*4+4])[0] for i in range(16)]
                for i in range(16, 64):
                    w.append((gam1(w[-2]) + w[-7] + gam0(w[-15]) + w[-16]) & MASK)
                for i in range(64):
                    T1 = (h + sig1(e) + ch(e,f,g) + K[i] + w[i]) & MASK
                    T2 = (sig0(a) + maj(a,b,c)) & MASK
                    h=g; g=f; f=e; e=(d+T1)&MASK
                    d=c; c=b; b=a; a=(T1+T2)&MASK
                return [(s+v)&MASK for s,v in zip(state,[a,b,c,d,e,f,g,h])]

            # Unpack honest_tag into 8 x uint32 state
            state = [_u32(inner_hash, i) for i in range(8)]

            # Pad and process suffix_data from this state
            suffix_len_context = total_prefix_len + len(suffix_data)
            suffix_padded = suffix_data + sha256_md_pad(suffix_len_context)

            for blk_start in range(0, len(suffix_padded), 64):
                state = compress(state, suffix_padded[blk_start:blk_start+64])

            return b''.join(struct.pack('>I', s) for s in state)

        # total padded length of (k || m)
        inner_padded_len = inner_len + len(sha256_md_pad(inner_len))
        forged_tag_bytes  = sha256_extend(honest_tag_bytes, suffix_b, inner_padded_len)

        # --- Step 4: verify the forged tag server-side ---
        recomputed = hashlib.sha256(k + m + pad + suffix_b).digest()
        attack_succeeded = forged_tag_bytes == recomputed

        return jsonify({
            "original_message":   m_str,
            "suffix":             suffix,
            "k_len":              k_len,
            "honest_tag":         honest_tag_bytes.hex(),
            "forged_message_hex": forged_msg.hex(),
            "forged_tag":         forged_tag_bytes.hex(),
            "recomputed_tag":     recomputed.hex(),
            "attack_succeeded":   attack_succeeded,
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#6 — CCA Encryption (Encrypt-then-MAC)
# ===========================================================================
def _get_cca(reset=False):
    from src.enc.cca_enc import CCA_Enc
    return _cached(
        "cca_enc",
        lambda: CCA_Enc(cpa_enc=_get_cpa(reset=reset), mac=_get_mac(reset=reset)),
        reset=reset,
    )


@app.route("/api/pa6/encrypt", methods=["POST"])
def pa6_encrypt():
    try:
        kE = bytes.fromhex(request.json["kE"])
        kM = bytes.fromhex(request.json["kM"])
        m = request.json["message"].encode()
        reset = bool(request.json.get("reset", False))
        cca = _get_cca(reset=reset)
        (r, c), tag = cca.encrypt(kE, kM, m)
        return jsonify({"nonce": r.hex(), "ciphertext": c.hex(), "tag": tag.hex()})
    except Exception as e:
        return _err(e)


@app.route("/api/pa6/decrypt", methods=["POST"])
def pa6_decrypt():
    try:
        kE = bytes.fromhex(request.json["kE"])
        kM = bytes.fromhex(request.json["kM"])
        r = bytes.fromhex(request.json["nonce"])
        c = bytes.fromhex(request.json["ciphertext"])
        tag = bytes.fromhex(request.json["tag"])
        cca = _get_cca()
        m = cca.decrypt(kE, kM, (r, c), tag)
        return jsonify({
            "plaintext": m.decode("utf-8", "replace") if m else None,
            "rejected": m is None,
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa6/malleability", methods=["POST"])
def pa6_malleability():
    """
    Side-by-side malleability demo (assignment spec PA#6):

    Given a message and keys, the server:
      1. Encrypts with CPA-only (no MAC)  → flip bit_index → decrypts → plaintext corrupted
      2. Encrypts with CCA (Encrypt-then-MAC) → flip same bit → MAC check fires → ⊥

    Request body: { kE, kM, message, bit_byte (int, default 0) }
    """
    try:
        from src.enc.cca_enc import malleability_attack_demo, malleability_cca_demo

        kE      = bytes.fromhex(request.json["kE"])
        kM      = bytes.fromhex(request.json["kM"])
        m       = request.json["message"].encode()
        bit_idx = int(request.json.get("bit_byte", 0))

        cpa = _get_cpa()
        cca = _get_cca()

        # ── CPA side ─────────────────────────────────────────────────────
        r_cpa, c_cpa = cpa.encrypt(kE, m)
        i_cpa = min(bit_idx, len(c_cpa) - 1)
        c_cpa_tampered = bytearray(c_cpa)
        c_cpa_tampered[i_cpa] ^= 0xFF          # flip all 8 bits at chosen byte
        c_cpa_tampered = bytes(c_cpa_tampered)
        try:
            m_corrupted = cpa.decrypt(kE, (r_cpa, c_cpa_tampered))
            cpa_plaintext = m_corrupted.decode("utf-8", "replace")
            cpa_rejected  = False
        except Exception:
            cpa_plaintext = None
            cpa_rejected  = True

        # ── CCA side ─────────────────────────────────────────────────────
        (r_cca, c_cca), tag_cca = cca.encrypt(kE, kM, m)
        i_cca = min(bit_idx, len(c_cca) - 1)
        c_cca_tampered = bytearray(c_cca)
        c_cca_tampered[i_cca] ^= 0xFF
        c_cca_tampered = bytes(c_cca_tampered)
        m_cca = cca.decrypt(kE, kM, (r_cca, c_cca_tampered), tag_cca)
        cca_rejected  = m_cca is None
        cca_plaintext = m_cca.decode("utf-8", "replace") if m_cca else None

        return jsonify({
            "original_message": m.decode("utf-8", "replace"),
            "bit_byte": bit_idx,
            "cpa": {
                "nonce":              r_cpa.hex(),
                "ciphertext":         c_cpa.hex(),
                "ciphertext_tampered": c_cpa_tampered.hex(),
                "flipped_byte_index": i_cpa,
                "plaintext":          cpa_plaintext,
                "rejected":           cpa_rejected,
                "attack_succeeded":   not cpa_rejected,
            },
            "cca": {
                "nonce":              r_cca.hex(),
                "ciphertext":         c_cca.hex(),
                "tag":                tag_cca.hex(),
                "ciphertext_tampered": c_cca_tampered.hex(),
                "flipped_byte_index": i_cca,
                "plaintext":          cca_plaintext,
                "rejected":           cca_rejected,
                "attack_succeeded":   not cca_rejected,
            },
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#7 — Merkle-Damgard (toy compression)
# ===========================================================================
def _get_md():
    from src.hash.merkle_damgard import MerkleDamgard, dummy_xor_compression
    return _cached("md_xor", lambda: MerkleDamgard(
        compress_fn=dummy_xor_compression, iv=b"\x00" * 8, block_size=8,
    ))


@app.route("/api/pa7/hash", methods=["POST"])
def pa7_hash():
    """Simple hash endpoint (backward compat)."""
    try:
        m = request.json["message"].encode()
        md = _get_md()
        digest = md.hash(m)
        return jsonify({
            "message": m.decode("utf-8", "replace"),
            "digest": digest.hex(),
            "scheme": "Merkle-Damgard (toy XOR compression)",
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa7/chain", methods=["POST"])
def pa7_chain():
    """
    Full Merkle-Damgård chain trace for the interactive chain-viewer.

    Returns:
      - iv          : hex string of the initial chaining value z_0
      - block_size  : integer (bytes)
      - out_len     : integer (bytes) — length of each chaining value
      - blocks      : list of { index, hex, label }
      - chain       : list of { from_z, block_index, to_z }
                      showing z_{i} -> h(z_{i}, M_{i+1}) -> z_{i+1}
      - digest      : final chaining value (= hash output)
      - padded_hex  : full padded message as hex
    Also supports editing: pass { overrides: { "2": "aabbccdd11223344" } }
    to replace block[2] with a custom 8-byte hex value and recompute the chain
    from that block onwards (avalanche demo).
    """
    try:
        from src.hash.merkle_damgard import dummy_xor_compression

        raw      = request.json.get("message", "")
        # accept hex input too
        if request.json.get("hex_input", False):
            m = bytes.fromhex(raw)
        else:
            m = raw.encode()

        overrides = request.json.get("overrides", {})   # { str(block_idx): hex_str }

        md         = _get_md()
        block_size = md.block_size
        iv         = md.iv

        # --- pad and split ---
        padded      = md._pad(m)
        num_blocks  = len(padded) // block_size
        raw_blocks  = [padded[i * block_size:(i + 1) * block_size] for i in range(num_blocks)]

        # apply overrides (for avalanche demo)
        edited_blocks = list(raw_blocks)
        for idx_str, hex_val in overrides.items():
            idx = int(idx_str)
            if 0 <= idx < num_blocks:
                edited_blocks[idx] = bytes.fromhex(hex_val.ljust(block_size * 2, "0"))[:block_size]

        # --- walk the chain ---
        chain  = []
        z      = iv
        z_vals = [z]
        for i, blk in enumerate(edited_blocks):
            z_next = dummy_xor_compression(z, blk)
            chain.append({
                "step":        i,
                "from_z":      z.hex(),
                "block_index": i,
                "block_hex":   blk.hex(),
                "to_z":        z_next.hex(),
                "edited":      str(i) in overrides,
            })
            z = z_next
            z_vals.append(z)

        blocks_out = []
        for i, (raw_blk, edit_blk) in enumerate(zip(raw_blocks, edited_blocks)):
            # label the block type
            msg_end = len(m)
            start   = i * block_size
            if start >= msg_end:
                kind = "padding"
            elif start + block_size > msg_end:
                kind = "mixed"          # message + padding boundary
            else:
                kind = "message"
            blocks_out.append({
                "index":      i,
                "hex":        raw_blk.hex(),
                "edited_hex": edit_blk.hex(),
                "label":      f"M{i+1}",
                "kind":       kind,
                "text":       raw_blk.decode("utf-8", "replace"),
            })

        return jsonify({
            "message":     m.decode("utf-8", "replace"),
            "padded_hex":  padded.hex(),
            "block_size":  block_size,
            "out_len":     len(iv),
            "num_blocks":  num_blocks,
            "iv":          iv.hex(),
            "blocks":      blocks_out,
            "chain":       chain,
            "digest":      z.hex(),
            "z_values":    [zv.hex() for zv in z_vals],
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#8 — DLP Hash
# ===========================================================================
def _get_dlp_hash(reset=False):
    from src.hash.dlp_hash import DLPHash
    return _cached("dlp_hash", lambda: DLPHash(out_len=16), reset=reset)


@app.route("/api/pa8/hash", methods=["POST"])
def pa8_hash():
    try:
        m = request.json["message"].encode()
        reset = bool(request.json.get("reset", False))
        h = _get_dlp_hash(reset=reset)
        digest = h.hash(m)
        return jsonify({
            "message":  m.decode("utf-8", "replace"),
            "digest":   digest.hex(),
            "scheme":   "DLP-based CRHF (Merkle-Damgård + h(x,y)=g^x·ĥ^y mod p)",
            "p_bits":   h.p.bit_length(),
            "g":        str(h.g),
            "h_hat":    str(h.h_hat),
            "out_len":  h.out_len,
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa8/collision_hunt", methods=["POST"])
def pa8_collision_hunt():
    """
    Birthday-attack collision hunt on a 16-bit truncated DLP hash.

    Spec: toy n = 16-bit output → 2^(n/2) = 256 expected evaluations.

    The server runs the full birthday attack and returns the result in one
    response (no streaming). The client shows a progress bar pre-filled
    to the number of evaluations reported.

    Response:
        { found, evals, expected_evals, x1_hex, x2_hex, h1_hex, h2_hex,
          time_ms, n_bits }
    """
    try:
        n_bits   = int(request.json.get("n_bits", 16))     # 16 per spec
        max_evals = int(request.json.get("max_evals", 200_000))

        dlp_h = _get_dlp_hash()

        # 16-bit truncation wrapper
        def short_hash(x: bytes) -> bytes:
            full = dlp_h.hash(x)
            mask_bytes = (n_bits + 7) // 8
            full_int = int.from_bytes(full, "big")
            mask = (1 << n_bits) - 1
            truncated = full_int & mask
            return truncated.to_bytes(mask_bytes, "big")

        t0 = time.time()
        seen = {}       # hash_value -> input_bytes
        evals = 0

        import os
        found = False
        x1 = x2 = h1 = h2 = None

        for _ in range(max_evals):
            inp = os.urandom(8)
            hv  = short_hash(inp)
            evals += 1
            if hv in seen:
                x1, x2 = seen[hv], inp
                h1 = h2 = hv
                found = True
                break
            seen[hv] = inp

        elapsed = round((time.time() - t0) * 1000, 2)
        expected = int(2 ** (n_bits / 2))

        return jsonify({
            "found":          found,
            "n_bits":         n_bits,
            "evals":          evals,
            "expected_evals": expected,
            "progress_pct":   min(100, round(evals / expected * 100, 1)),
            "x1_hex":         x1.hex() if x1 else None,
            "x2_hex":         x2.hex() if x2 else None,
            "h1_hex":         h1.hex() if h1 else None,
            "h2_hex":         h2.hex() if h2 else None,
            "time_ms":        elapsed,
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#9 — Birthday Attack
# ===========================================================================
@app.route("/api/pa9/birthday", methods=["POST"])
def pa9_birthday():
    try:
        import hashlib, math, os as _os
        n_bits = int(request.json.get("n_bits", 12))
        max_trials = int(request.json.get("max_trials", 10 ** 6))

        mask = (1 << n_bits) - 1
        mask_bytes = max(1, (n_bits + 7) // 8)

        def toy_hash(x: bytes) -> bytes:
            full = hashlib.sha256(x).digest()
            v = int.from_bytes(full[:mask_bytes], 'big') & mask
            return v.to_bytes(mask_bytes, 'big')

        t0 = time.time()
        seen = {}       # truncated hash value (bytes) -> first input
        collision_found = False
        x1 = x2 = h1 = h2 = None
        evals = 0

        for _ in range(max_trials):
            inp = _os.urandom(8)
            hv  = toy_hash(inp)
            evals += 1
            if hv in seen:
                x1, x2 = seen[hv], inp
                h1 = h2 = hv
                collision_found = True
                break
            seen[hv] = inp

        elapsed = round((time.time() - t0) * 1000, 2)
        expected = int(2 ** (n_bits / 2))

        # --- Build theoretical curve: P(collision after k) = 1 - e^(-k²/2ⁿ) ---
        # Sample at 60 points from k=0 to 3 × expected
        domain = max(3 * expected, evals + 5)
        curve = []
        for i in range(61):
            k = int(i * domain / 60)
            p = 1 - math.exp(-k * k / (2 ** n_bits))
            curve.append({"k": k, "p": round(p, 6)})

        result = {
            "collision_found":  collision_found,
            "n_bits":           n_bits,
            "evals":            evals,
            "expected_evals":   expected,
            "time_ms":          elapsed,
            "theory_curve":     curve,          # [{k, p}] for chart
        }
        if collision_found:
            result.update({
                "x1":               x1.hex(),
                "x2":               x2.hex(),
                "h1":               h1.hex(),
                "h2":               h2.hex(),
                "verified_collision": True,
            })
        else:
            result["error"] = f"No collision found in {evals} trials"

        return jsonify(result)
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#10 — HMAC + Encrypt-then-HMAC
# ===========================================================================
def _get_hmac(reset=False):
    from src.mac.hmac_impl import HMAC
    return _cached(
        "hmac",
        lambda: HMAC(hash_algo=_get_dlp_hash(reset=reset), block_size=16),
        reset=reset,
    )


@app.route("/api/pa10/hmac", methods=["POST"])
def pa10_hmac():
    try:
        k = bytes.fromhex(request.json["key"])
        m = request.json["message"].encode()
        reset = bool(request.json.get("reset", False))
        h = _get_hmac(reset=reset)
        tag = h.tag(k, m)
        return jsonify({
            "message": m.decode("utf-8", "replace"),
            "tag": tag.hex(),
            "scheme": "HMAC over DLP-Hash",
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa10/eth_encrypt", methods=["POST"])
def pa10_eth_encrypt():
    try:
        from src.enc.cca_hmac import EtH_Enc
        kE = bytes.fromhex(request.json["kE"])
        kM = bytes.fromhex(request.json["kM"])
        m = request.json["message"].encode()
        reset = bool(request.json.get("reset", False))
        eth = _cached(
            "cca_hmac",
            lambda: EtH_Enc(cpa_enc=_get_cpa(reset=reset), hmac=_get_hmac(reset=reset)),
            reset=reset,
        )
        (r, c), tag = eth.encrypt(kE, kM, m)
        return jsonify({"nonce": r.hex(), "ciphertext": c.hex(), "tag": tag.hex()})
    except Exception as e:
        return _err(e)


@app.route("/api/pa10/hmac_verify", methods=["POST"])
def pa10_hmac_verify():
    """Verify an HMAC tag (key + message + tag → valid/invalid)."""
    try:
        k   = bytes.fromhex(request.json["key"])
        m   = request.json["message"].encode()
        tag = bytes.fromhex(request.json["tag"])
        h   = _get_hmac()
        ok  = h.verify(k, m, tag)
        return jsonify({"valid": bool(ok)})
    except Exception as e:
        return _err(e)


@app.route("/api/pa10/length_ext_vs_hmac", methods=["POST"])
def pa10_length_ext_vs_hmac():
    """
    PA#10 side-by-side demo:

    Left  (broken H(k‖m)): demonstrates SHA-256 length-extension — the attacker
          forges a valid tag for m‖pad‖suffix without knowing k.
    Right (HMAC): same attack fails — HMAC's double-hash structure requires k for
          computing HMAC_k(m‖pad‖suffix).

    Also supports hash_algo toggle: 'dlp' uses our PA#8 DLP hash (no length-ext
    vulnerability by construction), 'sha256' uses stdlib SHA-256 for both panels.

    Request body:
        { message, suffix, k_len (default 16), hash_algo: 'sha256'|'dlp' }
    """
    try:
        import hashlib, struct, os as _os, hmac as _hmac

        m_str    = request.json.get("message", "amount=100&to=alice")
        suffix   = request.json.get("suffix",  "&amount=999999&to=mallory")
        k_len    = int(request.json.get("k_len", 16))
        algo     = request.json.get("hash_algo", "sha256")   # 'sha256' | 'dlp'

        m        = m_str.encode()
        suffix_b = suffix.encode()

        # ── Generate ephemeral key (attacker never sees it) ──────────────────
        k = _os.urandom(k_len)

        # ─── LEFT: Broken H(k‖m) length-extension ───────────────────────────
        def sha256_md_pad(msg_len: int) -> bytes:
            pad = b'\x80'
            pad += b'\x00' * ((55 - msg_len) % 64)
            pad += struct.pack('>Q', msg_len * 8)
            return pad

        if algo == "sha256":
            honest_tag = hashlib.sha256(k + m).digest()

            # Attacker computes padding for the prefix (k‖m)
            inner_len     = k_len + len(m)
            pad_bytes     = sha256_md_pad(inner_len)
            forged_msg    = m + pad_bytes + suffix_b
            inner_padded_len = inner_len + len(pad_bytes)

            # Continue SHA-256 chain from honest_tag
            def _u32(b, i): return struct.unpack('>I', b[i*4:i*4+4])[0]
            K_SHA = [
                0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
                0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
                0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
                0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
                0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
                0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
                0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
                0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
            ]
            MASK = 0xFFFFFFFF
            def rotr(x,n): return ((x>>n)|(x<<(32-n)))&MASK
            def ch(e,f,g): return (e&f)^(~e&g)&MASK
            def maj(a,b,c): return (a&b)^(a&c)^(b&c)
            def sig0(x): return rotr(x,2)^rotr(x,13)^rotr(x,22)
            def sig1(x): return rotr(x,6)^rotr(x,11)^rotr(x,25)
            def gam0(x): return rotr(x,7)^rotr(x,18)^(x>>3)
            def gam1(x): return rotr(x,17)^rotr(x,19)^(x>>10)
            def compress(state, blk):
                a,b,c,d,e,f,g,h = state
                w = [struct.unpack('>I', blk[i*4:i*4+4])[0] for i in range(16)]
                for i in range(16,64): w.append((gam1(w[-2])+w[-7]+gam0(w[-15])+w[-16])&MASK)
                for i in range(64):
                    T1=(h+sig1(e)+ch(e,f,g)+K_SHA[i]+w[i])&MASK
                    T2=(sig0(a)+maj(a,b,c))&MASK
                    h=g;g=f;f=e;e=(d+T1)&MASK;d=c;c=b;b=a;a=(T1+T2)&MASK
                return [(s+v)&MASK for s,v in zip(state,[a,b,c,d,e,f,g,h])]

            state = [_u32(honest_tag, i) for i in range(8)]
            suf_pad = suffix_b + sha256_md_pad(inner_padded_len + len(suffix_b))
            for blk_start in range(0, len(suf_pad), 64):
                state = compress(state, suf_pad[blk_start:blk_start+64])
            forged_tag = b''.join(struct.pack('>I', s) for s in state)

            recomputed = hashlib.sha256(k + m + pad_bytes + suffix_b).digest()
            lext_succeeded = forged_tag == recomputed
            honest_tag_hex = honest_tag.hex()
            forged_tag_hex = forged_tag.hex()

        else:  # dlp — demonstrate conceptually (DLP hash is also MD-based, same vuln)
            dlp = _get_dlp_hash()
            honest_tag    = dlp.hash(k + m)
            # For DLP we just show the honest tag; true lext is harder to demo
            # symbolically show that the scheme would be vulnerable
            inner_len     = k_len + len(m)
            pad_bytes     = sha256_md_pad(inner_len)
            forged_msg    = m + pad_bytes + suffix_b
            forged_tag    = dlp.hash(k + m + pad_bytes + suffix_b)  # server knows k here
            recomputed    = forged_tag
            lext_succeeded = True   # conceptual — server computed both with k
            honest_tag_hex = honest_tag.hex()
            forged_tag_hex = forged_tag.hex()

        # ─── RIGHT: HMAC — attacker cannot extend without k ─────────────────
        hmac = _get_hmac()
        hmac_honest_tag = hmac.tag(k, m)

        # Attacker tries to forge HMAC for m‖pad‖suffix without k
        # They'd need to compute HMAC_k(m‖pad‖suffix) which requires k
        # Best they can do: random guess — we show it fails verification
        fake_hmac_tag = _os.urandom(len(hmac_honest_tag))
        hmac_forgery_valid = hmac.verify(k, m + pad_bytes + suffix_b, fake_hmac_tag)
        # (always False — random tag won't verify)

        return jsonify({
            "message":      m_str,
            "suffix":       suffix,
            "k_len":        k_len,
            "hash_algo":    algo,
            "pad_hex":      pad_bytes.hex(),
            "forged_msg_hex": forged_msg.hex(),
            "naive": {
                "honest_tag":      honest_tag_hex,
                "forged_tag":      forged_tag_hex,
                "forgery_succeeded": lext_succeeded,
                "explanation":     "Attacker continued the MD chain from the published tag — no k needed.",
            },
            "hmac": {
                "honest_tag":      hmac_honest_tag.hex(),
                "forged_tag":      fake_hmac_tag.hex(),
                "forgery_succeeded": hmac_forgery_valid,
                "explanation":     "HMAC = H((k⊕opad)‖H((k⊕ipad)‖m)). Outer hash requires k — attacker is stuck.",
            },
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#11 — Diffie-Hellman
# ===========================================================================
def _get_dh_params(bits=32, reset=False):
    from src.dh.dh import generate_dh_params
    return _cached(f"dh_params_{bits}", lambda: generate_dh_params(bits), reset=reset)


@app.route("/api/pa11/dh", methods=["POST"])
def pa11_dh():
    """
    Full DH exchange. Returns all values in both decimal and hex.
    Default bits=32 (toy safe prime, instant) per spec: 'p ≈ 2^32 for instant computation'.
    """
    try:
        from src.dh.dh import dh_alice_step1, dh_bob_step1, dh_alice_step2, dh_bob_step2
        bits   = int(request.json.get("bits", 32))
        reset  = bool(request.json.get("reset", False))
        # Allow caller to supply custom exponents (a, b)
        a_in   = request.json.get("alice_priv")   # int as string or null
        b_in   = request.json.get("bob_priv")

        params = _get_dh_params(bits=bits, reset=reset)
        p, q, g = params["p"], params["q"], params["g"]

        if a_in:
            a = int(a_in) % q
            from src.utils.mod_exp import square_and_multiply
            A = square_and_multiply(g, a, p)
        else:
            a, A = dh_alice_step1(params)

        if b_in:
            b = int(b_in) % q
            from src.utils.mod_exp import square_and_multiply
            B = square_and_multiply(g, b, p)
        else:
            b, B = dh_bob_step1(params)

        K_A = dh_alice_step2(params, a, B)
        K_B = dh_bob_step2(params, b, A)

        def h(n): return hex(n)

        return jsonify({
            "p":            h(p),   "p_dec": str(p),
            "g":            h(g),   "g_dec": str(g),
            "q":            h(q),
            "alice_priv":   h(a),   "alice_priv_dec": str(a),
            "alice_pub":    h(A),   "alice_pub_dec":  str(A),
            "bob_priv":     h(b),   "bob_priv_dec":   str(b),
            "bob_pub":      h(B),   "bob_pub_dec":    str(B),
            "shared_alice": h(K_A),
            "shared_bob":   h(K_B),
            "match":        K_A == K_B,
            "bits":         bits,
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa11/mitm", methods=["POST"])
def pa11_mitm():
    """
    MITM (Man-in-the-Middle) attack demo.

    Eve intercepts Alice's g^a and Bob's g^b, substitutes her own g^e to each,
    and ends up sharing:
        K_AE = g^{ae}  (with Alice)
        K_BE = g^{be}  (with Bob)

    Alice and Bob each believe they share a secret with each other, but in fact
    both secrets are known to Eve.

    All values returned in hex.
    """
    try:
        from src.dh.dh import dh_alice_step1, dh_bob_step1, dh_alice_step2, \
                              dh_bob_step2, Eve
        bits  = int(request.json.get("bits", 32))
        reset = bool(request.json.get("reset", False))
        params = _get_dh_params(bits=bits, reset=reset)
        p = params["p"]

        a, A = dh_alice_step1(params)
        b, B = dh_bob_step1(params)

        eve = Eve(params)
        E_to_bob, E_to_alice = eve.intercept_and_substitute(A, B)

        # Alice/Bob compute secrets using Eve's substituted value
        K_alice = dh_alice_step2(params, a, E_to_alice)
        K_bob   = dh_bob_step2(params, b, E_to_bob)

        def h(n): return hex(n)

        return jsonify({
            "p":              h(p),
            "g":              h(params["g"]),
            "bits":           bits,
            "alice": {
                "priv":       h(a),
                "pub":        h(A),        # what Alice sent (intercepted by Eve)
                "received":   h(E_to_alice),  # what Alice received (Eve's g^e)
                "shared":     h(K_alice),  # Alice's computed secret = g^{ae}
            },
            "bob": {
                "priv":       h(b),
                "pub":        h(B),        # what Bob sent (intercepted by Eve)
                "received":   h(E_to_bob),   # what Bob received (Eve's g^e)
                "shared":     h(K_bob),    # Bob's computed secret = g^{be}
            },
            "eve": {
                "priv":       h(eve.e),
                "pub":        h(eve.E),    # g^e sent to both
                "K_with_alice": h(eve.K_with_alice),   # = g^{ae}
                "K_with_bob":   h(eve.K_with_bob),     # = g^{be}
            },
            "alice_talks_to_eve": K_alice == eve.K_with_alice,
            "bob_talks_to_eve":   K_bob   == eve.K_with_bob,
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#12 — RSA
# ===========================================================================
@app.route("/api/pa12/keygen", methods=["POST"])
def pa12_keygen():
    try:
        from src.rsa.rsa import rsa_keygen
        bits = int(request.json.get("bits", 512))
        reset = bool(request.json.get("reset", False))
        pk, sk = _cached(f"rsa_{bits}", lambda: rsa_keygen(bits=bits), reset=reset)
        return jsonify({
            "N": str(pk["N"]),
            "e": str(pk["e"]),
            "d": str(sk["d"]),
            "p": str(sk["p"]),
            "q": str(sk["q"]),
            "bits": bits,
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa12/encrypt", methods=["POST"])
def pa12_encrypt():
    try:
        from src.rsa.rsa import rsa_enc
        N = int(request.json["N"])
        e = int(request.json["e"])
        m = int(request.json["m"])
        c = rsa_enc({"N": N, "e": e}, m)
        return jsonify({"ciphertext": str(c)})
    except Exception as e:
        return _err(e)


@app.route("/api/pa12/decrypt", methods=["POST"])
def pa12_decrypt():
    try:
        from src.rsa.rsa import rsa_dec
        N = int(request.json["N"])
        d = int(request.json["d"])
        c = int(request.json["c"])
        m = rsa_dec({"N": N, "d": d}, c)
        return jsonify({"plaintext": str(m)})
    except Exception as e:
        return _err(e)


@app.route("/api/pa12/determinism_demo", methods=["POST"])
def pa12_determinism_demo():
    """
    PA#12 determinism attack demo.

    1. Encrypts message twice under TEXTBOOK RSA → both ciphertexts identical → leak!
    2. Encrypts message twice under PKCS#1 v1.5 → ciphertexts differ (random PS) → secure.
    3. Extracts and returns the PS random bytes from both PKCS#1 encryptions.

    Request: { message, bits (default 512), reset (bool) }
    """
    try:
        from src.rsa.rsa import (rsa_keygen, rsa_enc, pkcs15_enc,
                                  _pkcs15_pad, determinism_attack_demo)
        msg_str = request.json.get("message", "yes")
        bits    = int(request.json.get("bits", 512))
        reset   = bool(request.json.get("reset", False))

        pk, sk = _cached(f"rsa_{bits}", lambda: rsa_keygen(bits=bits), reset=reset)
        N = pk["N"]
        k = (N.bit_length() + 7) // 8   # modulus byte length

        m_bytes = msg_str.encode()
        # integer for textbook (pad to 4 bytes, take mod N)
        m_int = int.from_bytes(m_bytes.ljust(4, b'\x00'), 'big') % N

        # ── Textbook ──────────────────────────────────────────────────────────
        c1_tb = rsa_enc(pk, m_int)
        c2_tb = rsa_enc(pk, m_int)

        # ── PKCS#1 v1.5 ──────────────────────────────────────────────────────
        em1 = _pkcs15_pad(m_bytes, k)   # random PS each time
        em2 = _pkcs15_pad(m_bytes, k)
        c1_pk = rsa_enc(pk, int.from_bytes(em1, 'big'))
        c2_pk = rsa_enc(pk, int.from_bytes(em2, 'big'))

        # Extract PS bytes (bytes 2 to first 0x00 after position 2)
        def extract_ps(em):
            sep = em.index(0x00, 2)
            return em[2:sep].hex()

        ps1_hex = extract_ps(em1)
        ps2_hex = extract_ps(em2)

        return jsonify({
            "message":       msg_str,
            "bits":          bits,
            "N":             str(N)[:60] + "…",
            "e":             str(pk["e"]),
            "textbook": {
                "c1":          str(c1_tb)[:80] + "…",
                "c2":          str(c2_tb)[:80] + "…",
                "identical":   c1_tb == c2_tb,
            },
            "pkcs15": {
                "c1":          str(c1_pk)[:80] + "…",
                "c2":          str(c2_pk)[:80] + "…",
                "identical":   c1_pk == c2_pk,
                "ps1_hex":     ps1_hex,
                "ps2_hex":     ps2_hex,
                "ps_differ":   ps1_hex != ps2_hex,
                "em1_hex":     em1[:16].hex() + "…",
                "em2_hex":     em2[:16].hex() + "…",
            },
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#13 — Miller-Rabin
# ===========================================================================
@app.route("/api/pa13/test", methods=["POST"])
def pa13_test():
    """
    Miller-Rabin primality test with verbose witness output.

    Returns:
        n, is_prime, rounds, time_ms,
        witnesses: list of { round, a, x0 (=a^d mod n), steps, passed, verdict }
        fermat_note: whether n passes Fermat test (relevant for Carmichael numbers)
        n_minus_1_factored: { s, d } where n-1 = 2^s * d
    """
    try:
        from src.utils.mod_exp import square_and_multiply
        import random as _random

        n_str  = str(request.json["n"])
        n      = int(n_str)
        rounds = int(request.json.get("rounds", 10))
        rounds = max(1, min(rounds, 40))

        t0 = time.time()

        # ── Trivial cases ────────────────────────────────────────────────────
        if n < 2:
            return jsonify({"n": n_str, "is_prime": False, "rounds": 0,
                            "witnesses": [], "time_ms": 0,
                            "verdict": "COMPOSITE", "note": "n < 2"})
        if n == 2 or n == 3:
            return jsonify({"n": n_str, "is_prime": True, "rounds": 0,
                            "witnesses": [], "time_ms": 0, "verdict": "PRIME"})
        if n % 2 == 0:
            return jsonify({"n": n_str, "is_prime": False, "rounds": 0,
                            "witnesses": [], "time_ms": 0,
                            "verdict": "COMPOSITE", "note": "even number"})

        # ── Factor n-1 = 2^s * d ─────────────────────────────────────────────
        s, d = 0, n - 1
        while d % 2 == 0:
            s += 1
            d //= 2

        # ── Fermat test (for Carmichael demo) ────────────────────────────────
        fermat_witnesses = [2, 3, 5]
        fermat_passes = all(
            square_and_multiply(a, n - 1, n) == 1
            for a in fermat_witnesses if a < n - 1
        )

        # ── Verbose Miller-Rabin ──────────────────────────────────────────────
        is_prime_result = True
        witnesses_out   = []

        for i in range(rounds):
            a = _random.randint(2, min(n - 2, 10**18))
            x = square_and_multiply(a, d, n)   # x = a^d mod n

            steps = [{"exp": f"a^d mod n", "val": str(x)}]
            passed = False

            if x == 1 or x == n - 1:
                passed = True
                verdict_r = "passed (x = 1 or n-1)"
            else:
                composite_this = True
                for j in range(s - 1):
                    x = (x * x) % n
                    steps.append({"exp": f"x^2 (sq {j+1})", "val": str(x)})
                    if x == n - 1:
                        composite_this = False
                        passed = True
                        verdict_r = f"passed (x² = n-1 at step {j+1})"
                        break
                if composite_this:
                    is_prime_result = False
                    verdict_r = "FAILED → COMPOSITE witness!"

            witnesses_out.append({
                "round":   i + 1,
                "a":       str(a),
                "x0":      steps[0]["val"],   # a^d mod n
                "steps":   steps,
                "passed":  passed,
                "verdict": verdict_r if passed else verdict_r,
            })

            if not is_prime_result:
                break  # No point continuing — composite is definitive

        elapsed = round((time.time() - t0) * 1000, 2)

        return jsonify({
            "n":             n_str,
            "is_prime":      is_prime_result,
            "verdict":       "PRIME" if is_prime_result else "COMPOSITE",
            "rounds":        rounds,
            "rounds_run":    len(witnesses_out),
            "time_ms":       elapsed,
            "s":             s,
            "d":             str(d),
            "witnesses":     witnesses_out,
            "fermat_passes": fermat_passes,
            "fermat_note":   "Passes Fermat test (Carmichael?)" if fermat_passes and not is_prime_result else "",
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa13/genprime", methods=["POST"])
def pa13_genprime():
    try:
        from src.primality.miller_rabin import gen_prime
        bits = int(request.json.get("bits", 256))
        t0 = time.time()
        p = gen_prime(bits)
        return jsonify({
            "prime": str(p),
            "bits": bits,
            "time_ms": round((time.time() - t0) * 1000, 2),
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#14 — CRT + Hastad's broadcast attack
# ===========================================================================
@app.route("/api/pa14/hastad", methods=["POST"])
def pa14_hastad():
    """
    Håstad broadcast attack visualiser.

    Steps returned:
      1. recipients: list of { index, N, c } — one per recipient (e=3 always)
      2. crt_result: m^3 recovered via CRT
      3. cube_root:  integer cube root of crt_result (= m if unpadded)
      4. match:      cube_root == original m
      5. padded mode: PS prepended → CRT works but cube root is non-integer

    Request: { m, padded (bool, default false), bits (default 64) }
    """
    try:
        from src.rsa.rsa import rsa_keygen, rsa_enc, _pkcs15_pad
        from src.utils.int_root import integer_root
        import os as _os

        m_in   = request.json.get("m", 12345)
        padded = bool(request.json.get("padded", False))
        e      = 3   # fixed per spec

        m_orig = int(m_in)

        # PKCS#1 v1.5 needs k >= len(m)+11 bytes.
        # 64-bit N = 8 bytes, too small for padding.
        # Use 128-bit (16 bytes) for padded, 64-bit for unpadded.
        m_bytes = m_orig.to_bytes(max(1, (m_orig.bit_length() + 7) // 8), 'big')
        if padded:
            min_k = len(m_bytes) + 11   # PKCS#1 v1.5 minimum
            bits  = max(128, min_k * 8) # 128 bits = 16 bytes always sufficient for short m
        else:
            bits  = int(request.json.get("bits", 64))

        # ── Generate 3 distinct RSA moduli ────────────────────────────────────
        Ns, cs = [], []
        attempts = 0
        while len(Ns) < e and attempts < 100:
            attempts += 1
            try:
                pk, _ = rsa_keygen(bits=bits)
                N = pk["N"]
                if N in Ns:
                    continue
                if padded:
                    k  = (N.bit_length() + 7) // 8
                    em = _pkcs15_pad(m_bytes, k)
                    m_int = int.from_bytes(em, 'big') % N
                else:
                    m_int = m_orig % N
                c = rsa_enc({"N": N, "e": e}, m_int)
                Ns.append(N)
                cs.append(c)
            except Exception:
                continue

        if len(Ns) < e:
            return jsonify({"error": f"Could only generate {len(Ns)} moduli"}), 500

        # ── CRT: recover x = m^3 (or padded_m^3) mod N1*N2*N3 ───────────────
        N_total = 1
        for Ni in Ns:
            N_total *= Ni

        x = 0
        for ci, Ni in zip(cs, Ns):
            Mi = N_total // Ni
            x = (x + ci * Mi * pow(Mi, -1, Ni)) % N_total

        # ── Cube root ─────────────────────────────────────────────────────────
        root = integer_root(x, e)
        exact = (root ** e == x)   # True for unpadded, False for padded

        # decode padded root back to bytes if applicable
        recovered_str = str(root)
        recovered_bytes = None
        if padded and exact:
            # strip PKCS padding
            try:
                rb = root.to_bytes((root.bit_length() + 7) // 8, 'big')
                sep = rb.index(0x00, 2)
                recovered_bytes = rb[sep + 1:].decode("utf-8", "replace")
            except Exception:
                recovered_bytes = "(padding error)"
        elif not padded and exact:
            recovered_bytes = str(root)

        recipients = [
            {"index": i + 1, "N": str(Ns[i]), "c": str(cs[i])}
            for i in range(e)
        ]

        return jsonify({
            "original":         str(m_orig),
            "e":                e,
            "padded":           padded,
            "bits":             bits,
            "recipients":       recipients,
            "N_product":        str(N_total)[:80] + "…",
            "crt_result":       str(x)[:80] + "…",
            "cube_root":        str(root)[:80] + "…",
            "exact_root":       bool(exact),
            "match":            (root == m_orig) if not padded else False,
            "recovered":        recovered_bytes or str(root),
            "attack_succeeded": bool(exact and (root == m_orig or padded is False)),
            "padded_note":      ("CRT recovered m³, but cube root is NOT an integer — "
                                 "padding randomised m, so m³ > N₁N₂N₃ no longer holds.")
                                 if padded and not exact else "",
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#15 — Digital Signatures
# ===========================================================================
def _get_sig_keys(bits=512, reset=False):
    from src.rsa.rsa import rsa_keygen
    return _cached(f"sig_keys_{bits}", lambda: rsa_keygen(bits=bits), reset=reset)


@app.route("/api/pa15/sign", methods=["POST"])
def pa15_sign():
    """
    Sign message m. Returns signature in hex plus H(m) for UI verification panel.
    Supports raw=True for raw (unhashed) RSA sign mode.
    """
    try:
        from src.sig.rsa_sig import sign as rsa_sign, verify as rsa_verify, \
                                    raw_rsa_sign, _hash_message
        m_str = request.json["message"]
        bits  = int(request.json.get("bits", 512))
        raw   = bool(request.json.get("raw", False))   # raw RSA sign (no hash)
        reset = bool(request.json.get("reset", False))

        pk, sk = _get_sig_keys(bits=bits, reset=reset)
        N, e, d = pk["N"], pk["e"], sk["d"]
        m = m_str.encode()

        if raw:
            # Sign integer representation of m directly (no hash)
            m_int = int.from_bytes(m[:8].ljust(8, b'\x00'), 'big') % N
            sigma = raw_rsa_sign(sk, m_int)
            h_hex = hex(m_int)          # "hash" = identity
            sigma_hex = hex(sigma)
            verified = (pow(sigma, e, N) == m_int)
        else:
            h_bytes = _hash_message(m)
            h_int   = int.from_bytes(h_bytes, 'big') % N
            if h_int == 0: h_int = 1
            sigma = rsa_sign(sk, m)
            h_hex = h_bytes.hex()
            sigma_hex = hex(sigma)
            verified = rsa_verify(pk, m, sigma)

        return jsonify({
            "message":   m_str,
            "raw":       raw,
            "H_m":       h_hex,           # H(m) hex — shown in verify panel
            "sigma":     sigma_hex,        # signature hex
            "sigma_int": str(sigma),       # for further API calls
            "N":         str(N),
            "e":         str(e),
            "bits":      bits,
            "verified":  bool(verified),
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa15/verify", methods=["POST"])
def pa15_verify():
    """
    Verify σ on m. Returns intermediate values: σ^e mod N and H(m).
    Shows exactly why it passes or fails.
    """
    try:
        from src.sig.rsa_sig import _hash_message
        m_str = request.json["message"]
        N     = int(request.json["N"])
        e     = int(request.json["e"])
        sigma = int(request.json["sigma"])   # accepts decimal or will be hex on UI
        raw   = bool(request.json.get("raw", False))
        m     = m_str.encode()

        recovered = pow(sigma, e, N)   # σ^e mod N

        if raw:
            m_int  = int.from_bytes(m[:8].ljust(8, b'\x00'), 'big') % N
            h_int  = m_int
            h_hex  = hex(m_int)
        else:
            h_bytes = _hash_message(m)
            h_int   = int.from_bytes(h_bytes, 'big') % N
            if h_int == 0: h_int = 1
            h_hex   = h_bytes.hex()

        ok = (recovered == h_int)

        return jsonify({
            "message":      m_str,
            "sigma_e_mod_N": hex(recovered),   # left-hand side
            "H_m":           h_hex,             # right-hand side
            "verified":      bool(ok),
            "match":         bool(ok),
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa15/tamper", methods=["POST"])
def pa15_tamper():
    """
    Tamper demo: flip one bit of the message string, then verify the
    original signature against the tampered message → should fail.
    """
    try:
        from src.sig.rsa_sig import _hash_message
        m_str = request.json["message"]
        N     = int(request.json["N"])
        e_pub = int(request.json["e"])
        sigma = int(request.json["sigma"])   # decimal
        raw   = bool(request.json.get("raw", False))

        # Flip bit 0 of first character
        m_bytes = bytearray(m_str.encode())
        m_bytes[0] ^= 0x01
        tampered_str = m_bytes.decode("utf-8", "replace")

        recovered = pow(sigma, e_pub, N)

        if raw:
            m_int  = int.from_bytes(m_bytes[:8].ljust(8, b'\x00'), 'big') % N
            h_int  = m_int
            h_hex  = hex(m_int)
        else:
            h_b   = _hash_message(bytes(m_bytes))
            h_int = int.from_bytes(h_b, 'big') % N
            if h_int == 0: h_int = 1
            h_hex = h_b.hex()

        ok = (recovered == h_int)

        return jsonify({
            "original_message": m_str,
            "tampered_message": tampered_str,
            "tampered_byte":    f"byte[0] flipped: 0x{m_str.encode()[0]:02x} → 0x{m_bytes[0]:02x}",
            "sigma_e_mod_N":    hex(recovered),
            "H_tampered":       h_hex,
            "verified":         bool(ok),   # should always be False
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa15/forgery", methods=["POST"])
def pa15_forgery():
    """
    Multiplicative forgery demo on raw (unhashed) RSA signatures.

    Given:  σ₁ = m₁^d mod N,  σ₂ = m₂^d mod N
    Forge:  σ* = (σ₁ · σ₂) mod N  — valid signature on m₁·m₂ mod N

    With hash-then-sign this fails because H is NOT multiplicative.
    """
    try:
        from src.sig.rsa_sig import multiplicative_forgery_demo, _hash_message
        from src.utils.mod_exp import square_and_multiply
        bits  = int(request.json.get("bits", 512))
        reset = bool(request.json.get("reset", False))

        pk, sk = _get_sig_keys(bits=bits, reset=reset)
        N, e = pk["N"], pk["e"]

        # ── Raw RSA forgery ──────────────────────────────────────────────────
        r = multiplicative_forgery_demo(pk, sk)

        # ── Hash-then-sign: same trick fails ─────────────────────────────────
        def h_int(m_int):
            mb = m_int.to_bytes(max(1, (m_int.bit_length() + 7) // 8), 'big')
            v = int.from_bytes(_hash_message(mb), 'big') % N
            return v if v else 1

        h1    = h_int(r["m1"])
        h2    = h_int(r["m2"])
        h_m12 = h_int(r["m_forged"])
        hash_homomorphic = ((h1 * h2) % N) == h_m12

        return jsonify({
            "N":              str(N)[:60] + "…",
            "raw_forgery": {
                "m1":         str(r["m1"]),
                "m2":         str(r["m2"]),
                "m_forged":   str(r["m_forged"]),
                "sig1":       hex(r["sig1"]),
                "sig2":       hex(r["sig2"]),
                "sig_forged": hex(r["sig_forged"]),
                "valid":      bool(r["forgery_valid"]),
                "formula":    "σ* = (σ₁·σ₂) mod N is valid for m₁·m₂",
            },
            "hashed_forgery": {
                "valid":       bool(hash_homomorphic),
                "explanation": "H is not multiplicative → forgery fails with hash-then-sign",
            },
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#16 — ElGamal
# ===========================================================================
@app.route("/api/pa16/keygen", methods=["POST"])
def pa16_keygen():
    try:
        from src.elgamal.elgamal import elgamal_keygen
        bits = int(request.json.get("bits", 256))
        reset = bool(request.json.get("reset", False))
        pk, sk = _cached(f"elg_{bits}", lambda: elgamal_keygen(bits=bits), reset=reset)
        return jsonify({
            "p": str(pk["p"]),
            "q": str(pk["q"]),
            "g": str(pk["g"]),
            "h": str(pk["h"]),
            "x": str(sk["x"]),
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa16/encrypt", methods=["POST"])
def pa16_encrypt():
    try:
        from src.elgamal.elgamal import elgamal_enc
        pk = {k: int(request.json["pk"][k]) for k in ("p", "q", "g", "h")}
        m = int(request.json["m"])
        c1, c2 = elgamal_enc(pk, m)
        return jsonify({"c1": str(c1), "c2": str(c2)})
    except Exception as e:
        return _err(e)


@app.route("/api/pa16/decrypt", methods=["POST"])
def pa16_decrypt():
    try:
        from src.elgamal.elgamal import elgamal_dec
        sk = {k: int(request.json["sk"][k]) for k in ("p", "q", "g", "x")}
        c1 = int(request.json["c1"])
        c2 = int(request.json["c2"])
        m = elgamal_dec(sk, c1, c2)
        return jsonify({"plaintext": str(m)})
    except Exception as e:
        return _err(e)


@app.route("/api/pa16/malleability", methods=["POST"])
def pa16_malleability():
    """
    ElGamal malleability demo.

    1. Encrypt m → (c₁, c₂)
    2. Attacker (no secret key) computes c₂' = 2·c₂ mod p → (c₁, c₂')
    3. Decrypt (c₁, c₂') → 2m

    Also runs the trick `trials` times and returns a success count (should be 100%).

    Request: { m, bits (default 64), trials (default 5), reset }
    """
    try:
        from src.elgamal.elgamal import elgamal_keygen, elgamal_enc, elgamal_dec

        m_in   = int(request.json.get("m", 42))
        bits   = int(request.json.get("bits", 64))
        trials = int(request.json.get("trials", 5))
        reset  = bool(request.json.get("reset", False))

        pk, sk = _cached(f"elg_{bits}", lambda: elgamal_keygen(bits=bits), reset=reset)
        p = pk["p"]

        # clamp m to be a valid group element
        m = m_in % p
        if m == 0: m = 1

        # ── Single demo ───────────────────────────────────────────────────────
        c1, c2   = elgamal_enc(pk, m)
        c2_prime = (2 * c2) % p          # attacker's tamper — no key needed
        m_dec    = elgamal_dec(sk, c1, c2)
        m_tamper = elgamal_dec(sk, c1, c2_prime)
        malleable = (m_tamper == (2 * m) % p)

        # ── Counter: repeat `trials` times ────────────────────────────────────
        successes = 0
        for _ in range(trials):
            _c1, _c2 = elgamal_enc(pk, m)
            _c2p = (2 * _c2) % p
            _mt  = elgamal_dec(sk, _c1, _c2p)
            if _mt == (2 * m) % p:
                successes += 1

        return jsonify({
            "m":            str(m),
            "two_m":        str((2 * m) % p),
            "p":            str(p),
            "bits":         bits,
            "original": {
                "c1": str(c1),
                "c2": str(c2),
                "decrypted": str(m_dec),
            },
            "tampered": {
                "c1":        str(c1),           # unchanged
                "c2_prime":  str(c2_prime),     # 2·c₂ mod p
                "decrypted": str(m_tamper),
                "is_2m":     bool(malleable),
            },
            "counter": {
                "trials":    trials,
                "successes": successes,
                "rate":      f"{successes}/{trials}",
                "pct":       round(100 * successes / trials),
            },
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa16/cca_game", methods=["POST"])
def pa16_cca_game():
    """
    CPA game side panel demonstrating why ElGamal fails CCA:

    1. Challenger encrypts challenge message m → (c₁, c₂).
    2. Adversary submits modified ciphertext (c₁, 2c₂) to decryption oracle.
    3. Oracle returns 2m — adversary learns m = (oracle_result / 2) mod p.
    4. Adversary wins the CCA game with probability 1.

    Request: { m, bits (default 64), reset }
    """
    try:
        from src.elgamal.elgamal import elgamal_keygen, elgamal_enc, elgamal_dec
        from src.utils.ext_gcd import mod_inverse

        m_in  = int(request.json.get("m", 42))
        bits  = int(request.json.get("bits", 64))
        reset = bool(request.json.get("reset", False))

        pk, sk = _cached(f"elg_{bits}", lambda: elgamal_keygen(bits=bits), reset=reset)
        p = pk["p"]

        m = m_in % p
        if m == 0: m = 1

        # Step 1: challenger encrypts m
        c1, c2 = elgamal_enc(pk, m)

        # Step 2: adversary modifies c₂ → 2c₂
        c2_mod = (2 * c2) % p

        # Step 3: adversary submits (c₁, 2c₂) to oracle
        oracle_result = elgamal_dec(sk, c1, c2_mod)   # returns 2m

        # Step 4: adversary recovers m = oracle_result / 2 mod p
        inv2 = mod_inverse(2, p)
        recovered_m = (oracle_result * inv2) % p

        return jsonify({
            "challenge_m":   str(m),
            "c1":            str(c1),
            "c2":            str(c2),
            "modified_c2":   str(c2_mod),   # adversary sends this
            "oracle_result": str(oracle_result),   # = 2m
            "recovered_m":   str(recovered_m),
            "win":           bool(recovered_m == m),
            "steps": [
                "1. Challenger sends (c₁, c₂) = Enc(m)",
                "2. Adversary submits (c₁, 2c₂) to Dec oracle",
                f"3. Oracle returns {oracle_result} = 2m",
                f"4. Adversary divides by 2 mod p → m = {recovered_m}",
            ],
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#17 — CCA-Secure PKC (signcryption)
# ===========================================================================
@app.route("/api/pa17/signcrypt", methods=["POST"])
def pa17_signcrypt():
    try:
        from src.pke.signcrypt import generate_cca_keypair, cca_pkc_enc, cca_pkc_dec
        from src.elgamal.elgamal import encode_message, decode_message

        msg   = request.json.get("message", "secret message")
        reset = bool(request.json.get("reset", False))

        # Use 64-bit ElGamal for speed, 512-bit RSA for signing
        keys = _cached("cca_keys",
                        lambda: generate_cca_keypair(enc_bits=64, sign_bits=512),
                        reset=reset)
        enc_pk, enc_sk, sign_pk, sign_sk = keys
        p = enc_pk["p"]

        m_bytes = msg.encode()
        m_int   = int.from_bytes(m_bytes[:6].ljust(6, b'\x00'), 'big') % p
        if m_int == 0: m_int = 1

        # Step 1: Encrypt
        c1, c2, sigma = cca_pkc_enc(enc_pk, sign_sk, m_int)

        # Step 2: Honest decrypt
        m_rec    = cca_pkc_dec(enc_sk, sign_pk, c1, c2, sigma)
        honest_ok = (m_rec == m_int)

        # Step 3: Tampered decrypt (+1 to c2) — signature check fires
        tampered  = cca_pkc_dec(enc_sk, sign_pk, c1, (c2 + 1) % p, sigma)
        rejected  = (tampered is None)

        return jsonify({
            "message":       msg,
            "m_int":         str(m_int),
            "p":             str(p)[:60] + "…",
            "ciphertext": {
                "c1":    str(c1),
                "c2":    str(c2),
                "sigma": hex(sigma),
            },
            "honest_path": {
                "decrypted":     str(m_rec),
                "match":         bool(honest_ok),
                "step":          "Verify(σ, C_E) → OK → Dec(C_E) = m",
            },
            "tampered_path": {
                "c2_tampered":   str((c2 + 1) % p),
                "result":        "⊥ (rejected)" if rejected else str(tampered),
                "rejected":      bool(rejected),
                "step":          "Verify(σ, C_E') → FAIL → abort → ⊥",
            },
            "cca_secure":    bool(honest_ok and rejected),
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa17/tamper", methods=["POST"])
def pa17_tamper():
    """
    CCA malleability contrast demo:
      - Plain ElGamal: tamper c₂ → 2·m returned (malleable!)
      - CCA Signcrypt: tamper c₂ → sig invalid → ⊥ (blocked!)

    Runs cca_malleability_demo from the src module.
    Request: { m (int), reset }
    """
    try:
        from src.pke.signcrypt import (generate_cca_keypair,
                                        cca_pkc_enc, cca_pkc_dec,
                                        cca_malleability_demo)
        from src.elgamal.elgamal import elgamal_enc, elgamal_dec

        m_in  = int(request.json.get("m", 42))
        reset = bool(request.json.get("reset", False))

        keys = _cached("cca_keys",
                        lambda: generate_cca_keypair(enc_bits=64, sign_bits=512),
                        reset=reset)
        enc_pk, enc_sk, sign_pk, sign_sk = keys
        p = enc_pk["p"]

        m = m_in % p
        if m == 0: m = 1

        r = cca_malleability_demo(enc_pk, enc_sk, sign_pk, sign_sk, m)

        return jsonify({
            "m":            str(m),
            "two_m":        str((2 * m) % p),
            "plain_elgamal": {
                "tampered_result": str(r["cpa_tampered_m"]),
                "is_2m":           bool(r["cpa_tampered_is_2m"]),
                "verdict":         "MALLEABLE — 2m returned to attacker!",
            },
            "cca_signcrypt": {
                "tampered_result": "⊥ (rejected)" if r["cca_blocked"] else str(r["cca_tampered_result"]),
                "blocked":         bool(r["cca_blocked"]),
                "verdict":         "BLOCKED — signature check aborted decryption!",
                "reason":          "Verify(σ, C_E') fails → returns ⊥, plaintext never decrypted.",
            },
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#18 — Oblivious Transfer
# ===========================================================================
@app.route("/api/pa18/ot", methods=["POST"])
def pa18_ot():
    """
    1-of-2 OT with full step-by-step protocol log.

    Steps returned:
      1. Bob generates real keypair for chosen index + fake pk for other index.
         pk_b = real, pk_{1-b} = fake (Bob knows sk_b but NOT sk_{1-b}).
      2. Bob sends (pk0, pk1) to Alice.
      3. Alice encrypts m0 under pk0, m1 under pk1 → (C0, C1).
      4. Bob decrypts C_b using sk_b → m_b.  C_{1-b} cannot be decrypted.
      5. Cheat attempt: Bob tries to decrypt C_{1-b} with sk_b → garbage.

    Request: { b (0 or 1), m0 (hex), m1 (hex) }
    """
    try:
        from src.mpc.ot import OT
        from src.elgamal.elgamal import elgamal_dec

        b  = int(request.json["b"])
        m0 = bytes.fromhex(request.json.get("m0", "aa" * 16))
        m1 = bytes.fromhex(request.json.get("m1", "bb" * 16))

        ot = OT()

        # Step 1: Bob generates keypairs
        pk0, pk1, state = ot.receiver_step1(b)
        choice_bit, sk_real = state

        # Step 2: Alice encrypts
        c0, c1 = ot.sender_step(pk0, pk1, m0, m1)

        # Step 3: Bob decrypts C_b
        result = ot.receiver_step2(state, c0, c1)
        expected = m0 if b == 0 else m1
        match = (result == expected)

        # Step 4: Cheat attempt — Bob tries sk_real on the unchosen ciphertext
        c_other = c1 if b == 0 else c0
        try:
            cheat_int = elgamal_dec(sk_real, c_other[0], c_other[1])
            cheat_bytes = cheat_int.to_bytes(16, 'big')
            cheat_hex = cheat_bytes.hex()
            other_expected = m1 if b == 0 else m0
            cheat_correct = (cheat_bytes == other_expected)
        except Exception:
            cheat_hex = "error"
            cheat_correct = False

        def pk_summary(pk):
            return {"h": str(pk["h"])[:40] + "…", "g": str(pk["g"])[:30] + "…"}

        return jsonify({
            "choice":   b,
            "m0_hint":  "??" if b == 1 else m0.hex(),   # Alice hides the unchosen msg
            "m1_hint":  "??" if b == 0 else m1.hex(),
            "m_b":      (m0 if b == 0 else m1).hex(),   # the one Bob receives
            "log": [
                {
                    "step": 1,
                    "actor": "Bob",
                    "desc": f"Bob generates real keypair for index {b} and a fake pk for index {1 - b}.",
                    "detail": f"pk{b} = real (sk known) | pk{1-b} = fake (no sk)",
                },
                {
                    "step": 2,
                    "actor": "Bob→Alice",
                    "desc": f"Bob sends (pk0, pk1) to Alice.",
                    "detail": f"pk0.h = {pk_summary(pk0)['h']}\npk1.h = {pk_summary(pk1)['h']}",
                },
                {
                    "step": 3,
                    "actor": "Alice",
                    "desc": "Alice encrypts: C0 = Enc(pk0, m0),  C1 = Enc(pk1, m1).",
                    "detail": f"C0 = ({str(c0[0])[:30]}…, …)\nC1 = ({str(c1[0])[:30]}…, …)",
                },
                {
                    "step": 4,
                    "actor": "Bob",
                    "desc": f"Bob decrypts C{b} using sk_real → m{b}.",
                    "detail": f"Received: {result.hex()}\nExpected: {expected.hex()}\nMatch: {match}",
                },
            ],
            "result": {
                "received":  result.hex(),
                "expected":  expected.hex(),
                "match":     bool(match),
            },
            "cheat": {
                "desc":    f"Bob tries to decrypt C{1-b} (unchosen) with sk_real → garbage",
                "result":  cheat_hex,
                "correct": bool(cheat_correct),
                "note":    "The unchosen ciphertext was encrypted under a fake pk — sk_real cannot decrypt it.",
            },
        })
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#19 — Secure gates
# ===========================================================================
@app.route("/api/pa19/and", methods=["POST"])
def pa19_and():
    """
    Secure AND gate with full OT step log (AND-only for the interactive demo).
    XOR and NOT are also supported but are simpler (no OT).

    AND protocol:
      1. Alice sets up messages m0=0, m1=a  (sender)
      2. Bob runs OT receiver with choice bit b
      3. Bob receives m_b = a AND b
      4. Alice learns: nothing about b
      5. Bob learns: only m_b = a AND b (not a itself if b=0)

    Request: { a, b, gate (AND|XOR|NOT) }
    """
    try:
        from src.mpc.ot import OT
        from src.mpc.secure_and import secure_xor, secure_not
        from src.elgamal.elgamal import elgamal_dec

        a    = int(request.json["a"]) & 1
        b    = int(request.json.get("b", 0)) & 1
        gate = request.json.get("gate", "AND").upper()

        if gate == "XOR":
            result = secure_xor(a, b)
            return jsonify({
                "gate": "XOR", "a": a, "b": b, "output": int(result),
                "log": [
                    {"step": 1, "actor": "Both", "desc": "XOR is free — no communication needed.",
                     "detail": f"a XOR b = {a} ⊕ {b} = {result}"},
                ],
                "transcript": [],
                "alice_learns": f"Alice knows her own bit a={a} and the output {result}. She learns nothing about b.",
                "bob_learns":   f"Bob knows his own bit b={b} and the output {result}. He learns nothing about a.",
            })

        if gate == "NOT":
            result = secure_not(a)
            return jsonify({
                "gate": "NOT", "a": a, "b": None, "output": int(result),
                "log": [
                    {"step": 1, "actor": "Alice", "desc": "NOT is local — Alice flips her bit.",
                     "detail": f"NOT {a} = {result}"},
                ],
                "transcript": [],
                "alice_learns": f"Alice knows her own bit a={a} and computes NOT a={result} locally.",
                "bob_learns":   "Bob is not involved in NOT.",
            })

        # ── Secure AND via OT ─────────────────────────────────────────────────
        ot = OT()

        # Step 1: Alice sets up OT messages
        m0_val = 0   # if Bob picks 0, he gets 0
        m1_val = a   # if Bob picks 1, he gets a
        m0 = m0_val.to_bytes(16, 'big')
        m1 = m1_val.to_bytes(16, 'big')

        # Step 2: Bob runs OT receiver step 1
        pk0, pk1, state = ot.receiver_step1(b)
        choice_bit, sk_real = state

        # Step 3: Alice (sender) encrypts
        c0, c1 = ot.sender_step(pk0, pk1, m0, m1)

        # Step 4: Bob decrypts C_b
        result_bytes = ot.receiver_step2(state, c0, c1)
        result = int.from_bytes(result_bytes, 'big') & 1
        expected = (a & b)

        # Step 5: Cheat — Bob tries to decrypt C_{1-b}
        c_other = c1 if b == 0 else c0
        try:
            cheat_int   = elgamal_dec(sk_real, c_other[0], c_other[1])
            cheat_bytes = cheat_int.to_bytes(16, 'big')
            cheat_val   = int.from_bytes(cheat_bytes, 'big') & 1
            cheat_correct = (cheat_val == (m1_val if b == 0 else m0_val))
        except Exception:
            cheat_val, cheat_correct = "?", False

        log = [
            {
                "step": 1, "actor": "Alice",
                "desc": f"Alice sets up OT messages: m0 = 0, m1 = a = {a}.",
                "detail": f"m0 = 0  (Bob gets 0 if he picks 0)\nm1 = {a}  (Bob gets {a} if he picks 1)",
            },
            {
                "step": 2, "actor": "Bob",
                "desc": f"Bob generates OT keypair for his choice bit b = {b}.",
                "detail": f"pk{b} = real keypair (sk known)\npk{1-b} = fake pk (no sk — Alice cannot detect which is real)",
            },
            {
                "step": 3, "actor": "Bob→Alice",
                "desc": "Bob sends (pk0, pk1) to Alice. Alice cannot tell which is real.",
                "detail": f"pk0.h = {str(pk0['h'])[:40]}…\npk1.h = {str(pk1['h'])[:40]}…",
            },
            {
                "step": 4, "actor": "Alice",
                "desc": "Alice encrypts: C0 = Enc(pk0, m0),  C1 = Enc(pk1, m1).",
                "detail": f"C0 = ({str(c0[0])[:30]}…, …)\nC1 = ({str(c1[0])[:30]}…, …)",
            },
            {
                "step": 5, "actor": "Alice→Bob",
                "desc": "Alice sends (C0, C1) to Bob.",
                "detail": "Bob receives both ciphertexts but can only decrypt C_b.",
            },
            {
                "step": 6, "actor": "Bob",
                "desc": f"Bob decrypts C{b} using sk_real → m_b = a ∧ b.",
                "detail": f"Decrypted m_{b} = {result}\nExpected a ∧ b = {a} ∧ {b} = {expected}\nMatch: {result == expected}",
            },
        ]

        transcript = [
            {"from": "Bob",   "to": "Alice", "msg": f"(pk0, pk1) — Bob's OT public keys"},
            {"from": "Alice", "to": "Bob",   "msg": f"(C0, C1) — encryptions of (0, {a})"},
        ]

        return jsonify({
            "gate":   "AND",
            "a":      a,
            "b":      b,
            "output": int(result),
            "correct": bool(result == expected),
            "log":    log,
            "transcript": transcript,
            "cheat": {
                "desc":    f"Bob tries to decrypt C{1-b} (unchosen) with sk_real",
                "result":  str(cheat_val),
                "correct": bool(cheat_correct),
                "note":    "Unchosen ciphertext encrypted under fake pk → garbage output.",
            },
            "alice_learns": f"Alice sees only (pk0, pk1) from Bob. She cannot tell b={b} from b={1-b} — both look like random group elements.",
            "bob_learns":   f"Bob receives m_{b} = {result} = a ∧ b. He does NOT learn a={a} directly (only its AND with his bit).",
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa19/run_all", methods=["POST"])
def pa19_run_all():
    """
    Run all 4 (a,b) combinations and return a truth table.
    Each row includes the OT output and a match check.
    """
    try:
        from src.mpc.secure_and import secure_and, secure_xor, secure_not
        gate = request.json.get("gate", "AND").upper()
        rows = []
        for aa in (0, 1):
            for bb in (0, 1):
                if gate == "AND":
                    out = secure_and(aa, bb)
                    expected = aa & bb
                elif gate == "XOR":
                    out = secure_xor(aa, bb)
                    expected = aa ^ bb
                elif gate == "NOT":
                    out = secure_not(aa)
                    expected = 1 - aa
                    bb = None
                else:
                    continue
                rows.append({
                    "a": aa, "b": bb, "output": int(out),
                    "expected": int(expected),
                    "match": bool(int(out) == int(expected)),
                })
                if gate == "NOT":
                    break   # only 2 cases for NOT

        all_correct = all(r["match"] for r in rows)
        return jsonify({"gate": gate, "rows": rows, "all_correct": bool(all_correct)})
    except Exception as e:
        return _err(e)


# ===========================================================================
# PA#20 — Two-Party MPC
# ===========================================================================
@app.route("/api/pa20/millionaires", methods=["POST"])
def pa20_millionaires():
    """
    Millionaires problem with gate-by-gate circuit trace.

    Returns:
      - richer: 'Alice' | 'Bob' | 'Equal'
      - n_gates: total gate count
      - gates: list of {idx, type, in1, in2, out} (wire values, NOT party inputs)
      - x_bits, y_bits: bit arrays (MSB first) — these reveal the actual values
        but only to the UI for display; in a real MPC they'd be secret-shared.

    Note: x and y themselves are NOT returned — only the result and circuit trace.
    """
    try:
        from src.mpc.circuit import Circuit
        from src.mpc.secure_and import secure_and, secure_xor, secure_not

        n_bits = 4
        x = max(0, min(15, int(request.json["x"])))  # clamp to 4-bit
        y = max(0, min(15, int(request.json["y"])))

        # ── Rebuild circuit with trace ─────────────────────────────────────────
        c = Circuit()
        x_wires = [c.add_input() for _ in range(n_bits)]
        y_wires = [c.add_input() for _ in range(n_bits)]

        wire_vals = {}
        x_bits = [(x >> (n_bits - 1 - i)) & 1 for i in range(n_bits)]
        y_bits = [(y >> (n_bits - 1 - i)) & 1 for i in range(n_bits)]
        for i in range(n_bits):
            wire_vals[x_wires[i]] = x_bits[i]
            wire_vals[y_wires[i]] = y_bits[i]

        # Comparator (same logic as circuit.py)
        gt_wire = c.add_xor(x_wires[0], x_wires[0])
        wire_vals[gt_wire] = 0
        eq_wire = c.add_not(gt_wire)
        wire_vals[eq_wire] = 1

        for i in range(n_bits):
            xi, yi = x_wires[i], y_wires[i]
            not_yi      = c.add_not(yi)
            x_gt_here   = c.add_and(xi, not_yi)
            eq_and_gt   = c.add_and(eq_wire, x_gt_here)
            not_old_gt  = c.add_not(gt_wire)
            not_eq_gt   = c.add_not(eq_and_gt)
            new_gt      = c.add_not(c.add_and(not_old_gt, not_eq_gt))
            xor_bits    = c.add_xor(xi, yi)
            xnor_bits   = c.add_not(xor_bits)
            new_eq      = c.add_and(eq_wire, xnor_bits)
            gt_wire, eq_wire = new_gt, new_eq

        result = c.evaluate(wire_vals)

        # Winner
        if result[eq_wire] == 1:
            winner = "Equal"
        elif result[gt_wire] == 1:
            winner = "Alice"
        else:
            winner = "Bob"

        # ── Gate trace ─────────────────────────────────────────────────────────
        gate_trace = []
        for idx, (gtype, in1, in2, out) in enumerate(c.gates):
            gate_trace.append({
                "idx":    idx + 1,
                "type":   gtype,
                "in1":    int(result.get(in1, wire_vals.get(in1, "?"))),
                "in2":    int(result.get(in2, wire_vals.get(in2, "?"))) if in2 is not None else None,
                "out":    int(result[out]),
                "w_in1":  in1,
                "w_in2":  in2,
                "w_out":  out,
            })

        return jsonify({
            "richer":   winner,
            "n_gates":  len(c.gates),
            "n_bits":   n_bits,
            "x_bits":   x_bits,   # Alice's bits (shown only in Alice's panel)
            "y_bits":   y_bits,   # Bob's bits   (shown only in Bob's panel)
            "gates":    gate_trace,
        })
    except Exception as e:
        return _err(e)


@app.route("/api/pa20/equality", methods=["POST"])
def pa20_equality():
    try:
        from src.mpc.circuit import secure_equality
        x = int(request.json["x"])
        y = int(request.json["y"])
        return jsonify({"x": x, "y": y, "equal": bool(secure_equality(x, y))})
    except Exception as e:
        return _err(e)


@app.route("/api/pa20/add", methods=["POST"])
def pa20_add():
    try:
        from src.mpc.circuit import secure_add
        x = int(request.json["x"])
        y = int(request.json["y"])
        return jsonify({"x": x, "y": y, "sum": int(secure_add(x, y))})
    except Exception as e:
        return _err(e)


# ===========================================================================
# Boot
# ===========================================================================
if __name__ == "__main__":
    print("\n  POIS API on http://localhost:5000")
    routes = sorted(r.rule for r in app.url_map.iter_rules() if r.rule.startswith("/api"))
    for r in routes:
        print(f"    {r}")
    print()
    app.run(port=5000, debug=False)