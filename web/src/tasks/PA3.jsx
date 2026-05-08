// PA#3 — CPA-Secure Symmetric Encryption.
// All deliverables:
//   1. Enc/Dec with fresh nonce per call
//   2. Multi-block support
//   3. IND-CPA game (secure & broken modes)
//   4. Broken variant (deterministic nonce reuse)
//   5. Malleability demo (1-bit flip in ciphertext flips bit in plaintext)

import { useState } from "react";
import { Card, Button, Output, KV, Description, Badge, ToggleGroup, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

const DEFAULT_KEY = "0123456789abcdef0123456789abcdef";

export default function PA3() {
  const [tab, setTab] = useState("roundtrip");

  return (
    <div>
      <Description>
        Construction: <code>C = ⟨r, F_k(r) ⊕ m⟩</code>, with a fresh random nonce <code>r</code> per
        encryption. CPA-security needs <code>F_k</code> to be a PRF and <code>r</code> to be unique each
        call. Reusing <code>r</code> on the same plaintext leaks information.
        <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-faint)" }}>
          Note: each PRF evaluation walks a 128-bit GGM tree and takes ~2–3 seconds. Sections may take
          a few seconds to load on first call.
        </div>
      </Description>

      <Card title="Section">
        <ToggleGroup
          value={tab}
          onChange={setTab}
          options={[
            { label: "Encrypt / Decrypt",   value: "roundtrip" },
            { label: "Nonce-reuse demo",    value: "nonce" },
            { label: "Broken variant",      value: "broken" },
            { label: "IND-CPA game",        value: "game" },
            { label: "Malleability",        value: "malleable" },
          ]}
        />
      </Card>

      {tab === "roundtrip" && <Roundtrip />}
      {tab === "nonce"     && <NonceReuse />}
      {tab === "broken"    && <Broken />}
      {tab === "game"      && <IndCpaGame />}
      {tab === "malleable" && <Malleability />}
    </div>
  );
}

// ─── 1. Encrypt + decrypt round-trip ────────────────────────────────
function Roundtrip() {
  const [key, setKey] = useState(DEFAULT_KEY);
  const [pt, setPt] = useState("Hello, this is a secret!");
  const [enc, setEnc] = useState(null);
  const [dec, setDec] = useState(null);
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);

  async function encrypt() {
    setErr(null); setBusy("e"); setDec(null);
    const r = await callApi("/api/pa3/encrypt", { key, message: pt });
    if (r.ok) setEnc(r.data); else setErr(r.error);
    setBusy(null);
  }

  async function decrypt() {
    if (!enc) return;
    setErr(null); setBusy("d");
    const r = await callApi("/api/pa3/decrypt", { key, nonce: enc.nonce, ciphertext: enc.ciphertext });
    if (r.ok) setDec(r.data); else setErr(r.error);
    setBusy(null);
  }

  const matches = dec?.plaintext === pt;

  return (
    <Card title="Encrypt + decrypt">
      <label>Key k (hex, 16 bytes)</label>
      <input type="text" value={key} onChange={(e) => setKey(e.target.value)} />
      <div style={{ marginTop: 10 }}>
        <label>Plaintext</label>
        <textarea value={pt} onChange={(e) => setPt(e.target.value)} />
      </div>
      <div style={{ marginTop: 12, display: "flex", gap: 10 }}>
        <Button onClick={encrypt} loading={busy === "e"}>Encrypt</Button>
        <Button onClick={decrypt} loading={busy === "d"} variant="secondary" disabled={!enc}>
          Decrypt
        </Button>
      </div>
      {enc && (
        <Output>
          <KV k="nonce r"     v={enc.nonce} />
          <KV k="ciphertext"  v={enc.ciphertext} success />
        </Output>
      )}
      {dec && (
        <Output>
          <KV k="plaintext" v={dec.plaintext} success={matches} error={!matches} />
          <Badge variant={matches ? "success" : "error"}>
            {matches ? "✓ round-trip OK" : "✗ mismatch"}
          </Badge>
        </Output>
      )}
      <ErrorBanner>{err}</ErrorBanner>
    </Card>
  );
}

// ─── 2. Nonce-reuse demo ────────────────────────────────────────────
function NonceReuse() {
  const [key, setKey] = useState(DEFAULT_KEY);
  const [msg, setMsg] = useState("vote: A");
  const [out, setOut] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  async function run() {
    setErr(null); setBusy(true); setOut(null);
    const r = await callApi("/api/pa3/nonce_reuse_demo", { key, message: msg });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(false);
  }

  return (
    <Card title="Nonce-reuse: secure vs broken" sub="Encrypt the same plaintext twice in each scheme">
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
        Compares the two ciphertexts you get from encrypting the same message twice.
        Secure mode draws a fresh nonce so ciphertexts differ; the broken variant uses
        a fixed nonce so identical plaintexts produce identical ciphertexts.
      </div>
      <div className="row">
        <div>
          <label>Key (hex)</label>
          <input type="text" value={key} onChange={(e) => setKey(e.target.value)} />
        </div>
        <div>
          <label>Message</label>
          <input type="text" value={msg} onChange={(e) => setMsg(e.target.value)} />
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <Button onClick={run} loading={busy}>Run demo (~ 10 s)</Button>
      </div>
      {out && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 10 }}>
          <Output label="Secure (fresh nonce)">
            <KV k="nonce 1" v={trunc(out.secure.nonce_1, 32)} />
            <KV k="ct 1"    v={trunc(out.secure.ct_1, 32)} />
            <KV k="nonce 2" v={trunc(out.secure.nonce_2, 32)} />
            <KV k="ct 2"    v={trunc(out.secure.ct_2, 32)} />
            <Badge variant={out.secure.ciphertexts_equal ? "error" : "success"}>
              ciphertexts {out.secure.ciphertexts_equal ? "identical (BAD)" : "differ (good)"}
            </Badge>
          </Output>
          <Output label="Broken (fixed nonce r=0)">
            <KV k="nonce 1" v={trunc(out.broken.nonce_1, 32)} />
            <KV k="ct 1"    v={trunc(out.broken.ct_1, 32)} />
            <KV k="nonce 2" v={trunc(out.broken.nonce_2, 32)} />
            <KV k="ct 2"    v={trunc(out.broken.ct_2, 32)} />
            <Badge variant={out.broken.ciphertexts_equal ? "error" : "success"}>
              ciphertexts {out.broken.ciphertexts_equal ? "identical (leaked)" : "differ"}
            </Badge>
          </Output>
        </div>
      )}
      <ErrorBanner>{err}</ErrorBanner>
    </Card>
  );
}

// ─── 3. Broken variant ──────────────────────────────────────────────
function Broken() {
  const [key, setKey] = useState(DEFAULT_KEY);
  const [msg, setMsg] = useState("voter A");
  const [out, setOut] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  async function run() {
    setErr(null); setBusy(true); setOut(null);
    const r = await callApi("/api/pa3/encrypt_broken", { key, message: msg });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(false);
  }

  return (
    <Card title="Broken CPA encryption" sub="Deliberately uses fixed nonce r = 0 (insecure)">
      <div className="row">
        <div>
          <label>Key (hex)</label>
          <input type="text" value={key} onChange={(e) => setKey(e.target.value)} />
        </div>
        <div>
          <label>Message</label>
          <input type="text" value={msg} onChange={(e) => setMsg(e.target.value)} />
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <Button onClick={run} loading={busy}>Encrypt with broken variant</Button>
      </div>
      {out && (
        <Output>
          <KV k="nonce r"     v={out.nonce} />
          <KV k="ciphertext"  v={out.ciphertext} success />
          <KV k="scheme"      v={out.scheme} />
          <div style={{ marginTop: 6 }}>
            <Badge variant="error">notice nonce = all-zeroes</Badge>
          </div>
        </Output>
      )}
      <ErrorBanner>{err}</ErrorBanner>
    </Card>
  );
}

// ─── 4. IND-CPA game ────────────────────────────────────────────────
function IndCpaGame() {
  const [rounds, setRounds] = useState(10);
  const [broken, setBroken] = useState(false);
  const [out, setOut] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  async function run() {
    setErr(null); setBusy(true); setOut(null);
    const r = await callApi("/api/pa3/ind_cpa_game", { rounds: Number(rounds), broken });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(false);
  }

  return (
    <Card title="IND-CPA distinguishing game">
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
        Runs the IND-CPA security game with a dummy adversary. A secure scheme yields advantage ≈ 0.
        Each round = one PRF call ≈ 2–3 s, so keep rounds small.
      </div>
      <div className="row">
        <div className="narrow" style={{ width: 130 }}>
          <label>Rounds</label>
          <input type="number" min={5} max={50} value={rounds} onChange={(e) => setRounds(e.target.value)} />
        </div>
        <div>
          <label>Mode</label>
          <ToggleGroup
            value={broken}
            onChange={setBroken}
            options={[{ label: "Secure", value: false }, { label: "Broken", value: true }]}
          />
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <Button onClick={run} loading={busy}>Run game</Button>
      </div>
      {out && (
        <Output>
          <KV k="rounds"     v={out.rounds} />
          <KV k="advantage"  v={out.advantage.toFixed(4)} />
          <KV k="time"       v={`${out.time_ms} ms`} />
          <Badge variant={out.advantage < 0.15 ? "success" : "error"}>
            {out.advantage < 0.15 ? "✓ adversary advantage ≈ 0" : "✗ distinguisher succeeded"}
          </Badge>
        </Output>
      )}
      <ErrorBanner>{err}</ErrorBanner>
    </Card>
  );
}

// ─── 5. Malleability demo ───────────────────────────────────────────
function Malleability() {
  const [key, setKey] = useState(DEFAULT_KEY);
  const [pt, setPt] = useState("attack at dawn!");
  const [flipByte, setFlipByte] = useState(0);
  const [enc, setEnc] = useState(null);
  const [dec, setDec] = useState(null);
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);

  async function encrypt() {
    setErr(null); setBusy("e"); setDec(null);
    const r = await callApi("/api/pa3/encrypt", { key, message: pt });
    if (r.ok) setEnc(r.data); else setErr(r.error);
    setBusy(null);
  }

  async function tamperAndDecrypt() {
    if (!enc) return;
    setErr(null); setBusy("t");
    // flip lowest bit of byte at flipByte
    const ctBytes = enc.ciphertext.match(/.{2}/g) || [];
    const i = Math.min(Number(flipByte), ctBytes.length - 1);
    const flipped = (parseInt(ctBytes[i], 16) ^ 0x01).toString(16).padStart(2, "0");
    const tampered = [...ctBytes];
    tampered[i] = flipped;
    const r = await callApi("/api/pa3/decrypt", {
      key, nonce: enc.nonce, ciphertext: tampered.join(""),
    });
    if (r.ok) setDec(r.data); else setErr(r.error);
    setBusy(null);
  }

  return (
    <Card title="Malleability of CPA encryption" sub="Flipping 1 bit in ciphertext flips 1 bit in plaintext (no integrity!)">
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
        CPA security alone doesn't protect integrity. Encrypt, flip a bit in the ciphertext, decrypt
        — the plaintext changes predictably. PA#6 (Encrypt-then-MAC) fixes this.
      </div>
      <div className="row">
        <div>
          <label>Key</label>
          <input type="text" value={key} onChange={(e) => setKey(e.target.value)} />
        </div>
        <div>
          <label>Plaintext</label>
          <input type="text" value={pt} onChange={(e) => setPt(e.target.value)} />
        </div>
      </div>
      <div style={{ marginTop: 12, display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap" }}>
        <Button onClick={encrypt} loading={busy === "e"}>1. Encrypt</Button>
        <div style={{ width: 140 }}>
          <label>Flip byte index</label>
          <input type="number" min={0} value={flipByte} onChange={(e) => setFlipByte(e.target.value)} />
        </div>
        <Button onClick={tamperAndDecrypt} loading={busy === "t"} variant="secondary" disabled={!enc}>
          2. Flip + decrypt
        </Button>
      </div>
      {enc && (
        <Output label="Original ciphertext">
          <KV k="nonce" v={enc.nonce} />
          <KV k="ct"    v={enc.ciphertext} />
        </Output>
      )}
      {dec && (
        <Output label="Decryption of tampered ciphertext">
          <KV k="result" v={dec.plaintext} />
          <Badge variant="error">✗ malleable — decrypt accepted modified ct</Badge>
        </Output>
      )}
      <ErrorBanner>{err}</ErrorBanner>
    </Card>
  );
}

// helper
function trunc(s, n = 32) {
  if (!s) return s;
  return s.length > n ? s.slice(0, n) + "…" : s;
}