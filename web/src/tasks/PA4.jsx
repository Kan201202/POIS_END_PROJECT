// PA#4 — Modes of Operation.
// All deliverables:
//   1. CBC / OFB / CTR encrypt + decrypt round-trip
//   2. Bit-flip ciphertext, observe per-mode error propagation pattern
//   3. CBC IV-reuse attack
//   4. OFB keystream-reuse attack
//   5. Mode comparison

import { useState } from "react";
import { Card, Button, Output, KV, Description, Badge, ToggleGroup, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

const DEFAULT_KEY = "0123456789abcdef0123456789abcdef";

export default function PA4() {
  const [tab, setTab] = useState("roundtrip");

  return (
    <div>
      <Description>
        Block-cipher modes turn a fixed-input PRF into an encryption scheme over arbitrary-length
        messages. CBC chains, OFB pre-computes a keystream, CTR is fully parallel. Each has different
        IV-reuse and error-propagation behaviour.
        <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-faint)" }}>
          Note: PRF evaluations are slow (~2–3 s each). Multi-block messages may take 10+ seconds.
        </div>
      </Description>

      <Card title="Section">
        <ToggleGroup
          value={tab}
          onChange={setTab}
          options={[
            { label: "Encrypt / Decrypt",   value: "roundtrip" },
            { label: "Bit-flip propagation", value: "bitflip" },
            { label: "IV-reuse attack",      value: "ivreuse" },
            { label: "Mode comparison",      value: "compare" },
          ]}
        />
      </Card>

      {tab === "roundtrip" && <Roundtrip />}
      {tab === "bitflip"   && <BitFlip />}
      {tab === "ivreuse"   && <IvReuse />}
      {tab === "compare"   && <Compare />}
    </div>
  );
}

// ─── 1. Encrypt + decrypt round-trip ────────────────────────────────
function Roundtrip() {
  const [mode, setMode] = useState("CBC");
  const [key, setKey] = useState(DEFAULT_KEY);
  const [pt, setPt] = useState("hello world");
  const [enc, setEnc] = useState(null);
  const [dec, setDec] = useState(null);
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);

  async function encrypt() {
    setErr(null); setBusy("e"); setDec(null);
    const r = await callApi("/api/pa4/encrypt", { mode, key, message: pt });
    if (r.ok) setEnc(r.data); else setErr(r.error);
    setBusy(null);
  }

  async function decrypt() {
    if (!enc) return;
    setErr(null); setBusy("d");
    const r = await callApi("/api/pa4/decrypt", {
      mode, key, iv: enc.iv, ciphertext: enc.ciphertext,
    });
    if (r.ok) setDec(r.data); else setErr(r.error);
    setBusy(null);
  }

  const matches = dec?.plaintext === pt;
  const modeInfo = {
    CBC: "C_i = F_k(C_{i-1}) ⊕ M_i. Sequential encryption; needs random IV.",
    OFB: "Keystream = F_k(IV), F_k(F_k(IV)), … pre-computable, encrypt = decrypt.",
    CTR: "C_i = F_k(r+i) ⊕ M_i. Fully parallel; turns block cipher into stream cipher.",
  };

  return (
    <Card title="Encrypt + decrypt">
      <label>Mode</label>
      <ToggleGroup
        value={mode}
        onChange={setMode}
        options={[
          { label: "CBC", value: "CBC" },
          { label: "OFB", value: "OFB" },
          { label: "CTR", value: "CTR" },
        ]}
      />
      <div style={{ marginTop: 6, fontSize: 12, color: "var(--text-muted)" }}>
        {modeInfo[mode]}
      </div>
      <div style={{ marginTop: 10 }}>
        <label>Key (hex, 16 bytes)</label>
        <input type="text" value={key} onChange={(e) => setKey(e.target.value)} />
      </div>
      <div style={{ marginTop: 10 }}>
        <label>Plaintext</label>
        <textarea value={pt} onChange={(e) => setPt(e.target.value)} />
      </div>
      <div style={{ marginTop: 12, display: "flex", gap: 10 }}>
        <Button onClick={encrypt} loading={busy === "e"}>Encrypt with {mode}</Button>
        <Button onClick={decrypt} loading={busy === "d"} variant="secondary" disabled={!enc}>
          Decrypt
        </Button>
      </div>
      {enc && (
        <Output>
          <KV k="mode"        v={enc.mode} />
          <KV k="IV / nonce"  v={enc.iv} />
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

// ─── 2. Bit-flip propagation ────────────────────────────────────────
function BitFlip() {
  const [mode, setMode] = useState("CBC");
  const [key, setKey] = useState(DEFAULT_KEY);
  const [pt, setPt] = useState("Three sixteen-byte blocks AAAAAAAAAAAAAAAAA");
  const [flipByte, setFlipByte] = useState(0);
  const [out, setOut] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  async function run() {
    setErr(null); setBusy(true); setOut(null);
    const r = await callApi("/api/pa4/bitflip", {
      mode, key, message: pt, flip_byte: Number(flipByte),
    });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(false);
  }

  const expected = {
    CBC: "[flipped block, flipped block + 1] — error propagates 2 blocks",
    OFB: "[flipped block] — only that block",
    CTR: "[flipped block] — only that block",
  };

  return (
    <Card title="Bit-flip error propagation">
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
        Encrypts the message, flips one bit at byte index <i>flip_byte</i> in the ciphertext, decrypts,
        and reports which plaintext blocks ended up corrupted. The pattern is mode-specific.
      </div>
      <label>Mode</label>
      <ToggleGroup
        value={mode}
        onChange={setMode}
        options={[
          { label: "CBC", value: "CBC" },
          { label: "OFB", value: "OFB" },
          { label: "CTR", value: "CTR" },
        ]}
      />
      <div style={{ marginTop: 10 }}>
        <label>Plaintext</label>
        <textarea value={pt} onChange={(e) => setPt(e.target.value)} />
      </div>
      <div style={{ marginTop: 10, display: "flex", gap: 10, alignItems: "flex-end" }}>
        <div style={{ width: 160 }}>
          <label>Flip byte index</label>
          <input type="number" min={0} value={flipByte} onChange={(e) => setFlipByte(e.target.value)} />
        </div>
        <Button onClick={run} loading={busy}>Run flip + decrypt</Button>
      </div>
      {out && (
        <Output>
          <KV k="mode"             v={out.mode} />
          <KV k="block length"     v={`${out.block_len} bytes`} />
          <KV k="flipped byte"     v={out.flip_byte_index} />
          <KV k="flipped block"    v={out.flipped_block} />
          <KV k="affected blocks"  v={`[${out.affected_blocks.join(", ")}]`} success />
          <div style={{ marginTop: 6, fontSize: 12, color: "var(--text-muted)" }}>
            Expected for {mode}: {expected[mode]}
          </div>
        </Output>
      )}
      <ErrorBanner>{err}</ErrorBanner>
    </Card>
  );
}

// ─── 3. IV-reuse attack ─────────────────────────────────────────────
function IvReuse() {
  const [mode, setMode] = useState("CBC");
  const [key, setKey] = useState(DEFAULT_KEY);
  const [m0, setM0] = useState("sixteen-bytes!!!");
  const [m1, setM1] = useState("sixteen-bytes!!!");
  const [out, setOut] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  async function run() {
    setErr(null); setBusy(true); setOut(null);
    const r = await callApi("/api/pa4/iv_reuse_attack", { mode, key, m0, m1 });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(false);
  }

  return (
    <Card title="IV-reuse attack" sub="Encrypts m0 and m1 with the same IV and exploits the leak">
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
        For CBC: if M0[:block] == M1[:block], the first ciphertext blocks match.
        For OFB: same IV gives same keystream, so C0 ⊕ C1 = M0 ⊕ M1, and knowing M0 reveals M1.
      </div>
      <label>Mode</label>
      <ToggleGroup
        value={mode}
        onChange={setMode}
        options={[
          { label: "CBC", value: "CBC" },
          { label: "OFB", value: "OFB" },
        ]}
      />
      <div className="row" style={{ marginTop: 10 }}>
        <div>
          <label>m0</label>
          <input type="text" value={m0} onChange={(e) => setM0(e.target.value)} />
        </div>
        <div>
          <label>m1 ({mode === "CBC" ? "first block must match m0 for attack to work" : "secret target"})</label>
          <input type="text" value={m1} onChange={(e) => setM1(e.target.value)} />
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <Button onClick={run} loading={busy}>Run attack</Button>
      </div>
      {out && (
        <Output>
          <KV k="mode"        v={out.mode} />
          <KV k="explanation" v={out.explanation} />
          {out.recovered_m1 !== undefined && (
            <>
              <KV k="recovered m1" v={out.recovered_m1} success />
              <KV k="expected m1"  v={out.expected_m1} />
            </>
          )}
          <Badge variant={out.attack_succeeded ? "success" : "muted"}>
            {out.attack_succeeded ? "✓ attack succeeded" : "attack did not detect leak"}
          </Badge>
        </Output>
      )}
      <ErrorBanner>{err}</ErrorBanner>
    </Card>
  );
}

// ─── 4. Mode comparison table ───────────────────────────────────────
function Compare() {
  const rows = [
    ["Property",                    "CBC",        "OFB",        "CTR"],
    ["Parallel encryption",         "no",         "no",         "yes"],
    ["Parallel decryption",         "yes",        "no",         "yes"],
    ["Random-access decryption",    "no",         "no",         "yes"],
    ["Error propagation",           "2 blocks",   "1 block",    "1 block"],
    ["IV reuse attack",             "fatal",      "fatal",      "fatal"],
    ["Pre-computable keystream",    "no",         "yes",        "yes"],
    ["Pad message to block size",   "yes",        "no",         "no"],
  ];

  return (
    <Card title="Mode comparison">
      <div className="kv-grid" style={{ gridTemplateColumns: "2fr 1fr 1fr 1fr" }}>
        {rows.map((row, i) =>
          row.map((cell, j) => (
            <span
              key={`${i}-${j}`}
              className={i === 0 ? "k" : "v"}
              style={{
                fontWeight: i === 0 ? 600 : (j === 0 ? 500 : 400),
                color: i === 0 ? "var(--text)" : (j === 0 ? "var(--text-muted)" : "var(--text)"),
              }}
            >
              {cell}
            </span>
          ))
        )}
      </div>
    </Card>
  );
}