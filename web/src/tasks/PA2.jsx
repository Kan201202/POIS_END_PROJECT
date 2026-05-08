// PA#2 — Pseudorandom Function (GGM tree).
// Covers all 5 spec deliverables:
//   1. Forward GGM PRF (PA#2a)
//   2. Backward PRG from PRF (PA#2b)
//   3. AES-PRF alternative
//   4. Distinguishing game
//   5. Avalanche / tree visualisation

import { useState, useMemo } from "react";
import { Card, Button, Output, KV, Description, Badge, ToggleGroup, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

const DEFAULT_KEY = "0123456789abcdef0123456789abcdef";
const DEFAULT_X = "ffeeddccbbaa99887766554433221100";

export default function PA2() {
  const [tab, setTab] = useState("forward");

  return (
    <div>
      <Description>
        The <b>GGM construction</b> turns any length-doubling PRG into a Pseudorandom Function.
        Given <code>G(s) = G₀(s) ‖ G₁(s)</code>, define{" "}
        <code>F_k(b₁…bₙ) = G_bₙ(… G_b₁(k) …)</code> — a root-to-leaf path through a binary tree.
        This page exercises all 5 PA#2 deliverables: forward, backward, AES alternative,
        security game, and tree visualisation.
      </Description>

      <Card title="Section">
        <ToggleGroup
          value={tab}
          onChange={setTab}
          options={[
            { label: "Forward (PRG→PRF)", value: "forward" },
            { label: "Backward (PRF→PRG)", value: "backward" },
            { label: "AES-PRF",            value: "aes" },
            { label: "Security game",      value: "game" },
            { label: "Tree trace",         value: "tree" },
          ]}
        />
      </Card>

      {tab === "forward"  && <ForwardPanel />}
      {tab === "backward" && <BackwardPanel />}
      {tab === "aes"      && <AESPanel />}
      {tab === "game"     && <GamePanel />}
      {tab === "tree"     && <TreePanel />}
    </div>
  );
}

// ─── 1. Forward: GGM PRF evaluation + avalanche ─────────────────────
function ForwardPanel() {
  const [key, setKey] = useState(DEFAULT_KEY);
  const [x, setX] = useState(DEFAULT_X);
  const [out, setOut] = useState(null);
  const [out2, setOut2] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  async function run() {
    setErr(null); setBusy(true); setOut(null); setOut2(null);
    const r = await callApi("/api/pa2/prf", { key, x });
    if (!r.ok) { setErr(r.error); setBusy(false); return; }
    setOut(r.data);

    const flipped = flipBitHex(x, 0);
    const r2 = await callApi("/api/pa2/prf", { key, x: flipped });
    if (r2.ok) setOut2({ ...r2.data, original_x: x, flipped_x: flipped });
    setBusy(false);
  }

  const avalanche = useMemo(() => {
    if (!out || !out2) return null;
    return hexHammingPercent(out.output, out2.output);
  }, [out, out2]);

  return (
    <Card title="GGM PRF evaluation" sub="F_k(x) using PRG-based tree traversal">
      <div className="row">
        <div>
          <label>Key k (hex, 16 bytes)</label>
          <input type="text" value={key} onChange={(e) => setKey(e.target.value)} />
        </div>
        <div>
          <label>Input x (hex, 16 bytes)</label>
          <input type="text" value={x} onChange={(e) => setX(e.target.value)} />
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <Button onClick={run} loading={busy}>Evaluate F_k(x) + avalanche test</Button>
      </div>

      {out && (
        <Output>
          <KV k="key"     v={out.key} />
          <KV k="x"       v={out.input} />
          <KV k="F_k(x)"  v={out.output} success />
          <KV k="scheme"  v={out.scheme} />
        </Output>
      )}

      {out2 && (
        <Output label="Avalanche test (1-bit flip in x)">
          <KV k="original x"  v={out2.original_x} />
          <KV k="flipped x"   v={out2.flipped_x} />
          <KV k="F_k(x')"     v={out2.output} />
          <KV k="bit-diff %"  v={`${avalanche?.toFixed(1)}%`} />
          <div style={{ marginTop: 6 }}>
            <Badge variant={avalanche > 35 && avalanche < 65 ? "success" : "error"}>
              {avalanche > 35 && avalanche < 65 ? "good avalanche (≈ 50%)" : "weak avalanche"}
            </Badge>
          </div>
        </Output>
      )}

      <ErrorBanner>{err}</ErrorBanner>
    </Card>
  );
}

// ─── 2. Backward: PRG from PRF ──────────────────────────────────────
function BackwardPanel() {
  const [seed, setSeed] = useState(DEFAULT_KEY);
  const [length, setLength] = useState(64);
  const [out, setOut] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  async function run() {
    setErr(null); setBusy(true); setOut(null);
    const r = await callApi("/api/pa2/prg_from_prf", { seed, length: Number(length) });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(false);
  }

  const monobitOk = out && Math.abs(out.ones_ratio - 0.5) < 0.05;

  return (
    <Card title="Backward direction — PRG from PRF" sub="G(s) = F_s(0) ‖ F_s(1) ‖ F_s(2) ‖ …">
      <div className="row">
        <div>
          <label>Seed s (hex)</label>
          <input type="text" value={seed} onChange={(e) => setSeed(e.target.value)} />
        </div>
        <div className="narrow" style={{ width: 130 }}>
          <label>Output bytes</label>
          <input type="number" min={16} max={256} value={length} onChange={(e) => setLength(e.target.value)} />
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <Button onClick={run} loading={busy}>Expand seed via PRF</Button>
      </div>
      {out && (
        <Output>
          <KV k="seed"       v={out.seed} />
          <KV k="output"     v={out.output} success />
          <KV k="length"     v={`${out.length} bytes`} />
          <KV k="ones-ratio" v={out.ones_ratio} />
          <KV k="scheme"     v={out.scheme} />
          <div style={{ marginTop: 6 }}>
            <Badge variant={monobitOk ? "success" : "error"}>
              monobit {monobitOk ? "PASS" : "FAIL"}
            </Badge>
          </div>
        </Output>
      )}
      <ErrorBanner>{err}</ErrorBanner>
    </Card>
  );
}

// ─── 3. AES-PRF alternative ─────────────────────────────────────────
function AESPanel() {
  const [key, setKey] = useState(DEFAULT_KEY);
  const [x, setX] = useState(DEFAULT_X);
  const [aes, setAes] = useState(null);
  const [ggm, setGgm] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  async function run() {
    setErr(null); setBusy(true); setAes(null); setGgm(null);
    const [a, g] = await Promise.all([
      callApi("/api/pa2/aes_prf", { key, x }),
      callApi("/api/pa2/prf",     { key, x }),
    ]);
    if (a.ok) setAes(a.data); else setErr(a.error);
    if (g.ok) setGgm(g.data); else setErr(g.error);
    setBusy(false);
  }

  return (
    <Card title="AES-PRF alternative" sub="F_k(x) = AES_k(x) — direct, faster than GGM">
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
        Shows AES-128 plugged in as a PRF in place of GGM — functionally equivalent downstream.
      </div>
      <div className="row">
        <div>
          <label>Key k (hex)</label>
          <input type="text" value={key} onChange={(e) => setKey(e.target.value)} />
        </div>
        <div>
          <label>Input x (hex)</label>
          <input type="text" value={x} onChange={(e) => setX(e.target.value)} />
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <Button onClick={run} loading={busy}>Compute both PRFs</Button>
      </div>
      {(aes || ggm) && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 10 }}>
          {aes && (
            <Output label="AES-PRF">
              <KV k="F_k(x)" v={aes.output} success />
              <KV k="scheme" v={aes.scheme} />
            </Output>
          )}
          {ggm && (
            <Output label="GGM-PRF">
              <KV k="F_k(x)" v={ggm.output} success />
              <KV k="scheme" v={ggm.scheme} />
            </Output>
          )}
        </div>
      )}
      <ErrorBanner>{err}</ErrorBanner>
    </Card>
  );
}

// ─── 4. Distinguishing game ─────────────────────────────────────────
function GamePanel() {
  const [n, setN] = useState(100);
  const [out, setOut] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  async function run() {
    setErr(null); setBusy(true); setOut(null);
    const r = await callApi("/api/pa2/distinguishing_game", { num_queries: Number(n) });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(false);
  }

  return (
    <Card title="IND-PRF distinguishing game" sub="Adversary queries PRF and a random oracle">
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
        Submits q queries to the PRF and a random function. A secure PRF should be statistically
        indistinguishable — advantage should be ≈ 0.
      </div>
      <div className="row">
        <div className="narrow" style={{ width: 160 }}>
          <label>Queries q</label>
          <input type="number" min={10} max={1000} step={10} value={n} onChange={(e) => setN(e.target.value)} />
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <Button onClick={run} loading={busy}>Run game</Button>
      </div>
      {out && (
        <Output>
          <KV k="queries"               v={out.num_queries} />
          <KV k="distinct PRF outs"     v={out.real_distinct} />
          <KV k="distinct random outs"  v={out.random_distinct} />
          <KV k="advantage"             v={out.advantage.toFixed(4)} />
          <KV k="time"                  v={`${out.time_ms} ms`} />
          <div style={{ marginTop: 6 }}>
            <Badge variant={out.advantage < 0.05 ? "success" : "error"}>
              {out.advantage < 0.05 ? "✓ indistinguishable" : "✗ distinguisher succeeded"}
            </Badge>
          </div>
        </Output>
      )}
      <ErrorBanner>{err}</ErrorBanner>
    </Card>
  );
}

// ─── 5. Tree-trace ──────────────────────────────────────────────────
function TreePanel() {
  const [key, setKey] = useState(DEFAULT_KEY);
  const [x, setX] = useState(DEFAULT_X);
  const [depth, setDepth] = useState(4);
  const [out, setOut] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  async function run() {
    setErr(null); setBusy(true); setOut(null);
    const r = await callApi("/api/pa2/tree_trace", { key, x, depth: Number(depth) });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(false);
  }

  return (
    <Card title="GGM tree path" sub="Visualises the root-to-leaf walk taken by F_k(x)">
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
        At each level i the input bit b_i picks the left (0) or right (1) child. The leaf is F_k(x).
      </div>
      <div className="row">
        <div>
          <label>Key k (hex)</label>
          <input type="text" value={key} onChange={(e) => setKey(e.target.value)} />
        </div>
        <div>
          <label>Input x (hex)</label>
          <input type="text" value={x} onChange={(e) => setX(e.target.value)} />
        </div>
        <div className="narrow" style={{ width: 110 }}>
          <label>Depth (bits)</label>
          <input type="number" min={1} max={8} value={depth} onChange={(e) => setDepth(e.target.value)} />
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <Button onClick={run} loading={busy}>Trace tree path</Button>
      </div>

      {out && (
        <div style={{ marginTop: 14 }}>
          <Output label={`x bits = ${out.x_bits}`}>
            {out.path.map((step) => (
              <div key={step.level} style={{
                marginBottom: 10, paddingBottom: 10,
                borderBottom: "1px solid var(--border)",
              }}>
                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
                  Level {step.level} — bit b<sub>{step.level}</sub> = {step.bit} (chose {step.chosen})
                </div>
                <KV k="node"  v={trunc(step.node)} />
                <KV k="left"  v={trunc(step.left)}
                    success={step.chosen === "left"} />
                <KV k="right" v={trunc(step.right)}
                    success={step.chosen === "right"} />
              </div>
            ))}
            <KV k="leaf F_k(x)" v={out.leaf} success />
          </Output>
        </div>
      )}

      <ErrorBanner>{err}</ErrorBanner>
    </Card>
  );
}

// ─── helpers ────────────────────────────────────────────────────────
function trunc(s, n = 48) {
  if (!s) return s;
  return s.length > n ? s.slice(0, n) + "…" : s;
}

function flipBitHex(hex, bitIndex) {
  const bytes = hex.match(/.{2}/g) || [];
  if (bytes.length === 0) return hex;
  const byteIdx = Math.floor(bitIndex / 8);
  const bitInByte = bitIndex % 8;
  const flipped = (parseInt(bytes[byteIdx], 16) ^ (1 << (7 - bitInByte))) & 0xff;
  bytes[byteIdx] = flipped.toString(16).padStart(2, "0");
  return bytes.join("");
}

function hexHammingPercent(a, b) {
  const ba = a.match(/.{2}/g) || [];
  const bb = b.match(/.{2}/g) || [];
  const len = Math.min(ba.length, bb.length);
  if (len === 0) return 0;
  let diff = 0;
  for (let i = 0; i < len; i++) {
    const x = parseInt(ba[i], 16) ^ parseInt(bb[i], 16);
    for (let j = 0; j < 8; j++) if (x & (1 << j)) diff++;
  }
  return (diff / (len * 8)) * 100;
}