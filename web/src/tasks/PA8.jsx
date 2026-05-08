// PA#8 — DLP Hash Live + Collision Hunt
//
// Spec:
//  • Student types a message; app computes DLP_Hash(message) and displays
//    the group element as a hex string.
//  • "Collision hunt" button runs the birthday attack (toy n = 16-bit output)
//    in the background, updating a counter of hashes evaluated, and highlights
//    the two colliding inputs when found.
//  • A progress bar shows how close the count is to 2^(n/2) = 256.
//  • Toy params: q ≈ 2^16, truncated to 16-bit output for collision demo.
//    Full-size hash shown separately.

import { useState, useRef } from "react";
import { Card, Button, Output, KV, Description, Badge, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

export default function PA8() {
  // ── Live hash panel ──────────────────────────────────────────────────────
  const [msg, setMsg]     = useState("collision-resistant hash");
  const [hashOut, setHashOut] = useState(null);
  const [hashBusy, setHashBusy] = useState(false);

  // ── Collision hunt panel ─────────────────────────────────────────────────
  const [nBits, setNBits]       = useState(16);
  const [huntOut, setHuntOut]   = useState(null);
  const [huntBusy, setHuntBusy] = useState(false);
  const [progress, setProgress] = useState(0);   // animated 0–100
  const animRef                 = useRef(null);

  const [err, setErr] = useState(null);

  // ── Live hash ──────────────────────────────────────────────────────────
  async function computeHash() {
    setErr(null); setHashBusy(true);
    const r = await callApi("/api/pa8/hash", { message: msg });
    if (r.ok) setHashOut(r.data); else setErr(r.error);
    setHashBusy(false);
  }

  // ── Collision hunt ─────────────────────────────────────────────────────
  async function runHunt() {
    setErr(null); setHuntBusy(true); setHuntOut(null); setProgress(0);
    clearInterval(animRef.current);

    // Animate progress bar while waiting (server is synchronous)
    const expected = Math.pow(2, nBits / 2);
    let fake = 0;
    animRef.current = setInterval(() => {
      fake = Math.min(fake + expected * 0.04, expected * 0.92);
      setProgress(Math.round((fake / expected) * 100));
    }, 120);

    const r = await callApi("/api/pa8/collision_hunt", { n_bits: nBits });
    clearInterval(animRef.current);

    if (r.ok) {
      setHuntOut(r.data);
      // Animate bar to final value
      const final = r.data.progress_pct;
      let cur = progress;
      const step = setInterval(() => {
        cur = Math.min(cur + 4, final);
        setProgress(cur);
        if (cur >= final) clearInterval(step);
      }, 30);
    } else {
      setErr(r.error);
    }
    setHuntBusy(false);
  }

  const expected256 = Math.pow(2, nBits / 2);

  return (
    <div>
      <Description>
        Compression function: <code>h(x, y) = g<sup>x</sup> · ĥ<sup>y</sup> mod p</code> where{" "}
        <code>log<sub>g</sub>(ĥ)</code> is unknown. Any colliding pair{" "}
        <code>(x,y) ≠ (x′,y′)</code> with equal outputs reveals the discrete log, contradicting
        DLP hardness. Plugged into the MD transform (PA#7) this gives a full CRHF. The{" "}
        <b>birthday attack</b> finds a collision in ~2<sup>n/2</sup> evaluations.
      </Description>

      {/* ── Live hash ── */}
      <Card title="DLP Hash — live">
        <label>Message</label>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
          <input
            id="pa8-message"
            type="text"
            value={msg}
            onChange={(e) => setMsg(e.target.value)}
            style={{ flex: 1 }}
          />
          <Button id="pa8-hash" onClick={computeHash} loading={hashBusy}>Hash</Button>
        </div>

        {hashOut && (
          <Output>
            <KV k="message"      v={hashOut.message} />
            <KV k="digest (hex)" v={hashOut.digest} success />
            <KV k="scheme"       v={hashOut.scheme} />
            <div style={{ display: "flex", gap: 24, flexWrap: "wrap", marginTop: 8 }}>
              <GroupParam label="p bits" value={`${hashOut.p_bits} bits`} />
              <GroupParam label="output" value={`${hashOut.out_len * 8} bits`} />
              <GroupParam label="g"      value={trunc(hashOut.g, 24)} />
              <GroupParam label="ĥ"      value={trunc(hashOut.h_hat, 24)} />
            </div>
          </Output>
        )}
      </Card>

      {/* ── Collision hunt ── */}
      <Card title="Collision hunt — birthday attack (16-bit truncation)">
        <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 12 }}>
          The DLP hash digest is <b>truncated to n bits</b> for speed. The birthday bound says a
          collision should appear after ~2<sup>n/2</sup> evaluations. For n = 16 that is{" "}
          <b>256 evaluations</b>. Click "Hunt" and watch the progress bar fill.
        </div>

        <div style={{ display: "flex", gap: 16, alignItems: "flex-end", flexWrap: "wrap" }}>
          <div style={{ width: 160 }}>
            <label>Output bits n</label>
            <input
              id="pa8-nbits"
              type="number"
              min={8}
              max={20}
              value={nBits}
              onChange={(e) => setNBits(Number(e.target.value))}
            />
          </div>
          <div style={{ fontSize: 12, color: "var(--text-muted)", paddingBottom: 6 }}>
            2<sup>n/2</sup> = {Math.round(expected256)} expected evaluations
          </div>
          <Button
            id="pa8-hunt"
            onClick={runHunt}
            loading={huntBusy}
            variant={huntOut?.found ? "secondary" : "primary"}
          >
            {huntOut?.found ? "Hunt again" : "Hunt collision"}
          </Button>
        </div>

        {/* Progress bar */}
        {(huntBusy || huntOut) && (
          <div style={{ marginTop: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
              <span>Evaluations</span>
              <span>
                {huntOut ? huntOut.evals : "…"} / {Math.round(expected256)} expected
                {" "}({progress}%)
              </span>
            </div>
            <div style={{
              height: 12, borderRadius: 6,
              background: "rgba(99,179,237,0.12)",
              border: "1px solid rgba(99,179,237,0.25)",
              overflow: "hidden",
            }}>
              <div style={{
                height: "100%",
                width: `${Math.min(progress, 100)}%`,
                background: huntOut?.found
                  ? "linear-gradient(90deg,#48bb78,#68d391)"
                  : "linear-gradient(90deg,#63b3ed,#90cdf4)",
                borderRadius: 6,
                transition: "width 0.15s ease",
              }} />
            </div>
          </div>
        )}

        {/* Collision result */}
        {huntOut && (
          <Output style={{ marginTop: 16 }}>
            {huntOut.found ? (
              <>
                <Badge variant="error">
                  🎉 Collision found in {huntOut.evals} evaluations!
                </Badge>

                <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginTop: 12 }}>
                  <CollisionBox
                    label="Input 1"
                    input={huntOut.x1_hex}
                    hash={huntOut.h1_hex}
                    highlight
                  />
                  <CollisionBox
                    label="Input 2"
                    input={huntOut.x2_hex}
                    hash={huntOut.h2_hex}
                    highlight
                  />
                </div>

                <div style={{ marginTop: 12, fontSize: 12, color: "var(--text-muted)" }}>
                  Both inputs hash to <code style={{ color: "var(--accent)" }}>{huntOut.h1_hex}</code>{" "}
                  under the {nBits}-bit truncated DLP hash.
                  Expected evaluations: <b>{huntOut.expected_evals}</b> (2<sup>{nBits}/2</sup>).
                  Actual: <b>{huntOut.evals}</b>. Time: <b>{huntOut.time_ms} ms</b>.
                </div>
              </>
            ) : (
              <Badge variant="error">No collision found within {huntOut.evals} evaluations.</Badge>
            )}
          </Output>
        )}
      </Card>

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function GroupParam({ label, value }) {
  return (
    <div style={{ fontSize: 11 }}>
      <span style={{ color: "var(--text-muted)", marginRight: 4 }}>{label}:</span>
      <code style={{ fontSize: 11 }}>{value}</code>
    </div>
  );
}

function CollisionBox({ label, input, hash, highlight }) {
  return (
    <div style={{
      flex: 1, minWidth: 180,
      border: highlight ? "1px solid rgba(246,173,85,0.6)" : "1px solid var(--border)",
      background: highlight ? "rgba(246,173,85,0.08)" : "transparent",
      borderRadius: 8, padding: "10px 14px",
    }}>
      <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6 }}>{label}</div>
      <div style={{ fontFamily: "monospace", fontSize: 12, marginBottom: 4 }}>
        <span style={{ color: "var(--text-muted)" }}>x = </span>
        <span style={{ color: "var(--text)" }}>{input}</span>
      </div>
      <div style={{ fontFamily: "monospace", fontSize: 12 }}>
        <span style={{ color: "var(--text-muted)" }}>H(x) = </span>
        <span style={{ color: "var(--accent)", fontWeight: 600 }}>{hash}</span>
      </div>
    </div>
  );
}

function trunc(s, n) {
  if (!s) return s;
  return s.length > n ? s.slice(0, n) + "…" : s;
}
