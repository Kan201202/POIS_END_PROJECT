// PA#18 — 1-of-2 Oblivious Transfer (OT)
//
// Spec:
//  • Alice's panel (left, greyed out): holds two messages m0 and m1, hidden.
//  • Bob's panel (right, interactive): student clicks "Choose 0" or "Choose 1."
//  • OT protocol runs step-by-step with a message log showing:
//    key pairs generated, (pk0, pk1) sent to Alice, C0 and C1 received, C_b decrypted.
//  • Result: m_b is revealed. m_{1-b} remains hidden (shown as "??").
//  • "Cheat attempt" button tries to decrypt C_{1-b} and shows the failure.

import { useState } from "react";
import { Card, Button, Output, KV, Description, Badge, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

const DEFAULT_M0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";   // 16 bytes hex
const DEFAULT_M1 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

function trunc(s, n = 42) {
  return s && String(s).length > n ? String(s).slice(0, n) + "…" : String(s);
}

// One row in the step log
function LogRow({ step }) {
  const actorColor = step.actor === "Alice" ? "#f6ad55"
                   : step.actor === "Bob"   ? "#63b3ed"
                   : "#b794f4";
  return (
    <div style={{ display: "flex", gap: 10, padding: "6px 0",
      borderTop: "1px solid var(--border)" }}>
      <div style={{ width: 70, flexShrink: 0, fontFamily: "monospace",
        fontSize: 11, color: actorColor, fontWeight: 600 }}>
        {step.actor}
      </div>
      <div style={{ fontSize: 12 }}>
        <div style={{ color: "var(--text)" }}>{step.desc}</div>
        {step.detail && (
          <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "monospace",
            marginTop: 2, whiteSpace: "pre-wrap" }}>
            {step.detail}
          </div>
        )}
      </div>
    </div>
  );
}

export default function PA18() {
  const [m0,   setM0]   = useState(DEFAULT_M0.slice(0, 32));
  const [m1,   setM1]   = useState(DEFAULT_M1.slice(0, 32));
  const [b,    setB]    = useState(0);
  const [out,  setOut]  = useState(null);
  const [showCheat, setShowCheat] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err,  setErr]  = useState(null);

  async function runOT(choice) {
    setErr(null); setBusy(true); setOut(null); setShowCheat(false);
    setB(choice);
    // pad to 16 bytes if needed
    const pad = (h) => h.padEnd(32, "0").slice(0, 32);
    const r = await callApi("/api/pa18/ot", { b: choice, m0: pad(m0), m1: pad(m1) });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(false);
  }

  return (
    <div>
      <Description>
        <b>1-of-2 Oblivious Transfer</b>: Alice holds <code>(m₀, m₁)</code>. Bob picks
        choice bit <code>b</code> and learns only <code>m_b</code>. Alice never learns
        which message Bob chose. Bob cannot decrypt the unchosen message even with a
        "cheat attempt" — the fake pk guarantees this.
      </Description>

      {/* ── Side-by-side Alice / Bob panels ── */}
      <div className="row" style={{ alignItems: "flex-start", gap: 12 }}>

        {/* Alice's panel (greyed out — holds the secrets) */}
        <Card title="🟡 Alice — Sender" style={{ flex: 1, opacity: out ? 0.7 : 1 }}>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
            Alice holds two messages. They are hidden from Bob until the OT completes.
          </div>
          <label>m₀ (16 bytes, hex)</label>
          <input type="text" value={m0} onChange={(e) => { setM0(e.target.value); setOut(null); }}
            placeholder="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" />
          <label style={{ marginTop: 8 }}>m₁ (16 bytes, hex)</label>
          <input type="text" value={m1} onChange={(e) => { setM1(e.target.value); setOut(null); }}
            placeholder="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" />

          {out && (
            <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 6 }}>
              <div style={{ fontSize: 12 }}>
                <span style={{ color: "var(--text-muted)" }}>Alice sees m₀: </span>
                <code style={{ color: b === 0 ? "#68d391" : "#fc8181" }}>
                  {b === 0 ? trunc(m0) : "?? (hidden from viewer)"}
                </code>
              </div>
              <div style={{ fontSize: 12 }}>
                <span style={{ color: "var(--text-muted)" }}>Alice sees m₁: </span>
                <code style={{ color: b === 1 ? "#68d391" : "#fc8181" }}>
                  {b === 1 ? trunc(m1) : "?? (hidden from viewer)"}
                </code>
              </div>
            </div>
          )}
        </Card>

        {/* Bob's panel (interactive) */}
        <Card title="🔵 Bob — Receiver" style={{ flex: 1 }}>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 12 }}>
            Bob picks a choice bit. He will receive exactly one message. The other stays hidden.
          </div>
          <div style={{ display: "flex", gap: 10, marginBottom: 12 }}>
            {[0, 1].map((choice) => (
              <button key={choice} id={`pa18-choose-${choice}`}
                onClick={() => runOT(choice)}
                disabled={busy}
                style={{
                  flex: 1, padding: "10px 0", borderRadius: 8, cursor: "pointer",
                  fontSize: 14, fontWeight: 700,
                  border: `2px solid ${b === choice && out ? "var(--accent)" : "var(--border)"}`,
                  background: b === choice && out ? "var(--accent)" : "var(--surface2)",
                  color: b === choice && out ? "#fff" : "var(--text)",
                  opacity: busy ? 0.6 : 1,
                }}>
                {busy && b === choice ? "Running…" : `Choose ${choice}`}
              </button>
            ))}
          </div>

          {out && (
            <>
              {/* What Bob receives */}
              <div style={{ padding: "10px 14px", borderRadius: 8, marginBottom: 8,
                background: "rgba(72,187,120,0.10)",
                border: "1px solid rgba(72,187,120,0.4)" }}>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  Bob receives m_{out.choice}:
                </div>
                <div style={{ fontFamily: "monospace", fontSize: 13, color: "#68d391",
                  marginTop: 4, fontWeight: 600 }}>
                  {out.result.received}
                </div>
                <Badge variant={out.result.match ? "success" : "error"} style={{ marginTop: 6 }}>
                  {out.result.match ? `✓ Correct — m${out.choice} delivered` : "✗ Mismatch"}
                </Badge>
              </div>

              {/* Unchosen message — hidden */}
              <div style={{ padding: "10px 14px", borderRadius: 8,
                background: "rgba(252,129,129,0.06)",
                border: "1px solid rgba(252,129,129,0.3)" }}>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  m_{1 - out.choice} (unchosen):
                </div>
                <div style={{ fontFamily: "monospace", fontSize: 13, color: "#fc8181",
                  marginTop: 4, fontWeight: 600, letterSpacing: 2 }}>
                  ?? (hidden — OT protocol enforces this)
                </div>
              </div>
            </>
          )}
        </Card>
      </div>

      {/* ── Protocol step log ── */}
      {out && (
        <Card title="Protocol message log">
          {out.log.map((s) => <LogRow key={s.step} step={s} />)}
        </Card>
      )}

      {/* ── Cheat attempt ── */}
      {out && (
        <Card title="Cheat attempt — Bob tries to decrypt the unchosen message">
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
            Bob applies <code>sk_real</code> (his real secret key) to decrypt{" "}
            <code>C_{'{'}1-b{'}'}</code> — the ciphertext he was NOT meant to receive.
            The unchosen message was encrypted under a <b>fake pk</b>, so sk_real produces garbage.
          </div>
          <Button id="pa18-cheat" onClick={() => setShowCheat(true)} variant="secondary">
            Cheat attempt: Dec(C_{1 - out.choice}, sk_real)
          </Button>

          {showCheat && (
            <Output style={{ marginTop: 10 }}>
              <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 6 }}>
                {out.cheat.desc}
              </div>
              <KV k="Cheat result (hex)" v={trunc(out.cheat.result)} />
              <KV k={`Expected m${1 - out.choice}`} v={out.choice === 0 ? trunc(m1) : trunc(m0)} />
              <Badge variant={out.cheat.correct ? "error" : "success"} style={{ marginTop: 8 }}>
                {out.cheat.correct
                  ? "⚠ Cheat succeeded (unexpected!)"
                  : `✓ Cheat failed — garbage output, m${1 - out.choice} remains hidden`}
              </Badge>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
                {out.cheat.note}
              </div>
            </Output>
          )}
        </Card>
      )}

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}
