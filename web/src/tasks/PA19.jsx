// PA#19 — Secure AND gate step-by-step (via OT)
//
// Spec:
//  • Alice panel: student enters bit a ∈ {0,1}.
//  • Bob panel: student enters bit b ∈ {0,1}.
//  • Click "Compute AND." Step-log shows:
//    Alice sets up OT messages (0, a), Bob runs OT receiver with choice b,
//    Bob receives m_b = a ∧ b.
//  • Transcript (all messages exchanged) is shown.
//  • "What does Alice learn?" / "What does Bob learn?" summary confirms neither
//    party sees the other's input.
//  • "Run all 4" button confirms correct AND output for all (a,b) combinations.

import { useState } from "react";
import { Card, Button, Output, KV, Description, Badge, ToggleGroup, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

const ACTOR_COLOR = {
  "Alice":     "#f6ad55",
  "Bob":       "#63b3ed",
  "Bob→Alice": "#b794f4",
  "Alice→Bob": "#68d391",
  "Both":      "#a0aec0",
};

function LogRow({ step }) {
  const color = ACTOR_COLOR[step.actor] || "#aaa";
  return (
    <div style={{ display: "flex", gap: 10, padding: "7px 0",
      borderTop: "1px solid var(--border)" }}>
      <div style={{ width: 76, flexShrink: 0, fontFamily: "monospace",
        fontSize: 11, color, fontWeight: 700, paddingTop: 1 }}>
        {step.actor}
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 12, color: "var(--text)" }}>{step.desc}</div>
        {step.detail && (
          <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "monospace",
            marginTop: 3, whiteSpace: "pre-wrap" }}>
            {step.detail}
          </div>
        )}
      </div>
    </div>
  );
}

function TranscriptRow({ msg }) {
  const fromColor = ACTOR_COLOR[msg.from] || "#aaa";
  const toColor   = ACTOR_COLOR[msg.to]   || "#aaa";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8,
      padding: "5px 0", borderTop: "1px solid var(--border)", fontSize: 12 }}>
      <span style={{ color: fromColor, fontWeight: 700, minWidth: 44 }}>{msg.from}</span>
      <span style={{ color: "var(--text-muted)" }}>→</span>
      <span style={{ color: toColor, fontWeight: 700, minWidth: 44 }}>{msg.to}</span>
      <span style={{ color: "var(--text-muted)", marginLeft: 4 }}>{msg.msg}</span>
    </div>
  );
}

export default function PA19() {
  const [gate, setGate]   = useState("AND");
  const [a, setA]         = useState(1);
  const [b, setB]         = useState(1);
  const [out, setOut]     = useState(null);
  const [table, setTable] = useState(null);
  const [busy, setBusy]   = useState(null);
  const [err, setErr]     = useState(null);

  async function compute() {
    setErr(null); setBusy("run"); setOut(null); setTable(null);
    const r = await callApi("/api/pa19/and", { a, b, gate });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(null);
  }

  async function runAll() {
    setErr(null); setBusy("all"); setOut(null); setTable(null);
    const r = await callApi("/api/pa19/run_all", { gate });
    if (r.ok) setTable(r.data); else setErr(r.error);
    setBusy(null);
  }

  return (
    <div>
      <Description>
        <b>Secure AND</b> uses a 1-of-2 OT call: Alice (sender) holds messages{" "}
        <code>(m0=0, m1=a)</code>. Bob (receiver) picks choice bit <code>b</code> and
        receives <code>m_b = a ∧ b</code> — <b>without Alice learning b</b> and without
        Bob learning <code>a</code> when <code>b=0</code>. XOR and NOT are free (no communication).
      </Description>

      {/* ── Gate selector ── */}
      <Card title="Choose gate">
        <ToggleGroup value={gate} onChange={(v) => { setGate(v); setOut(null); setTable(null); }}
          options={[
            { label: "AND", value: "AND" },
            { label: "XOR", value: "XOR" },
            { label: "NOT", value: "NOT" },
          ]} />
        <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 8 }}>
          {gate === "AND" && "Uses OT — full 6-step protocol with message transcript."}
          {gate === "XOR" && "Free — additive secret sharing, no communication needed."}
          {gate === "NOT" && "Local — Alice flips her bit, no Bob involvement."}
        </div>
      </Card>

      {/* ── Alice / Bob input panels ── */}
      <div className="row" style={{ alignItems: "flex-start", gap: 12 }}>
        <Card title="🟡 Alice — Her bit (a)" style={{ flex: 1 }}>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
            Alice's input. {gate === "AND"
              ? "She sets up OT messages (0, a) — Bob never learns a directly."
              : gate === "NOT" ? "NOT is local — only Alice is involved."
              : "XOR is free — result computed locally by both parties."}
          </div>
          <ToggleGroup id="pa19-alice-bit" value={a} onChange={(v) => { setA(v); setOut(null); }}
            options={[{ label: "0", value: 0 }, { label: "1", value: 1 }]} />
        </Card>

        {gate !== "NOT" && (
          <Card title="🔵 Bob — His bit (b)" style={{ flex: 1 }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
              Bob's input. {gate === "AND"
                ? "He uses b as his OT choice bit — Alice never learns b."
                : "XOR is free — result computed locally by both parties."}
            </div>
            <ToggleGroup id="pa19-bob-bit" value={b} onChange={(v) => { setB(v); setOut(null); }}
              options={[{ label: "0", value: 0 }, { label: "1", value: 1 }]} />
          </Card>
        )}
      </div>

      {/* ── Run buttons ── */}
      <Card title={`Compute ${gate}`}>
        <div style={{ display: "flex", gap: 10 }}>
          <Button id="pa19-compute" onClick={compute} loading={busy === "run"}>
            Compute {gate}
          </Button>
          <Button id="pa19-run-all" onClick={runAll} loading={busy === "all"} variant="secondary">
            Run all {gate === "NOT" ? "2" : "4"} combinations
          </Button>
        </div>

        {/* Single result */}
        {out && !table && (
          <>
            {/* Result badge */}
            <div style={{ marginTop: 14, padding: "12px 16px", borderRadius: 8,
              background: "rgba(72,187,120,0.10)", border: "1px solid rgba(72,187,120,0.4)" }}>
              <div style={{ fontWeight: 700, fontSize: 15 }}>
                {out.a} {out.gate} {out.b ?? ""} = <span style={{ color: "#68d391" }}>{out.output}</span>
              </div>
              <Badge variant={out.correct !== false ? "success" : "error"} style={{ marginTop: 6 }}>
                {out.correct !== false ? "✓ Correct output" : "✗ Mismatch"}
              </Badge>
            </div>

            {/* Step log (AND only) */}
            {out.log?.length > 1 && (
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>Protocol log</div>
                {out.log.map((s) => <LogRow key={s.step} step={s} />)}
              </div>
            )}

            {/* Transcript */}
            {out.transcript?.length > 0 && (
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
                  Message transcript (all messages exchanged)
                </div>
                {out.transcript.map((t, i) => <TranscriptRow key={i} msg={t} />)}
              </div>
            )}

            {/* Privacy summary */}
            <div style={{ marginTop: 14, display: "flex", gap: 10, flexWrap: "wrap" }}>
              <div style={{ flex: 1, minWidth: 180, padding: "10px 14px", borderRadius: 8,
                background: "rgba(246,173,85,0.08)", border: "1px solid rgba(246,173,85,0.3)" }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "#f6ad55",
                  marginBottom: 4 }}>What does Alice learn?</div>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  {out.alice_learns}
                </div>
              </div>
              <div style={{ flex: 1, minWidth: 180, padding: "10px 14px", borderRadius: 8,
                background: "rgba(99,179,237,0.08)", border: "1px solid rgba(99,179,237,0.3)" }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "#63b3ed",
                  marginBottom: 4 }}>What does Bob learn?</div>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  {out.bob_learns}
                </div>
              </div>
            </div>
          </>
        )}

        {/* Truth table */}
        {table && (
          <div style={{ marginTop: 14 }}>
            <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>
              {table.gate} truth table — all {table.rows.length} combinations
            </div>
            <table style={{ width: "auto", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ color: "var(--text-muted)", fontSize: 11 }}>
                  <th style={{ textAlign: "center", padding: "4px 14px",
                    borderBottom: "1px solid var(--border)" }}>a</th>
                  {gate !== "NOT" && (
                    <th style={{ textAlign: "center", padding: "4px 14px",
                      borderBottom: "1px solid var(--border)" }}>b</th>
                  )}
                  <th style={{ textAlign: "center", padding: "4px 14px",
                    borderBottom: "1px solid var(--border)" }}>Output</th>
                  <th style={{ textAlign: "center", padding: "4px 14px",
                    borderBottom: "1px solid var(--border)" }}>Expected</th>
                  <th style={{ textAlign: "center", padding: "4px 14px",
                    borderBottom: "1px solid var(--border)" }}>✓</th>
                </tr>
              </thead>
              <tbody>
                {table.rows.map((row, i) => (
                  <tr key={i} style={{
                    background: row.match ? "rgba(72,187,120,0.04)" : "rgba(252,129,129,0.08)"
                  }}>
                    <td style={{ textAlign: "center", padding: "5px 14px",
                      fontFamily: "monospace", fontWeight: 700 }}>{row.a}</td>
                    {gate !== "NOT" && (
                      <td style={{ textAlign: "center", padding: "5px 14px",
                        fontFamily: "monospace", fontWeight: 700 }}>{row.b ?? "—"}</td>
                    )}
                    <td style={{ textAlign: "center", padding: "5px 14px",
                      fontFamily: "monospace", fontWeight: 700,
                      color: "#68d391" }}>{row.output}</td>
                    <td style={{ textAlign: "center", padding: "5px 14px",
                      fontFamily: "monospace", color: "var(--text-muted)" }}>{row.expected}</td>
                    <td style={{ textAlign: "center", padding: "5px 14px" }}>
                      {row.match ? "✓" : "✗"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Badge variant={table.all_correct ? "success" : "error"} style={{ marginTop: 10 }}>
              {table.all_correct
                ? `✓ All ${table.rows.length} cases correct — ${table.gate} truth table verified!`
                : "✗ Some cases failed (unexpected)"}
            </Badge>
          </div>
        )}
      </Card>

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}
