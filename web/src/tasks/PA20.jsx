// PA#20 — Millionaire's Problem (2-Party Secure Comparison)
//
// Spec:
//  • Alice panel: slider for her wealth x (1-15, hidden from Bob's panel).
//  • Bob panel: slider for his wealth y (1-15, hidden from Alice's panel).
//  • Click "Who is richer?" — comparison circuit evaluates gate-by-gate,
//    progress bar shows gates completed.
//  • Result: "Alice is richer" / "Bob is richer" / "Equal" shown to both.
//    Actual values x and y are never revealed across panels.
//  • "Circuit trace" expandable section shows AND/XOR/NOT gates with
//    input wire values and output wire values.

import { useState, useEffect, useRef } from "react";
import { Card, Button, Description, Badge, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

const GATE_COLOR = { AND: "#63b3ed", XOR: "#f6ad55", NOT: "#b794f4" };

function GateRow({ g }) {
  return (
    <tr style={{ fontSize: 11, fontFamily: "monospace" }}>
      <td style={{ padding: "2px 6px", color: "var(--text-muted)" }}>{g.idx}</td>
      <td style={{ padding: "2px 6px" }}>
        <span style={{ color: GATE_COLOR[g.type] || "#aaa",
          fontWeight: 700, padding: "1px 6px", borderRadius: 4,
          background: (GATE_COLOR[g.type] || "#aaa") + "22" }}>
          {g.type}
        </span>
      </td>
      <td style={{ padding: "2px 6px", color: "var(--text-muted)" }}>w{g.w_in1}</td>
      <td style={{ padding: "2px 6px", fontWeight: 700 }}>{g.in1}</td>
      <td style={{ padding: "2px 6px", color: "var(--text-muted)" }}>
        {g.w_in2 != null ? `w${g.w_in2}` : "—"}
      </td>
      <td style={{ padding: "2px 6px", fontWeight: 700 }}>
        {g.in2 != null ? g.in2 : "—"}
      </td>
      <td style={{ padding: "2px 6px", color: "var(--text-muted)" }}>w{g.w_out}</td>
      <td style={{ padding: "2px 6px", fontWeight: 700, color: "#68d391" }}>{g.out}</td>
    </tr>
  );
}

export default function PA20() {
  const [x, setX] = useState(7);
  const [y, setY] = useState(12);
  const [out, setOut] = useState(null);
  const [progress, setProgress] = useState(0);   // animated gate count
  const [showTrace, setShowTrace] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const animRef = useRef(null);

  // Animate progress bar gate by gate
  function animateGates(total) {
    setProgress(0);
    let i = 0;
    const step = () => {
      i += 1;
      setProgress(i);
      if (i < total) {
        animRef.current = setTimeout(step, 18);   // ~18ms per gate
      }
    };
    animRef.current = setTimeout(step, 50);
  }

  useEffect(() => () => clearTimeout(animRef.current), []);

  async function run() {
    setErr(null); setBusy(true); setOut(null); setProgress(0); setShowTrace(false);
    const r = await callApi("/api/pa20/millionaires", { x: Number(x), y: Number(y) });
    if (r.ok) {
      setOut(r.data);
      animateGates(r.data.n_gates);
    } else {
      setErr(r.error);
    }
    setBusy(false);
  }

  const winnerColor = out?.richer === "Alice" ? "#f6ad55"
                    : out?.richer === "Bob"   ? "#63b3ed"
                    : "#68d391";

  const pct = out ? Math.round((progress / out.n_gates) * 100) : 0;

  return (
    <div>
      <Description>
        <b>Millionaire's Problem</b>: Alice and Bob each hold a private wealth value.
        A 4-bit ripple-carry comparator circuit determines who is richer using only
        AND, XOR, and NOT gates — <b>without either party revealing their actual value</b>.
        Toy parameters: n = 4-bit comparison (16 possible values, 1–15). Fast enough
        to animate gate-by-gate.
      </Description>

      {/* ── Side-by-side panels ── */}
      <div className="row" style={{ alignItems: "flex-start", gap: 12 }}>

        {/* Alice's panel */}
        <Card title="🟡 Alice — Her Wealth (x)" style={{ flex: 1 }}>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
            Alice's value is <b>hidden from Bob's panel</b>. Only the comparison result
            is revealed to both.
          </div>
          <label style={{ fontSize: 13 }}>
            x = <b style={{ color: "#f6ad55", fontSize: 15 }}>{x}</b>
            <span style={{ color: "var(--text-muted)", fontSize: 11, marginLeft: 8 }}>
              (binary: {x.toString(2).padStart(4, "0")})
            </span>
          </label>
          <input id="pa20-alice-slider" type="range" min={1} max={15} value={x}
            onChange={(e) => { setX(Number(e.target.value)); setOut(null); setProgress(0); }}
            style={{ width: "100%", marginTop: 6, accentColor: "#f6ad55" }} />
          <div style={{ display: "flex", justifyContent: "space-between",
            fontSize: 10, color: "var(--text-muted)" }}>
            <span>1</span><span>8</span><span>15</span>
          </div>
          {out && (
            <div style={{ marginTop: 10, fontSize: 11, color: "var(--text-muted)" }}>
              x bits (MSB first): [
                <span style={{ color: "#f6ad55", fontFamily: "monospace" }}>
                  {out.x_bits.join(", ")}
                </span>
              ] — Alice's input wires
            </div>
          )}
        </Card>

        {/* Bob's panel */}
        <Card title="🔵 Bob — His Wealth (y)" style={{ flex: 1 }}>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
            Bob's value is <b>hidden from Alice's panel</b>. Only the comparison result
            is revealed to both.
          </div>
          <label style={{ fontSize: 13 }}>
            y = <b style={{ color: "#63b3ed", fontSize: 15 }}>{y}</b>
            <span style={{ color: "var(--text-muted)", fontSize: 11, marginLeft: 8 }}>
              (binary: {y.toString(2).padStart(4, "0")})
            </span>
          </label>
          <input id="pa20-bob-slider" type="range" min={1} max={15} value={y}
            onChange={(e) => { setY(Number(e.target.value)); setOut(null); setProgress(0); }}
            style={{ width: "100%", marginTop: 6, accentColor: "#63b3ed" }} />
          <div style={{ display: "flex", justifyContent: "space-between",
            fontSize: 10, color: "var(--text-muted)" }}>
            <span>1</span><span>8</span><span>15</span>
          </div>
          {out && (
            <div style={{ marginTop: 10, fontSize: 11, color: "var(--text-muted)" }}>
              y bits (MSB first): [
                <span style={{ color: "#63b3ed", fontFamily: "monospace" }}>
                  {out.y_bits.join(", ")}
                </span>
              ] — Bob's input wires
            </div>
          )}
        </Card>
      </div>

      {/* ── Evaluate button ── */}
      <Card title="Secure Comparison Circuit">
        <Button id="pa20-run" onClick={run} loading={busy}>
          Who is richer?
        </Button>

        {/* Progress bar */}
        {out && (
          <div style={{ marginTop: 14 }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
              Circuit evaluation: {progress} / {out.n_gates} gates
              <span style={{ marginLeft: 8, color: pct === 100 ? "#68d391" : "var(--accent)" }}>
                ({pct}%)
              </span>
            </div>
            <div style={{ height: 10, borderRadius: 5, background: "var(--surface2)",
              overflow: "hidden" }}>
              <div style={{
                height: "100%", borderRadius: 5,
                width: `${pct}%`,
                background: `linear-gradient(90deg, var(--accent), ${winnerColor})`,
                transition: "width 0.08s linear",
              }} />
            </div>
          </div>
        )}

        {/* Result banner */}
        {out && pct === 100 && (
          <div style={{
            marginTop: 16, padding: "16px 20px", borderRadius: 10,
            background: winnerColor + "18",
            border: `2px solid ${winnerColor}55`,
            textAlign: "center",
          }}>
            <div style={{ fontSize: 22, fontWeight: 800, color: winnerColor }}>
              {out.richer === "Equal"
                ? "🤝 Equal wealth"
                : `${out.richer} is richer`}
            </div>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 6 }}>
              {out.richer === "Equal"
                ? "x = y (circuit outputs Eq=1)"
                : `Circuit output: ${out.richer === "Alice" ? "GT=1, Eq=0" : "GT=0, Eq=0"}`}
            </div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
              ✓ Actual values x = {x} and y = {y} are only visible in their respective panels.
              In a real MPC protocol, inputs would be secret-shared and neither party would see them.
            </div>
          </div>
        )}
      </Card>

      {/* ── Circuit trace (expandable) ── */}
      {out && (
        <Card title="Circuit trace (AND/XOR/NOT gates)">
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
            Shows each gate's type, input wire IDs, input values, output wire ID, and output value.
            Input wires of the <i>other party</i> are not labelled — only wire numbers are shown.
          </div>
          <button onClick={() => setShowTrace(!showTrace)}
            style={{ background: "none", border: "1px solid var(--border)",
              borderRadius: 6, padding: "4px 12px", cursor: "pointer",
              color: "var(--text)", fontSize: 12 }}>
            {showTrace ? "▲ Hide" : "▼ Show"} {out.n_gates} gates
          </button>

          {showTrace && (
            <div style={{ marginTop: 10, overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ fontSize: 11, color: "var(--text-muted)",
                    borderBottom: "1px solid var(--border)" }}>
                    <th style={{ textAlign: "left", padding: "2px 6px" }}>#</th>
                    <th style={{ textAlign: "left", padding: "2px 6px" }}>Gate</th>
                    <th style={{ textAlign: "left", padding: "2px 6px" }}>Wire A</th>
                    <th style={{ textAlign: "left", padding: "2px 6px" }}>A val</th>
                    <th style={{ textAlign: "left", padding: "2px 6px" }}>Wire B</th>
                    <th style={{ textAlign: "left", padding: "2px 6px" }}>B val</th>
                    <th style={{ textAlign: "left", padding: "2px 6px" }}>Wire Out</th>
                    <th style={{ textAlign: "left", padding: "2px 6px" }}>Out val</th>
                  </tr>
                </thead>
                <tbody>
                  {out.gates.map((g) => <GateRow key={g.idx} g={g} />)}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}
