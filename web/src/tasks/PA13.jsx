// PA#13 — Miller-Rabin Primality Tester
//
// Spec:
//  • Number input field (up to 20 digits).
//  • "Rounds" slider k = 1–40.
//  • Click "Test" → shows PRIME or COMPOSITE, time taken, and list of witnesses
//    a_i tested with their computed values at each round.
//  • Pre-loaded examples: 561 (Carmichael), a known 512-bit prime, a known
//    composite — click for instant demo.
//  • 561 must return COMPOSITE after 1+ rounds (despite passing Fermat).

import { useState } from "react";
import { Card, Button, Output, KV, Description, Badge, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

function trunc(s, n = 72) {
  return s && String(s).length > n ? String(s).slice(0, n) + "…" : String(s);
}

// Known 512-bit prime (2^521 - 1 is Mersenne but huge; use a well-known 512-bit prime)
const PRIME_512 =
  "13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171";

const PRESETS = [
  {
    label: "561",
    sub: "Carmichael — passes Fermat, caught by MR",
    value: "561",
    kind: "composite",
  },
  {
    label: "7 919",
    sub: "Known prime",
    value: "7919",
    kind: "prime",
  },
  {
    label: "2¹²⁸ − 1",
    sub: "Known composite (not Mersenne prime)",
    value: String(BigInt(2) ** BigInt(128) - BigInt(1)),
    kind: "composite",
  },
  {
    label: "512-bit prime",
    sub: "Large known prime",
    value: PRIME_512,
    kind: "prime",
  },
  {
    label: "2¹²⁷ − 1",
    sub: "Mersenne prime (M₁₂₇)",
    value: String(BigInt(2) ** BigInt(127) - BigInt(1)),
    kind: "prime",
  },
];

export default function PA13() {
  const [n,      setN]      = useState("561");
  const [rounds, setRounds] = useState(5);
  const [out,    setOut]    = useState(null);
  const [bits,   setBits]   = useState(128);
  const [genOut, setGenOut] = useState(null);
  const [busy,   setBusy]   = useState(null);
  const [err,    setErr]    = useState(null);

  async function test() {
    setErr(null); setBusy("t"); setOut(null);
    const r = await callApi("/api/pa13/test", { n, rounds: Number(rounds) });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(null);
  }

  async function gen() {
    setErr(null); setBusy("g"); setGenOut(null);
    const r = await callApi("/api/pa13/genprime", { bits: Number(bits) });
    if (r.ok) setGenOut(r.data); else setErr(r.error);
    setBusy(null);
  }

  const isPrime = out?.is_prime;

  return (
    <div>
      <Description>
        <b>Miller-Rabin</b> is a fast probabilistic primality test. Each round picks a random
        witness <code>a</code>, computes <code>a^d mod n</code> (where <code>n−1 = 2^s · d</code>),
        then squares up to <code>s−1</code> times looking for <code>n−1</code>. Any round that
        finds a witness proving compositeness is <b>definitive</b>. After k rounds the
        false-positive rate is ≤ 4<sup>−k</sup>. Carmichael numbers (e.g., 561) fool Fermat
        but are caught here.
      </Description>

      {/* ── Input ── */}
      <Card title="Primality tester">
        <label>Integer n (up to ~20 digits)</label>
        <input
          id="pa13-n"
          type="text"
          value={n}
          onChange={(e) => setN(e.target.value.replace(/[^0-9]/g, ""))}
          placeholder="Enter any positive integer…"
          style={{ fontFamily: "monospace" }}
        />

        {/* Preset buttons */}
        <div style={{ marginTop: 8, display: "flex", gap: 6, flexWrap: "wrap" }}>
          {PRESETS.map((p) => (
            <button
              key={p.value}
              onClick={() => { setN(p.value); setOut(null); }}
              title={p.sub}
              style={{
                padding: "4px 10px", borderRadius: 6, cursor: "pointer",
                fontSize: 12, border: "1px solid var(--border)",
                background: p.kind === "prime"
                  ? "rgba(72,187,120,0.12)" : "rgba(252,129,129,0.12)",
                color: p.kind === "prime" ? "#68d391" : "#fc8181",
              }}
            >
              {p.label}
            </button>
          ))}
        </div>
        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4, marginBottom: 10 }}>
          {PRESETS.find(p => p.value === n)?.sub || ""}
        </div>

        {/* Rounds slider */}
        <div style={{ marginBottom: 14 }}>
          <label style={{ display: "flex", justifyContent: "space-between" }}>
            <span>Rounds k</span>
            <span style={{ fontFamily: "monospace", color: "var(--accent)" }}>
              k = {rounds} &nbsp;|&nbsp; error ≤ 4<sup>−{rounds}</sup>
            </span>
          </label>
          <input
            id="pa13-rounds"
            type="range" min={1} max={40} step={1} value={rounds}
            onChange={(e) => setRounds(Number(e.target.value))}
            style={{ width: "100%", marginTop: 4 }}
          />
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--text-muted)" }}>
            <span>1</span><span>10</span><span>20</span><span>30</span><span>40</span>
          </div>
        </div>

        <Button id="pa13-test" onClick={test} loading={busy === "t"}>
          Test primality
        </Button>

        {/* ── Result ── */}
        {out && (
          <>
            {/* Big verdict banner */}
            <div style={{
              marginTop: 14, padding: "14px 20px", borderRadius: 10,
              background: isPrime
                ? "rgba(72,187,120,0.10)" : "rgba(252,129,129,0.10)",
              border: `1px solid ${isPrime ? "rgba(72,187,120,0.4)" : "rgba(252,129,129,0.4)"}`,
              display: "flex", alignItems: "center", gap: 14,
            }}>
              <span style={{ fontSize: 28 }}>{isPrime ? "✅" : "❌"}</span>
              <div>
                <div style={{
                  fontSize: 20, fontWeight: 700,
                  color: isPrime ? "#68d391" : "#fc8181",
                }}>
                  {out.verdict}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
                  {isPrime
                    ? `Probably prime — ${out.rounds_run} round(s) passed. Error ≤ 4^−${out.rounds_run}.`
                    : `Definitely composite — witness found in round ${out.rounds_run}.`}
                  &nbsp;Time: {out.time_ms} ms
                </div>
                {out.fermat_note && (
                  <div style={{ marginTop: 4, fontSize: 12, color: "#f6ad55" }}>
                    ⚠ {out.fermat_note} — Fermat test would call this prime!
                  </div>
                )}
              </div>
            </div>

            {/* Decomposition */}
            <Output style={{ marginTop: 10 }}>
              <KV k="n" v={trunc(out.n)} />
              <KV k="n − 1 = 2^s · d" v={`s = ${out.s}, d = ${trunc(out.d, 30)}`} />
            </Output>

            {/* Witness table */}
            {out.witnesses && out.witnesses.length > 0 && (
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
                  Witness table ({out.witnesses.length} round{out.witnesses.length !== 1 ? "s" : ""})
                </div>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", fontSize: 11, borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ color: "var(--text-muted)", textAlign: "left" }}>
                        <th style={{ padding: "4px 8px" }}>#</th>
                        <th style={{ padding: "4px 8px" }}>a (witness)</th>
                        <th style={{ padding: "4px 8px" }}>a^d mod n</th>
                        <th style={{ padding: "4px 8px" }}>Squarings</th>
                        <th style={{ padding: "4px 8px" }}>Round result</th>
                      </tr>
                    </thead>
                    <tbody>
                      {out.witnesses.map((w) => (
                        <tr key={w.round} style={{
                          borderTop: "1px solid var(--border)",
                          background: w.passed ? "transparent" : "rgba(252,129,129,0.08)",
                        }}>
                          <td style={{ padding: "5px 8px", color: "var(--text-muted)" }}>{w.round}</td>
                          <td style={{ padding: "5px 8px", fontFamily: "monospace" }}>
                            {trunc(w.a, 20)}
                          </td>
                          <td style={{ padding: "5px 8px", fontFamily: "monospace" }}>
                            {trunc(w.x0, 20)}
                          </td>
                          <td style={{ padding: "5px 8px", fontFamily: "monospace", color: "var(--text-muted)" }}>
                            {w.steps.length > 1
                              ? w.steps.slice(1).map((s, i) => (
                                  <span key={i} title={s.exp} style={{ marginRight: 6 }}>
                                    {trunc(s.val, 12)}
                                  </span>
                                ))
                              : "—"}
                          </td>
                          <td style={{ padding: "5px 8px" }}>
                            <span style={{
                              color: w.passed ? "#68d391" : "#fc8181",
                              fontWeight: 600, fontSize: 11,
                            }}>
                              {w.verdict}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )}
      </Card>

      {/* ── Prime generator ── */}
      <Card title="Generate a random prime">
        <div style={{ display: "flex", gap: 16, alignItems: "flex-end", flexWrap: "wrap" }}>
          <div style={{ width: 160 }}>
            <label>Bit length</label>
            <input type="number" min={64} max={512} step={64} value={bits}
              onChange={(e) => setBits(Number(e.target.value))} />
          </div>
          <Button onClick={gen} loading={busy === "g"}>Generate prime</Button>
        </div>
        {genOut && (
          <Output>
            <KV k="prime" v={trunc(genOut.prime, 72)} success />
            <KV k="bits"  v={genOut.bits} />
            <KV k="time"  v={`${genOut.time_ms} ms`} />
            <button
              onClick={() => { setN(genOut.prime); setOut(null); }}
              style={{
                marginTop: 8, padding: "4px 12px", borderRadius: 6, fontSize: 12,
                border: "1px solid var(--border)", background: "var(--surface2)",
                color: "var(--text)", cursor: "pointer",
              }}
            >
              → Test this prime
            </button>
          </Output>
        )}
      </Card>

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}
