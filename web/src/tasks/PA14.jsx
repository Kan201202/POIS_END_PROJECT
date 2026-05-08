// PA#14 — Håstad Broadcast Attack Visualiser
//
// Spec:
//  • Three recipient panels, each showing N_i and received ciphertext c_i = m³ mod N_i.
//  • Attacker panel runs CRT on the three ciphertexts and displays recovered m³.
//  • "Cube root" button computes integer cube root and reveals m.
//  • "Use PKCS padding" toggle re-runs: CRT still works but cube root is not integer.
//  • Toy params: 64-bit N_i for instant computation.

import { useState } from "react";
import { Card, Button, Output, KV, Description, Badge, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

function trunc(s, n = 42) {
  return s && String(s).length > n ? String(s).slice(0, n) + "…" : String(s);
}

export default function PA14() {
  const [m,       setM]      = useState("12345");
  const [padded,  setPadded] = useState(false);
  const [out,     setOut]    = useState(null);
  const [phase,   setPhase]  = useState(0);   // 0=idle, 1=recipients, 2=crt, 3=root
  const [busy,    setBusy]   = useState(false);
  const [err,     setErr]    = useState(null);

  async function runAttack() {
    setErr(null); setBusy(true); setOut(null); setPhase(0);
    const r = await callApi("/api/pa14/hastad", { m, padded, bits: 64 });
    if (r.ok) {
      setPhase(1);           // show recipients immediately
      setOut(r.data);
    } else {
      setErr(r.error);
    }
    setBusy(false);
  }

  function showCRT()  { if (out) setPhase(2); }
  function showRoot() { if (out) setPhase(3); }

  const succeeded = out?.match && !padded;

  return (
    <div>
      <Description>
        If the same plaintext <code>m</code> is broadcast to <b>3</b> recipients all using
        exponent <code>e = 3</code>, the Chinese Remainder Theorem recovers{" "}
        <code>m³ mod N₁N₂N₃</code>. Since <code>m³ &lt; N₁N₂N₃</code>, the integer cube
        root gives back <code>m</code> directly — no factoring required. PKCS#1 padding
        defeats this because it randomises <code>m</code>, making <code>m³</code> too large.
      </Description>

      {/* ── Setup ── */}
      <Card title="Setup">
        <div style={{ display: "flex", gap: 16, alignItems: "flex-end", flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 140 }}>
            <label>Plaintext m (small integer)</label>
            <input
              id="pa14-msg"
              type="text"
              value={m}
              onChange={(e) => { setM(e.target.value); setOut(null); setPhase(0); }}
              placeholder="e.g. 12345"
            />
          </div>

          <label style={{ display: "flex", alignItems: "center", gap: 8,
            paddingBottom: 4, cursor: "pointer", whiteSpace: "nowrap" }}>
            <input type="checkbox" checked={padded}
              onChange={(e) => { setPadded(e.target.checked); setOut(null); setPhase(0); }} />
            <span style={{ color: padded ? "#f6ad55" : "var(--text)" }}>
              Use PKCS#1 padding
            </span>
          </label>

          <Button id="pa14-attack" onClick={runAttack} loading={busy}>
            Broadcast &amp; attack
          </Button>
        </div>
      </Card>

      {/* ── Three recipient panels ── */}
      {out && phase >= 1 && (
        <>
          <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-muted)", marginBottom: 8 }}>
            Step 1 — Each recipient receives <code>c_i = m³ mod N_i</code>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 14 }}>
            {out.recipients.map((r) => (
              <RecipientCard key={r.index} r={r} />
            ))}
          </div>

          {/* ── Attacker panel ── */}
          <Card title="🔴 Attacker — CRT reconstruction">
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
              CRT combines <code>c₁, c₂, c₃</code> to recover{" "}
              <code>x = m³ mod N₁N₂N₃</code> without knowing any private key.
            </div>

            {phase < 2 ? (
              <Button id="pa14-crt" onClick={showCRT}>Run CRT →</Button>
            ) : (
              <Output>
                <KV k="N₁N₂N₃ (product)" v={trunc(out.N_product, 44)} />
                <KV k="x = m³ mod N₁N₂N₃" v={trunc(out.crt_result, 44)} success />
                <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-muted)" }}>
                  CRT always recovers m³ — even in padded mode. The question is whether ∛x = m.
                </div>
              </Output>
            )}

            {phase >= 2 && (
              <div style={{ marginTop: 12 }}>
                {phase < 3 ? (
                  <Button id="pa14-root" onClick={showRoot} variant="secondary">
                    Compute ∛x (cube root) →
                  </Button>
                ) : (
                  <>
                    <Output>
                      <KV k="∛x (integer cube root)" v={trunc(out.cube_root, 44)} />
                      {out.exact_root ? (
                        <>
                          <KV k="Is exact integer root?" v="YES ✓" success />
                          <KV k="Recovered m" v={out.recovered} success={out.match} />
                          <Badge variant={out.match ? "success" : "error"}>
                            {out.match ? `✓ Attack succeeded! m = ${out.original} recovered.`
                              : `✗ Root found but m ≠ ${out.original}`}
                          </Badge>
                        </>
                      ) : (
                        <>
                          <KV k="Is exact integer root?" v="NO ✗ — not a perfect cube" />
                          <Badge variant="success">
                            ✓ Attack FAILED — PKCS padding defeats Håstad!
                          </Badge>
                          {out.padded_note && (
                            <div style={{ marginTop: 8, fontSize: 11, color: "#f6ad55" }}>
                              ⚠ {out.padded_note}
                            </div>
                          )}
                        </>
                      )}
                    </Output>

                    {/* Final verdict banner */}
                    <div style={{
                      marginTop: 12, padding: "12px 18px", borderRadius: 8,
                      background: out.match
                        ? "rgba(252,129,129,0.10)" : "rgba(72,187,120,0.10)",
                      border: `1px solid ${out.match ? "rgba(252,129,129,0.4)" : "rgba(72,187,120,0.4)"}`,
                    }}>
                      <div style={{
                        fontWeight: 700, fontSize: 15,
                        color: out.match ? "#fc8181" : "#68d391",
                      }}>
                        {out.match
                          ? `⚠ Unpadded RSA is BROKEN — attacker recovered m = "${out.original}"`
                          : `✓ PKCS#1 padding blocks Håstad — cube root is garbage`}
                      </div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                        {out.match
                          ? "Textbook RSA with small e is vulnerable when the same message is broadcast to multiple recipients."
                          : "Random PS bytes in PKCS#1 v1.5 inflate m so m³ > N₁N₂N₃ — CRT result is not a perfect cube."}
                      </div>
                    </div>
                  </>
                )}
              </div>
            )}
          </Card>

          {/* Public parameters */}
          <Card title="Public parameters">
            <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
              e = {out.e} (fixed) &nbsp;·&nbsp; {out.bits}-bit moduli &nbsp;·&nbsp;
              Padded: <b>{out.padded ? "YES" : "NO"}</b>
            </div>
          </Card>
        </>
      )}

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}

function RecipientCard({ r }) {
  return (
    <div style={{
      border: "1px solid var(--border)", borderRadius: 8,
      padding: "10px 12px", background: "rgba(99,179,237,0.04)",
    }}>
      <div style={{ fontSize: 12, fontWeight: 700, color: "var(--accent)", marginBottom: 8 }}>
        Recipient {r.index}
      </div>
      <div style={{ fontSize: 11, marginBottom: 4 }}>
        <span style={{ color: "var(--text-muted)" }}>N_{r.index} = </span>
        <code style={{ fontSize: 11, wordBreak: "break-all" }}>{trunc(r.N, 30)}</code>
      </div>
      <div style={{ fontSize: 11 }}>
        <span style={{ color: "var(--text-muted)" }}>c_{r.index} = </span>
        <code style={{ fontSize: 11, wordBreak: "break-all", color: "var(--accent)" }}>
          {trunc(r.c, 30)}
        </code>
      </div>
      <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 6 }}>
        c = m³ mod N_{r.index}
      </div>
    </div>
  );
}
