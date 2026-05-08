// PA#16 — ElGamal Malleability Demo
//
// Spec:
//  • Encrypt plaintext m → (c₁, c₂) shown.
//  • "Multiply c₂ by 2" button → (c₁, 2c₂ mod p) — new valid ciphertext.
//  • "Decrypt" shows 2m, demonstrating malleability.
//  • Counter shows how many times the trick succeeds (should be 100%).
//  • Side panel: CPA game — encrypt challenge, submit modified ciphertext
//    to decryption oracle, confirm 2m comes back, demonstrating CCA failure.

import { useState } from "react";
import { Card, Button, Output, KV, Description, Badge, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

function trunc(s, n = 44) {
  return s && String(s).length > n ? String(s).slice(0, n) + "…" : String(s);
}

export default function PA16() {
  const [bits, setBits]     = useState(64);
  const [m,    setM]        = useState("42");
  const [trials, setTrials] = useState(5);

  // malleability demo state
  const [mal,   setMal]     = useState(null);
  const [phase, setPhase]   = useState(0);  // 0=idle 1=encrypted 2=tampered 3=decrypted

  // CCA game side panel
  const [cca,   setCca]     = useState(null);

  const [busy, setBusy]     = useState(null);
  const [err,  setErr]      = useState(null);

  async function runMal() {
    setErr(null); setBusy("mal"); setMal(null); setPhase(0); setCca(null);
    const r = await callApi("/api/pa16/malleability", { m, bits, trials });
    if (r.ok) { setMal(r.data); setPhase(1); } else setErr(r.error);
    setBusy(null);
  }

  async function runCca() {
    setErr(null); setBusy("cca"); setCca(null);
    const r = await callApi("/api/pa16/cca_game", { m, bits });
    if (r.ok) setCca(r.data); else setErr(r.error);
    setBusy(null);
  }

  return (
    <div>
      <Description>
        <b>ElGamal</b> encryption: <code>(c₁, c₂) = (g^r, m·h^r) mod p</code>. CPA-secure
        under DDH. However, it is <b>malleable</b>: given <code>(c₁, c₂)</code>, anyone can
        produce <code>(c₁, 2c₂ mod p)</code> which decrypts to <code>2m</code> — without
        knowing m or the private key. This breaks CCA security.
      </Description>

      {/* ── Setup ── */}
      <Card title="Setup">
        <div style={{ display: "flex", gap: 16, alignItems: "flex-end", flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 120 }}>
            <label>Plaintext m (integer)</label>
            <input id="pa16-m" type="text" value={m}
              onChange={(e) => { setM(e.target.value); setMal(null); setPhase(0); }} />
          </div>
          <div style={{ width: 110 }}>
            <label>Group bits</label>
            <select value={bits} onChange={(e) => { setBits(Number(e.target.value)); setMal(null); setPhase(0); }}
              style={{ width: "100%", padding: "6px 10px", borderRadius: 6,
                background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--text)" }}>
              {[64, 128, 256].map(b => <option key={b} value={b}>{b}-bit</option>)}
            </select>
          </div>
          <div style={{ width: 100 }}>
            <label>Trials</label>
            <input type="number" min={1} max={20} value={trials}
              onChange={(e) => setTrials(Number(e.target.value))} />
          </div>
          <Button id="pa16-encrypt" onClick={runMal} loading={busy === "mal"}>
            Encrypt
          </Button>
        </div>
      </Card>

      {mal && phase >= 1 && (
        <>
          {/* ── Step 1: Original ciphertext ── */}
          <Card title="Step 1 — Original ciphertext (c₁, c₂) = Enc(m)">
            <div className="row" style={{ alignItems: "flex-start" }}>
              <div style={{ flex: 1 }}>
                <Output>
                  <KV k="m (plaintext)" v={mal.m} />
                  <KV k="c₁ = g^r mod p" v={trunc(mal.original.c1)} success />
                  <KV k="c₂ = m·h^r mod p" v={trunc(mal.original.c2)} success />
                  <KV k="Dec(c₁, c₂)" v={mal.original.decrypted} success={mal.original.decrypted === mal.m} />
                </Output>
              </div>
            </div>
            {phase < 2 && (
              <Button id="pa16-multiply" onClick={() => setPhase(2)} style={{ marginTop: 12 }} variant="secondary">
                Multiply c₂ by 2 (attacker) →
              </Button>
            )}
          </Card>

          {/* ── Step 2: Tampered ciphertext ── */}
          {phase >= 2 && (
            <Card title="Step 2 — Attacker computes (c₁, 2c₂ mod p) — no key needed!">
              <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
                The attacker simply multiplies <code>c₂</code> by 2 modulo <code>p</code>.
                No private key required.
              </div>
              <Output>
                <KV k="c₁ (unchanged)" v={trunc(mal.tampered.c1)} />
                <KV k="c₂' = 2·c₂ mod p" v={trunc(mal.tampered.c2_prime)} />
                <div style={{ fontSize: 11, color: "#f6ad55", margin: "4px 0 8px" }}>
                  ↑ This is the tampered ciphertext submitted to the oracle.
                </div>
              </Output>
              {phase < 3 && (
                <Button id="pa16-decrypt-tamper" onClick={() => setPhase(3)} variant="secondary">
                  Decrypt tampered ciphertext →
                </Button>
              )}
            </Card>
          )}

          {/* ── Step 3: Result ── */}
          {phase >= 3 && (
            <Card title="Step 3 — Decryption reveals 2m">
              <Output>
                <KV k="Dec(c₁, 2c₂)" v={mal.tampered.decrypted} />
                <KV k="2m (expected)" v={mal.two_m} />
                <KV k="match" v={mal.tampered.is_2m ? "YES — Dec(c₁, 2c₂) = 2m ✓" : "NO ✗"} />
              </Output>

              {/* Result banner */}
              <div style={{
                marginTop: 10, padding: "12px 16px", borderRadius: 8,
                background: mal.tampered.is_2m
                  ? "rgba(252,129,129,0.10)" : "rgba(72,187,120,0.10)",
                border: `1px solid ${mal.tampered.is_2m ? "rgba(252,129,129,0.4)" : "rgba(72,187,120,0.4)"}`,
              }}>
                <div style={{ fontWeight: 700, fontSize: 14,
                  color: mal.tampered.is_2m ? "#fc8181" : "#68d391" }}>
                  {mal.tampered.is_2m
                    ? `⚠ Malleability confirmed: Dec(c₁, 2c₂) = 2·${mal.m} = ${mal.two_m}`
                    : "✗ Malleability test failed (unexpected)"}
                </div>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                  ElGamal is NOT CCA-secure. Any ciphertext can be transformed into a related
                  one without knowing the plaintext or private key.
                </div>
              </div>

              {/* Success counter */}
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
                  Success counter ({mal.counter.trials} independent trials)
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  {/* Progress bar */}
                  <div style={{ flex: 1, height: 12, borderRadius: 6,
                    background: "var(--surface2)", overflow: "hidden" }}>
                    <div style={{ height: "100%", borderRadius: 6,
                      width: `${mal.counter.pct}%`,
                      background: mal.counter.pct === 100
                        ? "linear-gradient(90deg,#fc8181,#f6ad55)"
                        : "var(--accent)",
                      transition: "width 0.4s ease" }} />
                  </div>
                  <span style={{ fontWeight: 700, color: mal.counter.pct === 100 ? "#fc8181" : "#68d391",
                    fontFamily: "monospace", minWidth: 60 }}>
                    {mal.counter.rate} ({mal.counter.pct}%)
                  </span>
                </div>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                  Trick always works — 100% success rate. ElGamal malleability is deterministic.
                </div>
              </div>
            </Card>
          )}

          {/* ── CPA / CCA Game side panel ── */}
          <Card title="CCA Game — Why ElGamal Fails CCA">
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
              In the CCA game an adversary can submit any ciphertext (≠ challenge) to
              a decryption oracle. With ElGamal: submit <code>(c₁, 2c₂)</code> → oracle
              returns <code>2m</code> → adversary recovers <code>m</code>.
            </div>
            <Button id="pa16-cca" onClick={runCca} loading={busy === "cca"} variant="secondary">
              Run CCA game
            </Button>

            {cca && (
              <Output style={{ marginTop: 12 }}>
                {cca.steps.map((s, i) => (
                  <div key={i} style={{ fontSize: 12, padding: "3px 0",
                    color: i === cca.steps.length - 1 ? "#fc8181" : "var(--text-muted)" }}>
                    {s}
                  </div>
                ))}
                <div style={{ marginTop: 8 }}>
                  <KV k="Challenge m" v={cca.challenge_m} />
                  <KV k="Oracle returns" v={cca.oracle_result} />
                  <KV k="Adversary recovers m" v={cca.recovered_m} success={cca.win} />
                </div>
                <Badge variant={cca.win ? "error" : "success"} style={{ marginTop: 8 }}>
                  {cca.win
                    ? `⚠ Adversary wins! Recovered m = ${cca.recovered_m} without decrypting challenge.`
                    : "✗ Adversary failed (unexpected)"}
                </Badge>
              </Output>
            )}
          </Card>
        </>
      )}

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}
