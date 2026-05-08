// PA#17 — CCA-Secure PKC: Encrypt-then-Sign (Signcryption)
//
// Spec:
//  • Encrypt message using Encrypt-then-Sign → show (C_E, σ).
//  • "Tamper with C_E" button (CCA attacker) modifies one byte of C_E.
//  • Submit to decryption oracle → shows signature verification firing first:
//    "Signature invalid, decryption aborted, output ⊥" — plaintext never decrypts.
//  • Contrast panel (plain ElGamal): same tamper goes through, 2m returned.

import { useState } from "react";
import { Card, Button, Output, KV, Description, Badge, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

function trunc(s, n = 46) {
  return s && String(s).length > n ? String(s).slice(0, n) + "…" : String(s);
}

// Animated step badge
function Step({ num, label, status }) {
  const color = status === "ok" ? "#68d391"
              : status === "fail" ? "#fc8181"
              : "var(--text-muted)";
  const icon  = status === "ok" ? "✓" : status === "fail" ? "✗" : "…";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "5px 0" }}>
      <div style={{ width: 22, height: 22, borderRadius: "50%", flexShrink: 0,
        background: color + "22", border: `1px solid ${color}`,
        display: "flex", alignItems: "center", justifyContent: "center",
        fontSize: 11, color, fontWeight: 700 }}>
        {icon}
      </div>
      <span style={{ fontSize: 12, color }}><b>Step {num}:</b> {label}</span>
    </div>
  );
}

export default function PA17() {
  const [msg,    setMsg]    = useState("payload requiring authenticity + secrecy");
  const [mNum,   setMNum]   = useState("42");   // for tamper demo numeric m
  const [signOut, setSignOut] = useState(null);
  const [tamper,  setTamper]  = useState(null);
  const [phase,   setPhase]   = useState(0);    // 0 idle 1 encrypted 2 tampered
  const [busy,    setBusy]    = useState(null);
  const [err,     setErr]     = useState(null);

  async function encrypt() {
    setErr(null); setBusy("enc"); setSignOut(null); setTamper(null); setPhase(0);
    const r = await callApi("/api/pa17/signcrypt", { message: msg });
    if (r.ok) { setSignOut(r.data); setPhase(1); } else setErr(r.error);
    setBusy(null);
  }

  async function runTamper() {
    setErr(null); setBusy("tamper"); setTamper(null);
    const r = await callApi("/api/pa17/tamper", { m: Number(mNum) });
    if (r.ok) { setTamper(r.data); setPhase(2); } else setErr(r.error);
    setBusy(null);
  }

  return (
    <div>
      <Description>
        <b>Encrypt-then-Sign</b> (Signcryption): <code>C_E = ElGamal.Enc(pk, m)</code>,
        then <code>σ = RSA.Sign(sk, C_E)</code>. Decryption verifies σ on C_E <b>first</b> —
        any tampering causes immediate abort with <code>⊥</code>. This neutralises the
        CCA decryption oracle, achieving <b>IND-CCA2</b>. Contrast: plain ElGamal returns
        <code>2m</code> for the same tamper.
      </Description>

      {/* ── Encrypt ── */}
      <Card title="Encrypt-then-Sign">
        <label>Message</label>
        <textarea value={msg} rows={2}
          onChange={(e) => { setMsg(e.target.value); setSignOut(null); setPhase(0); }} />
        <div style={{ marginTop: 12 }}>
          <Button id="pa17-encrypt" onClick={encrypt} loading={busy === "enc"}>
            Encrypt-then-Sign
          </Button>
        </div>

        {signOut && phase >= 1 && (
          <Output style={{ marginTop: 12 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", marginBottom: 6 }}>
              Ciphertext bundle <code>(C_E, σ)</code>
            </div>
            <KV k="c₁ = g^r mod p" v={trunc(signOut.ciphertext.c1)} success />
            <KV k="c₂ = m·h^r mod p" v={trunc(signOut.ciphertext.c2)} success />
            <KV k="σ = RSA.Sign(C_E)" v={trunc(signOut.ciphertext.sigma)} success />

            <div style={{ marginTop: 10 }}>
              <Step num={1} label="Verify(σ, C_E) → OK" status="ok" />
              <Step num={2} label={`Dec(C_E) → m = ${signOut.m_int}`} status="ok" />
            </div>
            <Badge variant={signOut.cca_secure ? "success" : "error"} style={{ marginTop: 8 }}>
              {signOut.cca_secure
                ? "✓ Honest decrypt OK — untampered path works correctly"
                : "✗ Decryption failed (unexpected)"}
            </Badge>
          </Output>
        )}
      </Card>

      {/* ── Tamper demo ── */}
      <Card title="Tamper with C_E — CCA attacker simulation">
        <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
          The CCA attacker modifies <code>c₂ → c₂ + 1</code> and submits the tampered
          ciphertext to the decryption oracle. Signature verification fires <b>first</b>.
        </div>
        <div style={{ display: "flex", gap: 14, alignItems: "flex-end", flexWrap: "wrap", marginBottom: 12 }}>
          <div style={{ width: 160 }}>
            <label>Plaintext m (integer)</label>
            <input type="text" value={mNum} onChange={(e) => setMNum(e.target.value)} />
          </div>
          <Button id="pa17-tamper" onClick={runTamper} loading={busy === "tamper"} variant="secondary">
            Tamper C_E &amp; run oracle
          </Button>
        </div>

        {tamper && (
          <>
            {/* Side-by-side comparison */}
            <div className="row" style={{ alignItems: "flex-start", gap: 12 }}>

              {/* Plain ElGamal — malleable */}
              <div style={{ flex: 1, border: "1px solid rgba(252,129,129,0.4)",
                borderRadius: 8, padding: "12px 14px",
                background: "rgba(252,129,129,0.06)" }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: "#fc8181", marginBottom: 8 }}>
                  ⚠ Plain ElGamal (CPA-only)
                </div>
                <Step num={1} label="Submit (c₁, 2c₂) to oracle" status="ok" />
                <Step num={2} label="Decryption runs (no sig check)" status="ok" />
                <Step num={3} label={`Oracle returns ${tamper.plain_elgamal.tampered_result}`}
                      status={tamper.plain_elgamal.is_2m ? "fail" : "ok"} />
                <div style={{ marginTop: 10 }}>
                  <KV k="Result" v={tamper.plain_elgamal.tampered_result} />
                  <KV k="Expected 2m" v={tamper.two_m} />
                  <Badge variant="error" style={{ marginTop: 6 }}>
                    {tamper.plain_elgamal.is_2m
                      ? `✗ ${tamper.plain_elgamal.verdict}`
                      : "Mismatch (unexpected)"}
                  </Badge>
                </div>
              </div>

              {/* CCA Signcrypt — blocked */}
              <div style={{ flex: 1, border: "1px solid rgba(72,187,120,0.4)",
                borderRadius: 8, padding: "12px 14px",
                background: "rgba(72,187,120,0.06)" }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: "#68d391", marginBottom: 8 }}>
                  ✓ CCA Signcrypt (Encrypt-then-Sign)
                </div>
                <Step num={1} label="Verify(σ, C_E') fires first" status="ok" />
                <Step num={2} label="Verify → FAIL (C_E was modified)" status="fail" />
                <Step num={3} label="Decryption ABORTED → ⊥" status="fail" />
                <div style={{ marginTop: 10 }}>
                  <KV k="Result" v={tamper.cca_signcrypt.tampered_result} />
                  <div style={{ marginTop: 6, fontSize: 11, color: "#f6ad55" }}>
                    {tamper.cca_signcrypt.reason}
                  </div>
                  <Badge variant="success" style={{ marginTop: 6 }}>
                    {tamper.cca_signcrypt.blocked
                      ? `✓ ${tamper.cca_signcrypt.verdict}`
                      : "Not blocked (unexpected)"}
                  </Badge>
                </div>
              </div>
            </div>

            {/* Final verdict banner */}
            <div style={{
              marginTop: 14, padding: "12px 18px", borderRadius: 8,
              background: "rgba(72,187,120,0.08)",
              border: "1px solid rgba(72,187,120,0.35)",
            }}>
              <div style={{ fontWeight: 700, color: "#68d391" }}>
                ✓ Any tampered ciphertext returns ⊥ — untampered decrypts correctly.
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                The signature binds the ciphertext C_E to the sender. Any modification
                (even +1 to c₂) invalidates σ, causing immediate abort before decryption.
                The CCA oracle is useless — IND-CCA2 is achieved.
              </div>
            </div>
          </>
        )}
      </Card>

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}
