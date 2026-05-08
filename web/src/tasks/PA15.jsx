// PA#15 — Digital Signatures: Sign, Verify, Tamper, Forgery
//
// Spec:
//  • Text input + "Sign" button → σ = H(m)^d mod N shown in hex.
//  • "Verify" button → shows σ^e mod N and H(m) side-by-side, green "Valid" or red "Invalid".
//  • "Tamper" button → flips one bit of message, re-verifies → immediately fails.
//  • "Raw RSA sign (no hash)" toggle → signs m directly without hashing, then demonstrates
//    multiplicative forgery: given σ₁, σ₂, compute valid σ* on m₁·m₂ without the private key.

import { useState } from "react";
import { Card, Button, Output, KV, Description, Badge, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

function trunc(s, n = 48) {
  return s && String(s).length > n ? String(s).slice(0, n) + "…" : String(s);
}

export default function PA15() {
  const [msg,    setMsg]    = useState("I, Alice, agree to the terms.");
  const [bits,   setBits]   = useState(512);
  const [raw,    setRaw]    = useState(false);

  const [signOut,   setSignOut]   = useState(null);
  const [verifyOut, setVerifyOut] = useState(null);
  const [tamperOut, setTamperOut] = useState(null);
  const [forgeOut,  setForgeOut]  = useState(null);

  const [busy, setBusy] = useState(null);
  const [err,  setErr]  = useState(null);

  async function sign() {
    setErr(null); setBusy("sign");
    setSignOut(null); setVerifyOut(null); setTamperOut(null); setForgeOut(null);
    const r = await callApi("/api/pa15/sign", { message: msg, bits, raw });
    if (r.ok) setSignOut(r.data); else setErr(r.error);
    setBusy(null);
  }

  async function verify() {
    if (!signOut) return;
    setErr(null); setBusy("verify"); setVerifyOut(null);
    const r = await callApi("/api/pa15/verify", {
      message: signOut.message,
      N: signOut.N, e: signOut.e,
      sigma: signOut.sigma_int,
      raw,
    });
    if (r.ok) setVerifyOut(r.data); else setErr(r.error);
    setBusy(null);
  }

  async function tamper() {
    if (!signOut) return;
    setErr(null); setBusy("tamper"); setTamperOut(null);
    const r = await callApi("/api/pa15/tamper", {
      message: signOut.message,
      N: signOut.N, e: signOut.e,
      sigma: signOut.sigma_int,
      raw,
    });
    if (r.ok) setTamperOut(r.data); else setErr(r.error);
    setBusy(null);
  }

  async function forgery() {
    setErr(null); setBusy("forge"); setForgeOut(null);
    const r = await callApi("/api/pa15/forgery", { bits });
    if (r.ok) setForgeOut(r.data); else setErr(r.error);
    setBusy(null);
  }

  return (
    <div>
      <Description>
        <b>Hash-then-sign RSA</b>: σ = H(m)^d mod N. Verification checks σ^e mod N{" "}
        <span style={{ fontFamily: "monospace" }}>≟</span> H(m). Hashing is essential —
        raw RSA sign is multiplicatively homomorphic, allowing forgery of σ(m₁·m₂) from
        σ(m₁) and σ(m₂) without the private key.
      </Description>

      {/* ── Controls ── */}
      <Card title="Message & options">
        <label>Message</label>
        <textarea value={msg} onChange={(e) => setMsg(e.target.value)} rows={2} />
        <div style={{ display: "flex", gap: 16, alignItems: "flex-end", marginTop: 10, flexWrap: "wrap" }}>
          <div style={{ width: 150 }}>
            <label>Modulus bits</label>
            <select value={bits} onChange={(e) => setBits(Number(e.target.value))}
              style={{ width: "100%", padding: "6px 10px", borderRadius: 6,
                background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--text)" }}>
              {[256, 512, 1024].map(b => <option key={b} value={b}>{b}-bit</option>)}
            </select>
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: 8, paddingBottom: 2, cursor: "pointer" }}>
            <input type="checkbox" checked={raw} onChange={(e) => {
              setRaw(e.target.checked);
              setSignOut(null); setVerifyOut(null); setTamperOut(null);
            }} />
            <span style={{ color: raw ? "#f6ad55" : "var(--text)", fontSize: 13 }}>
              Raw RSA sign (no hash) — enables forgery demo
            </span>
          </label>
        </div>
      </Card>

      {/* ── Sign ── */}
      <Card title={raw ? "Raw RSA Sign (σ = m^d mod N)" : "Sign (σ = H(m)^d mod N)"}>
        <Button id="pa15-sign" onClick={sign} loading={busy === "sign"}>Sign</Button>

        {signOut && (
          <Output style={{ marginTop: 12 }}>
            <KV k="message" v={signOut.message} />
            <KV k={raw ? "m (no hash)" : "H(m)"} v={trunc(signOut.H_m)} />
            <KV k="σ (hex)" v={trunc(signOut.sigma)} success />
            <Badge variant={signOut.verified ? "success" : "error"}>
              {signOut.verified ? "✓ Self-verified OK" : "✗ Self-verify failed"}
            </Badge>
          </Output>
        )}
      </Card>

      {/* ── Verify ── */}
      {signOut && (
        <Card title="Verify (σ^e mod N ≟ H(m))">
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
            Compute σ^e mod N and compare with H(m). They must match for a valid signature.
          </div>
          <Button id="pa15-verify" onClick={verify} loading={busy === "verify"} variant="secondary">
            Verify
          </Button>

          {verifyOut && (
            <Output style={{ marginTop: 12 }}>
              <KV k="σ^e mod N" v={trunc(verifyOut.sigma_e_mod_N)} />
              <KV k={raw ? "m (no hash)" : "H(m)"} v={trunc(verifyOut.H_m)} />
              <div style={{
                marginTop: 8, padding: "8px 12px", borderRadius: 6, fontSize: 12,
                background: verifyOut.verified
                  ? "rgba(72,187,120,0.12)" : "rgba(252,129,129,0.12)",
                border: `1px solid ${verifyOut.verified ? "rgba(72,187,120,0.4)" : "rgba(252,129,129,0.4)"}`,
              }}>
                <span style={{ fontWeight: 700, color: verifyOut.verified ? "#68d391" : "#fc8181" }}>
                  {verifyOut.verified
                    ? "✓ Valid — σ^e mod N = H(m)"
                    : "✗ Invalid — σ^e mod N ≠ H(m)"}
                </span>
                <span style={{ marginLeft: 10, color: "var(--text-muted)" }}>
                  {verifyOut.verified ? "Values match ✓" : "Values differ ✗"}
                </span>
              </div>
            </Output>
          )}
        </Card>
      )}

      {/* ── Tamper ── */}
      {signOut && (
        <Card title="Tamper — flip one bit, verify fails">
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
            Flip bit 0 of the first byte of the message. The original signature σ should
            immediately fail verification — even a 1-bit change is detected.
          </div>
          <Button id="pa15-tamper" onClick={tamper} loading={busy === "tamper"} variant="secondary">
            Tamper &amp; verify
          </Button>

          {tamperOut && (
            <Output style={{ marginTop: 12 }}>
              <div style={{ fontSize: 12, marginBottom: 8 }}>
                <span style={{ color: "var(--text-muted)" }}>Original: </span>
                <code style={{ color: "#68d391" }}>{tamperOut.original_message}</code>
              </div>
              <div style={{ fontSize: 12, marginBottom: 8 }}>
                <span style={{ color: "var(--text-muted)" }}>Tampered: </span>
                <code style={{ color: "#fc8181" }}>{tamperOut.tampered_message}</code>
              </div>
              <KV k="bit flip" v={tamperOut.tampered_byte} />
              <KV k="σ^e mod N" v={trunc(tamperOut.sigma_e_mod_N)} />
              <KV k="H(tampered)" v={trunc(tamperOut.H_tampered)} />
              <Badge variant={tamperOut.verified ? "error" : "success"}>
                {tamperOut.verified
                  ? "⚠ Verified (unexpected!)"
                  : "✓ Verification failed — tamper detected!"}
              </Badge>
            </Output>
          )}
        </Card>
      )}

      {/* ── Multiplicative Forgery (raw mode only) ── */}
      <Card title="Multiplicative Forgery Demo">
        <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
          Raw RSA sign is homomorphic: <code>σ(m₁)·σ(m₂) mod N = σ(m₁·m₂)</code>.
          An attacker with two signed messages can forge a signature on their product —
          without ever seeing the private key. Hash-then-sign breaks this.
        </div>
        <Button id="pa15-forgery" onClick={forgery} loading={busy === "forge"} variant="secondary">
          Run forgery demo
        </Button>

        {forgeOut && (
          <>
            <div style={{ marginTop: 14 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "#f6ad55", marginBottom: 8 }}>
                Raw RSA — Forgery
              </div>
              <Output>
                <KV k="m₁" v={trunc(forgeOut.raw_forgery.m1)} />
                <KV k="σ₁ = m₁^d mod N" v={trunc(forgeOut.raw_forgery.sig1)} />
                <KV k="m₂" v={trunc(forgeOut.raw_forgery.m2)} />
                <KV k="σ₂ = m₂^d mod N" v={trunc(forgeOut.raw_forgery.sig2)} />
                <div style={{ margin: "8px 0", padding: "6px 10px", borderRadius: 6,
                  background: "rgba(246,173,85,0.10)", border: "1px solid rgba(246,173,85,0.3)",
                  fontSize: 12 }}>
                  <b>Attacker computes:</b> σ* = (σ₁ · σ₂) mod N
                </div>
                <KV k="m₁·m₂ mod N" v={trunc(forgeOut.raw_forgery.m_forged)} />
                <KV k="σ* (forged)" v={trunc(forgeOut.raw_forgery.sig_forged)} />
                <Badge variant={forgeOut.raw_forgery.valid ? "error" : "success"}>
                  {forgeOut.raw_forgery.valid
                    ? `⚠ Forgery valid! σ* verifies on m₁·m₂ — no private key used!`
                    : "✗ Forgery failed (unexpected)"}
                </Badge>
              </Output>
            </div>

            <div style={{ marginTop: 14 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "#68d391", marginBottom: 8 }}>
                Hash-then-sign — Forgery fails
              </div>
              <Output>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  H(m₁·m₂) ≠ H(m₁)·H(m₂) — hash is not multiplicative.
                  The same σ₁·σ₂ trick produces garbage under hash-then-sign.
                </div>
                <Badge variant={forgeOut.hashed_forgery.valid ? "error" : "success"} style={{ marginTop: 8 }}>
                  {forgeOut.hashed_forgery.valid
                    ? "⚠ Hash is homomorphic (broken)"
                    : "✓ Forgery fails — hash-then-sign is secure"}
                </Badge>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
                  {forgeOut.hashed_forgery.explanation}
                </div>
              </Output>
            </div>
          </>
        )}
      </Card>

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}
