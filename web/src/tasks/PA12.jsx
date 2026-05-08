// PA#12 — RSA: Textbook Determinism Attack Demo
//
// Spec:
//  • Student types a short message (e.g., "yes" or "no", simulating a vote).
//  • Click "Encrypt twice" — textbook mode → identical ciphertexts → red banner
//    "Identical ciphertexts: plaintext leaked."
//  • Switch to PKCS#1 v1.5 mode → ciphertexts differ each time → green banner.
//  • "Padding bytes" panel shows random PS bytes that differ between encryptions.
//  • Toy params: 512-bit N for fast computation.

import { useState } from "react";
import { Card, Button, Output, KV, Description, Badge, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

function trunc(s, n = 52) {
  if (!s) return "—";
  return String(s).length > n ? String(s).slice(0, n) + "…" : String(s);
}

// Colour-coded hex byte row
function HexRow({ hex, label, colour }) {
  const bytes = (hex || "").match(/.{2}/g) || [];
  return (
    <div style={{ marginTop: 6 }}>
      <span style={{ fontSize: 11, color: "var(--text-muted)", marginRight: 8 }}>{label}</span>
      <span style={{ fontFamily: "monospace", fontSize: 11 }}>
        {bytes.map((b, i) => (
          <span key={i} style={{
            padding: "1px 3px", marginRight: 2, borderRadius: 3,
            background: colour || "rgba(99,179,237,0.18)",
          }}>{b}</span>
        ))}
      </span>
    </div>
  );
}

export default function PA12() {
  const [bits, setBits]       = useState(512);
  const [msg, setMsg]         = useState("yes");
  const [mode, setMode]       = useState("textbook");   // "textbook" | "pkcs15"
  const [out, setOut]         = useState(null);
  const [busy, setBusy]       = useState(false);
  const [err, setErr]         = useState(null);

  // Basic keygen / enc / dec state (kept for the advanced tab)
  const [keypair, setKeypair] = useState(null);
  const [tab, setTab]         = useState("demo");       // "demo" | "manual"
  const [mVal, setMVal]       = useState("65");
  const [cVal, setCVal]       = useState("");
  const [decVal, setDecVal]   = useState("");
  const [kBusy, setKBusy]     = useState(null);

  async function runDemo() {
    setErr(null); setBusy(true); setOut(null);
    const r = await callApi("/api/pa12/determinism_demo", { message: msg, bits });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(false);
  }

  async function genKeys() {
    setErr(null); setKBusy("kg"); setKeypair(null); setCVal(""); setDecVal("");
    const r = await callApi("/api/pa12/keygen", { bits });
    if (r.ok) setKeypair(r.data); else setErr(r.error);
    setKBusy(null);
  }

  async function encrypt() {
    if (!keypair) return;
    setErr(null); setKBusy("enc");
    const r = await callApi("/api/pa12/encrypt", { N: keypair.N, e: keypair.e, m: mVal });
    if (r.ok) setCVal(r.data.ciphertext); else setErr(r.error);
    setKBusy(null);
  }

  async function decrypt() {
    if (!keypair || !cVal) return;
    setErr(null); setKBusy("dec");
    const r = await callApi("/api/pa12/decrypt", { N: keypair.N, d: keypair.d, c: cVal });
    if (r.ok) setDecVal(r.data.plaintext); else setErr(r.error);
    setKBusy(null);
  }

  const modeData = out && (mode === "textbook" ? out.textbook : out.pkcs15);

  return (
    <div>
      <Description>
        <b>Textbook RSA</b> is deterministic: <code>c = m^e mod N</code> always gives the same
        ciphertext for the same message — so an eavesdropper who knows the candidates{" "}
        (e.g., "yes"/"no") can trivially decrypt by encrypting both and comparing.{" "}
        <b>PKCS#1 v1.5</b> prepends random non-zero padding bytes <code>PS</code>, making
        each encryption unique. Switch modes below to see the contrast.
      </Description>

      {/* ── Tab selector ── */}
      <Card title="Section">
        <div style={{ display: "flex", gap: 8 }}>
          {[{ v: "demo", l: "Determinism attack demo" }, { v: "manual", l: "Manual encrypt / decrypt" }].map(t => (
            <button key={t.v} onClick={() => setTab(t.v)} style={{
              padding: "6px 16px", borderRadius: 6, cursor: "pointer", fontSize: 13,
              border: "1px solid var(--border)",
              background: tab === t.v ? "var(--accent)" : "var(--surface2)",
              color: tab === t.v ? "#fff" : "var(--text)",
              fontWeight: tab === t.v ? 600 : 400,
            }}>{t.l}</button>
          ))}
        </div>
      </Card>

      {tab === "demo" && (
        <>
          {/* ── Setup ── */}
          <Card title="Setup">
            <div style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: "flex-end" }}>
              <div style={{ flex: 1, minWidth: 140 }}>
                <label>Message (short plaintext, e.g. a vote)</label>
                <input id="pa12-msg" type="text" value={msg}
                  onChange={(e) => setMsg(e.target.value)} />
              </div>
              <div style={{ width: 130 }}>
                <label>N bits (toy)</label>
                <select value={bits} onChange={(e) => setBits(Number(e.target.value))}
                  style={{ width: "100%", padding: "6px 10px", borderRadius: 6,
                    background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--text)" }}>
                  {[512, 1024].map(b => <option key={b} value={b}>{b}-bit</option>)}
                </select>
              </div>
              <div>
                <label>Mode</label>
                <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
                  {[{ v: "textbook", l: "Textbook RSA" }, { v: "pkcs15", l: "PKCS#1 v1.5" }].map(opt => (
                    <label key={opt.v} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 13, cursor: "pointer" }}>
                      <input type="radio" name="mode" checked={mode === opt.v}
                        onChange={() => setMode(opt.v)} />
                      {opt.l}
                    </label>
                  ))}
                </div>
              </div>
              <Button id="pa12-encrypt-twice" onClick={runDemo} loading={busy}>Encrypt twice</Button>
            </div>
          </Card>

          {/* ── Result ── */}
          {out && modeData && (
            <>
              {/* Banner */}
              {modeData.identical ? (
                <div style={{
                  padding: "12px 18px", borderRadius: 8, marginBottom: 12,
                  background: "rgba(252,129,129,0.12)", border: "1px solid rgba(252,129,129,0.5)",
                  display: "flex", alignItems: "center", gap: 12,
                }}>
                  <span style={{ fontSize: 20 }}>🔴</span>
                  <div>
                    <div style={{ fontWeight: 700, color: "#fc8181" }}>
                      Identical ciphertexts — plaintext leaked!
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
                      Textbook RSA is deterministic: same m → same c every time. An attacker who
                      knows the message space (e.g., "yes" / "no") can trivially identify the vote.
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{
                  padding: "12px 18px", borderRadius: 8, marginBottom: 12,
                  background: "rgba(72,187,120,0.10)", border: "1px solid rgba(72,187,120,0.4)",
                  display: "flex", alignItems: "center", gap: 12,
                }}>
                  <span style={{ fontSize: 20 }}>🟢</span>
                  <div>
                    <div style={{ fontWeight: 700, color: "#68d391" }}>
                      Ciphertexts differ — randomised encryption is CPA-secure!
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
                      PKCS#1 v1.5 prepends random non-zero bytes PS, so Enc(m) ≠ Enc(m) probabilistically.
                    </div>
                  </div>
                </div>
              )}

              {/* Side-by-side ciphertexts */}
              <div className="row" style={{ alignItems: "flex-start" }}>
                <Card title="Encryption #1">
                  <div style={{ fontFamily: "monospace", fontSize: 11, wordBreak: "break-all",
                    color: modeData.identical ? "#fc8181" : "#68d391" }}>
                    {modeData.c1}
                  </div>
                  {mode === "pkcs15" && (
                    <HexRow hex={out.pkcs15.ps1_hex} label="PS (rand):"
                      colour="rgba(99,179,237,0.22)" />
                  )}
                </Card>
                <Card title={`Encryption #2 ${modeData.identical ? "← identical!" : "← different ✓"}`}>
                  <div style={{ fontFamily: "monospace", fontSize: 11, wordBreak: "break-all",
                    color: modeData.identical ? "#fc8181" : "#68d391" }}>
                    {modeData.c2}
                  </div>
                  {mode === "pkcs15" && (
                    <HexRow hex={out.pkcs15.ps2_hex} label="PS (rand):"
                      colour="rgba(246,173,85,0.22)" />
                  )}
                </Card>
              </div>

              {/* Padding bytes panel (PKCS#1 only) */}
              {mode === "pkcs15" && (
                <Card title="PKCS#1 v1.5 padding bytes panel">
                  <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
                    Encoded message structure: <code>0x00 ‖ 0x02 ‖ PS ‖ 0x00 ‖ m</code>.
                    Each call generates a fresh random PS (≥ 8 non-zero bytes), making ciphertexts unique.
                  </div>

                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", fontSize: 11, fontFamily: "monospace", marginBottom: 8 }}>
                    {[
                      { label: "0x00", bg: "rgba(154,154,200,0.25)" },
                      { label: "0x02", bg: "rgba(154,154,200,0.25)" },
                      { label: "PS…", bg: "rgba(99,179,237,0.3)" },
                      { label: "0x00", bg: "rgba(154,154,200,0.25)" },
                      { label: msg, bg: "rgba(72,187,120,0.25)" },
                    ].map((seg, i) => (
                      <span key={i} style={{ padding: "3px 8px", borderRadius: 4, background: seg.bg }}>
                        {seg.label}
                      </span>
                    ))}
                  </div>

                  <HexRow hex={out.pkcs15.ps1_hex} label="PS enc#1:" colour="rgba(99,179,237,0.22)" />
                  <HexRow hex={out.pkcs15.ps2_hex} label="PS enc#2:" colour="rgba(246,173,85,0.22)" />

                  <div style={{ marginTop: 10 }}>
                    <Badge variant={out.pkcs15.ps_differ ? "success" : "error"}>
                      {out.pkcs15.ps_differ
                        ? `✓ PS bytes differ → different ciphertexts (${out.pkcs15.ps1_hex.length / 2} bytes each)`
                        : "PS bytes identical (extremely unlikely — try again)"}
                    </Badge>
                  </div>

                  <div style={{ marginTop: 10, fontSize: 11, color: "var(--text-muted)" }}>
                    EM#1: <code>{out.pkcs15.em1_hex}</code><br />
                    EM#2: <code>{out.pkcs15.em2_hex}</code>
                  </div>
                </Card>
              )}

              {/* Public params */}
              <Card title="Public parameters">
                <div style={{ fontSize: 11, fontFamily: "monospace", color: "var(--text-muted)" }}>
                  N ({out.bits}-bit): {out.N} &nbsp;·&nbsp; e = {out.e}
                </div>
              </Card>
            </>
          )}
        </>
      )}

      {/* ── Manual tab ── */}
      {tab === "manual" && (
        <>
          <Card title="Key generation">
            <div style={{ display: "flex", gap: 12, alignItems: "flex-end" }}>
              <div style={{ width: 140 }}>
                <label>Modulus bits</label>
                <input type="number" min={256} max={2048} step={128} value={bits}
                  onChange={(e) => setBits(Number(e.target.value))} />
              </div>
              <Button onClick={genKeys} loading={kBusy === "kg"}>Generate keys</Button>
            </div>
            {keypair && (
              <Output>
                <KV k="N" v={trunc(keypair.N, 60)} />
                <KV k="e" v={keypair.e} />
                <KV k="d" v={trunc(keypair.d, 60)} />
                <Badge variant="success">{keypair.bits}-bit RSA keypair ready</Badge>
              </Output>
            )}
          </Card>

          {keypair && (
            <Card title="Encrypt / decrypt (textbook)">
              <label>Plaintext m (integer &lt; N)</label>
              <input type="text" value={mVal} onChange={(e) => setMVal(e.target.value)} />
              <div style={{ marginTop: 12, display: "flex", gap: 10 }}>
                <Button onClick={encrypt} loading={kBusy === "enc"}>Encrypt</Button>
                <Button onClick={decrypt} loading={kBusy === "dec"} variant="secondary" disabled={!cVal}>Decrypt</Button>
              </div>
              {cVal && <Output><KV k="ciphertext" v={trunc(cVal)} success /></Output>}
              {decVal && (
                <Output>
                  <KV k="recovered m" v={decVal} success={decVal === mVal} />
                  <Badge variant={decVal === mVal ? "success" : "error"}>
                    {decVal === mVal ? "✓ round-trip OK" : "✗ mismatch"}
                  </Badge>
                </Output>
              )}
            </Card>
          )}
        </>
      )}

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}
