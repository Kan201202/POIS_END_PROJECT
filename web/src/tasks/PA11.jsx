// PA#11 — Live Diffie-Hellman Exchange
//
// Spec:
//  • Two panels: Alice (left) and Bob (right), each with private exponent
//    input or a "randomise" button.
//  • Click "Exchange." App animates Alice sending g^a to Bob, Bob sending g^b to Alice.
//  • Both panels compute and display shared secret K = g^ab, shown in green when matching.
//  • "Enable Eve" checkbox inserts MITM: Eve intercepts, substitutes her own g^e,
//    and Eve's panel shows she holds both secrets.
//  • Toy params: p ≈ 2^32 safe prime for instant computation. Values in hex.

import { useState, useEffect } from "react";
import { Card, Button, Output, KV, Description, Badge, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

const ANIM_DELAY = 400;   // ms between animation steps

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

export default function PA11() {
  const [alicePriv, setAlicePriv] = useState("");   // "" = auto-random
  const [bobPriv,   setBobPriv]   = useState("");
  const [eveEnabled, setEveEnabled] = useState(false);
  const [bits, setBits]             = useState(32);

  const [out,     setOut]     = useState(null);   // normal exchange result
  const [mitmOut, setMitmOut] = useState(null);   // MITM result
  const [phase,   setPhase]   = useState(0);      // animation step 0–5
  const [busy,    setBusy]    = useState(false);
  const [err,     setErr]     = useState(null);

  function trunc(s, n = 18) {
    if (!s) return "—";
    return s.length > n ? s.slice(0, n) + "…" : s;
  }

  async function runExchange() {
    setErr(null); setBusy(true); setOut(null); setMitmOut(null); setPhase(0);

    if (eveEnabled) {
      const r = await callApi("/api/pa11/mitm", { bits });
      if (!r.ok) { setErr(r.error); setBusy(false); return; }
      // Animate phases
      for (let i = 1; i <= 5; i++) {
        await sleep(ANIM_DELAY);
        setPhase(i);
      }
      setMitmOut(r.data);
    } else {
      const body = { bits };
      if (alicePriv) body.alice_priv = alicePriv;
      if (bobPriv)   body.bob_priv   = bobPriv;
      const r = await callApi("/api/pa11/dh", body);
      if (!r.ok) { setErr(r.error); setBusy(false); return; }
      // Animate phases
      for (let i = 1; i <= 4; i++) {
        await sleep(ANIM_DELAY);
        setPhase(i);
      }
      setOut(r.data);
    }
    setBusy(false);
  }

  function randomise(who) {
    const val = Math.floor(Math.random() * 0xffffffff).toString();
    if (who === "alice") setAlicePriv(val);
    else setBobPriv(val);
  }

  const d = out || (mitmOut && {
    p: mitmOut.p, g: mitmOut.g, bits: mitmOut.bits,
    alice_priv: mitmOut.alice?.priv, alice_pub: mitmOut.alice?.pub,
    bob_priv:   mitmOut.bob?.priv,  bob_pub:   mitmOut.bob?.pub,
    shared_alice: mitmOut.alice?.shared, shared_bob: mitmOut.bob?.shared,
    match: false,
  });

  return (
    <div>
      <Description>
        In <b>Diffie-Hellman</b>, Alice and Bob exchange <code>g^a</code> and <code>g^b</code>{" "}
        publicly; both compute <code>K = g^ab</code>. Security rests on the CDH assumption.
        Unauthenticated DH is vulnerable to MITM — enable Eve below to see the attack live.
      </Description>

      {/* ── Controls ── */}
      <Card title="Parameters">
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: "flex-end" }}>
          <div style={{ width: 140 }}>
            <label>Modulus bits</label>
            <select value={bits} onChange={(e) => setBits(Number(e.target.value))}
              style={{ width: "100%", padding: "6px 10px", borderRadius: 6,
                background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--text)" }}>
              {[32, 64, 128].map(b => <option key={b} value={b}>{b} bits</option>)}
            </select>
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: 8, paddingBottom: 2, cursor: "pointer" }}>
            <input type="checkbox" checked={eveEnabled} onChange={(e) => { setEveEnabled(e.target.checked); setOut(null); setMitmOut(null); setPhase(0); }} />
            <span style={{ color: eveEnabled ? "#fc8181" : "var(--text)" }}>
              🕵️ Enable Eve (MITM)
            </span>
          </label>
          <Button id="pa11-exchange" onClick={runExchange} loading={busy}
            variant={eveEnabled ? "secondary" : "primary"}>
            Exchange
          </Button>
        </div>
      </Card>

      {/* ── Alice + Bob panels ── */}
      <div className="row" style={{ alignItems: "stretch" }}>
        {/* Alice */}
        <Card title="🔵 Alice">
          <label>Private exponent a</label>
          <div style={{ display: "flex", gap: 8 }}>
            <input type="text" value={alicePriv} placeholder="auto-random"
              onChange={(e) => setAlicePriv(e.target.value)} style={{ flex: 1 }} />
            <Button onClick={() => randomise("alice")} variant="ghost" style={{ whiteSpace: "nowrap" }}>
              ↻ Random
            </Button>
          </div>

          {d && phase >= 1 && (
            <Output style={{ marginTop: 12 }}>
              <KV k="priv a"  v={trunc(d.alice_priv)} />
              <KV k="pub g^a" v={trunc(d.alice_pub)} />
              {phase >= 3 && (
                <KV k="received from" v={eveEnabled
                  ? `Eve: ${trunc(mitmOut?.eve?.pub)}` : `Bob: ${trunc(d.bob_pub)}`} />
              )}
              {phase >= 4 && (
                <>
                  <KV k="K = g^ab" v={trunc(d.shared_alice)}
                    success={!eveEnabled && d.match} />
                  {eveEnabled && (
                    <Badge variant="error">⚠ Actually shares secret with Eve!</Badge>
                  )}
                  {!eveEnabled && d.match && (
                    <Badge variant="success">✓ Matches Bob's secret</Badge>
                  )}
                </>
              )}
            </Output>
          )}
        </Card>

        {/* Eve (MITM only) */}
        {eveEnabled && (
          <Card title="🔴 Eve (MITM)" style={{ border: "1px solid rgba(252,129,129,0.4)", background: "rgba(252,129,129,0.04)" }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
              Eve intercepts both public values, substitutes <code>g^e</code> to each party,
              and ends up knowing <b>both</b> shared secrets.
            </div>
            {mitmOut && phase >= 2 && (
              <Output>
                <KV k="priv e"          v={trunc(mitmOut.eve.priv)} />
                <KV k="pub g^e"         v={trunc(mitmOut.eve.pub)} />
                {phase >= 4 && (
                  <>
                    <KV k="K with Alice = g^ae" v={trunc(mitmOut.eve.K_with_alice)} />
                    <KV k="K with Bob  = g^be"  v={trunc(mitmOut.eve.K_with_bob)} />
                    <Badge variant="error">🕵️ Eve holds BOTH secrets!</Badge>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
                      Alice thinks she shares <code>{trunc(mitmOut.alice?.shared, 12)}</code> with Bob —
                      it's actually with Eve.
                    </div>
                  </>
                )}
              </Output>
            )}
          </Card>
        )}

        {/* Bob */}
        <Card title="🟢 Bob">
          <label>Private exponent b</label>
          <div style={{ display: "flex", gap: 8 }}>
            <input type="text" value={bobPriv} placeholder="auto-random"
              onChange={(e) => setBobPriv(e.target.value)} style={{ flex: 1 }} />
            <Button onClick={() => randomise("bob")} variant="ghost" style={{ whiteSpace: "nowrap" }}>
              ↻ Random
            </Button>
          </div>

          {d && phase >= 1 && (
            <Output style={{ marginTop: 12 }}>
              <KV k="priv b"  v={trunc(d.bob_priv)} />
              <KV k="pub g^b" v={trunc(d.bob_pub)} />
              {phase >= 2 && (
                <KV k="received from" v={eveEnabled
                  ? `Eve: ${trunc(mitmOut?.eve?.pub)}` : `Alice: ${trunc(d.alice_pub)}`} />
              )}
              {phase >= 4 && (
                <>
                  <KV k="K = g^ab" v={trunc(d.shared_bob)}
                    success={!eveEnabled && d.match} />
                  {eveEnabled && (
                    <Badge variant="error">⚠ Actually shares secret with Eve!</Badge>
                  )}
                  {!eveEnabled && d.match && (
                    <Badge variant="success">✓ Matches Alice's secret</Badge>
                  )}
                </>
              )}
            </Output>
          )}
        </Card>
      </div>

      {/* ── Animation status banner ── */}
      {busy && (
        <div style={{ textAlign: "center", fontSize: 13, color: "var(--text-muted)", marginTop: 4 }}>
          {phase === 0 && "Generating parameters…"}
          {phase === 1 && "Alice computes g^a, Bob computes g^b…"}
          {phase === 2 && "Alice → g^a → Bob channel" + (eveEnabled ? " [Eve intercepts!]" : "")}
          {phase === 3 && "Bob → g^b → Alice channel" + (eveEnabled ? " [Eve intercepts!]" : "")}
          {phase === 4 && "Computing shared secrets…"}
        </div>
      )}

      {/* ── Group params ── */}
      {d && phase >= 1 && (
        <Card title="Public group parameters">
          <div style={{ display: "flex", gap: 24, flexWrap: "wrap", fontSize: 12 }}>
            <span><span style={{ color: "var(--text-muted)" }}>p ({d.bits}-bit safe prime) = </span>
              <code>{d.p}</code></span>
            <span><span style={{ color: "var(--text-muted)" }}>g = </span>
              <code>{d.g}</code></span>
          </div>
        </Card>
      )}

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}
