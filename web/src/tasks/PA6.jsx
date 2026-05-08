// PA#6 — CCA-Secure Encryption: Malleability Attack Panel
//
// Assignment spec:
//   Left  (CPA-only):  student sees C = (r, F_k(r) ⊕ m).
//                      Flip any byte → decryption succeeds → corrupted plaintext shown.
//   Right (CCA / Encrypt-then-MAC): same flip → MAC check fires → ⊥ returned.
//   Both sides update live as student changes the flip-byte index.

import { useState } from "react";
import {
  Card, Button, Output, KV, Description, Badge, ErrorBanner,
} from "../components/ui";
import { callApi } from "../api";

const DEFAULT_KE = "0123456789abcdef0123456789abcdef";
const DEFAULT_KM = "fedcba9876543210fedcba9876543210";

export default function PA6() {
  const [kE, setKE]       = useState(DEFAULT_KE);
  const [kM, setKM]       = useState(DEFAULT_KM);
  const [msg, setMsg]     = useState("Transfer $100 to Alice");
  const [bitByte, setBit] = useState(0);
  const [out, setOut]     = useState(null);
  const [busy, setBusy]   = useState(false);
  const [err, setErr]     = useState(null);

  async function runDemo() {
    setErr(null); setBusy(true); setOut(null);
    const r = await callApi("/api/pa6/malleability", {
      kE, kM, message: msg, bit_byte: bitByte,
    });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(false);
  }

  return (
    <div>
      <Description>
        <b>Malleability attack panel</b> — CPA-secure encryption is <b>malleable</b>: flipping a
        bit in the ciphertext produces a predictable, controlled change in the plaintext, with{" "}
        <em>no error</em>. Adding an EUF-CMA MAC (Encrypt-then-MAC) makes the scheme CCA2-secure:{" "}
        any tampered ciphertext returns <code>⊥</code> before decryption ever runs.
      </Description>

      {/* ── Controls ── */}
      <Card title="Setup">
        <div className="row">
          <div>
            <label>k_E (encryption key, hex)</label>
            <input type="text" value={kE} onChange={(e) => setKE(e.target.value)} />
          </div>
          <div>
            <label>k_M (MAC key, hex)</label>
            <input type="text" value={kM} onChange={(e) => setKM(e.target.value)} />
          </div>
        </div>
        <div style={{ marginTop: 10 }}>
          <label>Message</label>
          <input type="text" value={msg} onChange={(e) => setMsg(e.target.value)} />
        </div>
        <div style={{ marginTop: 10, display: "flex", gap: 16, alignItems: "flex-end" }}>
          <div style={{ width: 180 }}>
            <label>Flip byte index</label>
            <input
              id="pa6-bit-byte"
              type="number"
              min={0}
              value={bitByte}
              onChange={(e) => setBit(Number(e.target.value))}
            />
          </div>
          <Button id="pa6-run" onClick={runDemo} loading={busy}>
            Run malleability demo
          </Button>
        </div>
        <div style={{ marginTop: 6, fontSize: 12, color: "var(--text-muted)" }}>
          The server encrypts the message under <em>both</em> schemes, flips byte
          #{bitByte} of each ciphertext, then attempts decryption. Results appear below.
        </div>
      </Card>

      {/* ── Side-by-side panel ── */}
      {out && (
        <div className="row" style={{ alignItems: "flex-start" }}>

          {/* Left — CPA only */}
          <Card title="CPA-only (no MAC)">
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
              <b>C = (r, F_k(r) ⊕ m)</b> — no integrity check. The decryption oracle
              always runs, so any bit-flip produces corrupted plaintext instead of an error.
            </div>
            <Output label="Ciphertext (original)">
              <KV k="nonce"      v={out.cpa.nonce} />
              <KV k="ciphertext" v={out.cpa.ciphertext} />
            </Output>
            <Output label={`After flipping byte #${out.cpa.flipped_byte_index}`}>
              <KV k="tampered ct" v={out.cpa.ciphertext_tampered} />
            </Output>
            <Output label="Decryption result">
              {out.cpa.rejected ? (
                <Badge variant="success">Rejected (unexpected — padding error)</Badge>
              ) : (
                <>
                  <KV k="corrupted plaintext" v={out.cpa.plaintext} />
                  <Badge variant="error">
                    ⚠ decryption succeeded — plaintext is corrupted (malleability!)
                  </Badge>
                </>
              )}
            </Output>
          </Card>

          {/* Right — CCA / Encrypt-then-MAC */}
          <Card title="CCA / Encrypt-then-MAC">
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
              <b>Enc-then-MAC:</b> tag covers the ciphertext. Decryption <em>first</em> verifies
              the MAC — any tampered ciphertext returns <code>⊥</code> immediately.
            </div>
            <Output label="Ciphertext + tag (original)">
              <KV k="nonce"      v={out.cca.nonce} />
              <KV k="ciphertext" v={out.cca.ciphertext} />
              <KV k="tag"        v={out.cca.tag} success />
            </Output>
            <Output label={`After flipping byte #${out.cca.flipped_byte_index}`}>
              <KV k="tampered ct" v={out.cca.ciphertext_tampered} />
            </Output>
            <Output label="Decryption result">
              {out.cca.rejected ? (
                <>
                  <Badge variant="success">⊥ rejected — MAC verification failed</Badge>
                  <div style={{ marginTop: 6, fontSize: 12, color: "var(--text-muted)" }}>
                    The plaintext is <em>never seen</em> — exactly the CCA2 guarantee.
                  </div>
                </>
              ) : (
                <Badge variant="error">
                  ⚠ attack succeeded — CCA not working correctly!
                </Badge>
              )}
            </Output>
          </Card>
        </div>
      )}

      {/* ── Bonus: honest round-trip ── */}
      <HonestPanel kE={kE} kM={kM} />

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}

// ─── Honest encrypt / decrypt sub-panel ─────────────────────────────────────
function HonestPanel({ kE, kM }) {
  const [msg, setMsg]     = useState("Confidential & integrity-protected payload.");
  const [encOut, setEncOut] = useState(null);
  const [decOut, setDecOut] = useState(null);
  const [busy, setBusy]   = useState(null);
  const [err, setErr]     = useState(null);

  async function encrypt() {
    setErr(null); setBusy("enc"); setDecOut(null);
    const r = await callApi("/api/pa6/encrypt", { kE, kM, message: msg });
    if (r.ok) setEncOut(r.data); else setErr(r.error);
    setBusy(null);
  }

  async function decrypt() {
    if (!encOut) return;
    setErr(null); setBusy("dec");
    const r = await callApi("/api/pa6/decrypt", {
      kE, kM,
      nonce: encOut.nonce,
      ciphertext: encOut.ciphertext,
      tag: encOut.tag,
    });
    if (r.ok) setDecOut(r.data); else setErr(r.error);
    setBusy(null);
  }

  return (
    <Card title="Honest round-trip (encrypt → decrypt)">
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
        Verify the scheme works correctly end-to-end: encrypt a message, then decrypt it with
        the correct keys. The MAC tag is verified before decryption.
      </div>
      <label>Plaintext</label>
      <textarea value={msg} onChange={(e) => setMsg(e.target.value)} />
      <div style={{ marginTop: 12, display: "flex", gap: 10 }}>
        <Button id="pa6-encrypt" onClick={encrypt} loading={busy === "enc"}>
          Encrypt + tag
        </Button>
        {encOut && (
          <Button id="pa6-decrypt" onClick={decrypt} loading={busy === "dec"} variant="secondary">
            Decrypt
          </Button>
        )}
      </div>
      {encOut && (
        <Output>
          <KV k="nonce"      v={encOut.nonce} />
          <KV k="ciphertext" v={encOut.ciphertext} success />
          <KV k="tag"        v={encOut.tag} success />
        </Output>
      )}
      {decOut && (
        <Output>
          {decOut.rejected ? (
            <Badge variant="error">⊥ rejected</Badge>
          ) : (
            <>
              <KV k="plaintext" v={decOut.plaintext} success />
              <Badge variant="success">✓ decrypted correctly</Badge>
            </>
          )}
        </Output>
      )}
      <ErrorBanner>{err}</ErrorBanner>
    </Card>
  );
}
