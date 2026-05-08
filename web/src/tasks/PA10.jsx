// PA#10 — Length-extension vs HMAC: Side-by-Side Demo
//
// Spec:
//  • Left panel (broken H(k‖m)): student is shown (m, t). They type a suffix m'.
//    App computes a valid tag for m‖pad‖m' WITHOUT knowing k → "Forgery succeeded."
//  • Right panel (HMAC): same attempt → "Forgery failed" (outer hash requires k).
//  • Toggle switches underlying hash between DLP hash and SHA-256.
//  • Also keeps the original HMAC tag + Encrypt-then-HMAC panels.

import { useState } from "react";
import {
  Card, Button, Output, KV, Description, Badge, ToggleGroup, ErrorBanner,
} from "../components/ui";
import { callApi } from "../api";

const DEFAULT_KEY = "0123456789abcdef0123456789abcdef";

export default function PA10() {
  const [tab, setTab] = useState("lext");

  return (
    <div>
      <Description>
        <b>HMAC</b>: <code>HMAC_k(m) = H((k⊕opad) ‖ H((k⊕ipad) ‖ m))</code>. The double-hash
        defeats <i>length-extension</i> attacks against naive <code>H(k‖m)</code> by routing the
        inner hash through a fresh outer keyed invocation. The left panel shows the attack succeeding;
        the right shows HMAC blocking it.
      </Description>

      <Card title="Section">
        <ToggleGroup
          value={tab}
          onChange={setTab}
          options={[
            { label: "Length-ext vs HMAC", value: "lext" },
            { label: "HMAC tag / verify",  value: "hmac" },
            { label: "Encrypt-then-HMAC",  value: "eth"  },
          ]}
        />
      </Card>

      {tab === "lext" && <LextPanel />}
      {tab === "hmac" && <HmacPanel />}
      {tab === "eth"  && <EthPanel />}
    </div>
  );
}

// ─── 1. Length-extension vs HMAC side-by-side ────────────────────────────────
function LextPanel() {
  const [msg, setMsg]       = useState("amount=100&to=alice");
  const [suffix, setSuffix] = useState("&amount=999999&to=mallory");
  const [kLen, setKLen]     = useState(16);
  const [algo, setAlgo]     = useState("sha256");
  const [out, setOut]       = useState(null);
  const [busy, setBusy]     = useState(false);
  const [err, setErr]       = useState(null);

  async function run() {
    setErr(null); setBusy(true); setOut(null);
    const r = await callApi("/api/pa10/length_ext_vs_hmac", {
      message: msg, suffix, k_len: kLen, hash_algo: algo,
    });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(false);
  }

  return (
    <>
      <Card title="Setup">
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 10 }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <label>Original message m (defender publishes this + H(k‖m))</label>
            <input type="text" value={msg} onChange={(e) => setMsg(e.target.value)} />
          </div>
          <div style={{ flex: 1, minWidth: 200 }}>
            <label>Attacker's suffix m′ (appended after MD padding)</label>
            <input type="text" value={suffix} onChange={(e) => setSuffix(e.target.value)} />
          </div>
        </div>
        <div style={{ display: "flex", gap: 16, alignItems: "flex-end", flexWrap: "wrap" }}>
          <div style={{ width: 120 }}>
            <label>|k| (bytes)</label>
            <input type="number" min={8} max={32} value={kLen}
              onChange={(e) => setKLen(Number(e.target.value))} />
          </div>
          <div>
            <label>Underlying hash</label>
            <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
              {["sha256", "dlp"].map(v => (
                <label key={v} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 13, cursor: "pointer" }}>
                  <input type="radio" name="algo" value={v}
                    checked={algo === v} onChange={() => setAlgo(v)} />
                  {v === "sha256" ? "SHA-256" : "DLP Hash (PA#8)"}
                </label>
              ))}
            </div>
          </div>
          <Button id="pa10-lext-run" onClick={run} loading={busy}>Run demo</Button>
        </div>

        {out && (
          <Output label="Forged message bytes (m‖pad‖m′)">
            <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "monospace", wordBreak: "break-all" }}>
              {out.forged_msg_hex}
            </div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
              MD padding (hex): <code>{out.pad_hex}</code>
            </div>
          </Output>
        )}
      </Card>

      {/* ── Side-by-side result ── */}
      {out && (
        <div className="row" style={{ alignItems: "flex-start" }}>

          {/* Left — broken H(k‖m) */}
          <Card title="Broken: naive H(k‖m)">
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
              Defender publishes <code>(m, t)</code> where <code>t = H(k‖m)</code>. Attacker only
              knows <code>m</code>, <code>t</code>, and <code>|k|</code>. By continuing the MD
              chain from <code>t</code>, they forge a valid tag for <code>m‖pad‖m′</code> —
              <b> without ever seeing k</b>.
            </div>
            <Output>
              <KV k="honest tag H(k‖m)" v={trunc(out.naive.honest_tag, 48)} />
              <KV k="forged tag (no k!)" v={trunc(out.naive.forged_tag, 48)} success />
              <Badge variant={out.naive.forgery_succeeded ? "error" : "success"}>
                {out.naive.forgery_succeeded
                  ? "⚠ Forgery succeeded — H(k‖m) is broken!"
                  : "Forgery failed (unexpected)"}
              </Badge>
              <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-muted)" }}>
                {out.naive.explanation}
              </div>
            </Output>
          </Card>

          {/* Right — HMAC */}
          <Card title="HMAC — length-extension fails">
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
              Defender uses <code>HMAC_k(m)</code>. Attacker tries the same extension trick.
              Computing <code>HMAC_k(m‖pad‖m′)</code> requires <b>k</b> for the outer hash —
              the attacker cannot proceed without it.
            </div>
            <Output>
              <KV k="honest HMAC_k(m)" v={trunc(out.hmac.honest_tag, 48)} success />
              <KV k="attacker's guess" v={trunc(out.hmac.forged_tag, 48)} />
              <Badge variant={out.hmac.forgery_succeeded ? "error" : "success"}>
                {out.hmac.forgery_succeeded
                  ? "⚠ Forgery succeeded — HMAC broken!"
                  : "✓ Forgery failed — HMAC secure!"}
              </Badge>
              <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-muted)" }}>
                {out.hmac.explanation}
              </div>
            </Output>
          </Card>
        </div>
      )}

      <ErrorBanner>{err}</ErrorBanner>
    </>
  );
}

// ─── 2. HMAC tag + verify ─────────────────────────────────────────────────────
function HmacPanel() {
  const [key, setKey]   = useState(DEFAULT_KEY);
  const [msg, setMsg]   = useState("authenticate this message");
  const [tag, setTag]   = useState("");
  const [vMsg, setVMsg] = useState("authenticate this message");
  const [busy, setBusy] = useState(null);
  const [err, setErr]   = useState(null);

  async function computeTag() {
    setErr(null); setBusy("tag");
    const r = await callApi("/api/pa10/hmac", { key, message: msg });
    if (r.ok) { setTag(r.data.tag); setVMsg(msg); }
    else setErr(r.error);
    setBusy(null);
  }

  async function verify() {
    if (!tag) { setErr("Compute a tag first."); return; }
    setErr(null); setBusy("ver");
    const r = await callApi("/api/pa10/hmac_verify", { key, message: vMsg, tag });
    if (r.ok) setBusy({ result: r.data.valid });
    else setErr(r.error);
    setBusy(null);
  }

  const [verResult, setVerResult] = useState(null);

  async function verify2() {
    if (!tag) { setErr("Compute a tag first."); return; }
    setErr(null);
    const r = await callApi("/api/pa10/hmac_verify", { key, message: vMsg, tag });
    if (r.ok) setVerResult(r.data.valid);
    else setErr(r.error);
  }

  return (
    <>
      <Card title="Compute HMAC tag">
        <label>Key (hex)</label>
        <input type="text" value={key} onChange={(e) => setKey(e.target.value)} />
        <div style={{ marginTop: 10 }}>
          <label>Message</label>
          <textarea value={msg} onChange={(e) => setMsg(e.target.value)} />
        </div>
        <div style={{ marginTop: 12 }}>
          <Button id="pa10-hmac-tag" onClick={computeTag} loading={busy === "tag"}>Compute HMAC</Button>
        </div>
        {tag && (
          <Output>
            <KV k="tag" v={tag} success />
            <KV k="scheme" v="HMAC over DLP-Hash" />
          </Output>
        )}
      </Card>

      {tag && (
        <Card title="Verify HMAC tag">
          <label>Message to verify</label>
          <textarea value={vMsg} onChange={(e) => setVMsg(e.target.value)} />
          <div style={{ marginTop: 10 }}>
            <label>Tag (hex)</label>
            <input type="text" value={tag} onChange={(e) => setTag(e.target.value)} />
          </div>
          <div style={{ marginTop: 12 }}>
            <Button id="pa10-hmac-verify" onClick={verify2} variant="secondary">Verify</Button>
          </div>
          {verResult !== null && (
            <Output>
              <Badge variant={verResult ? "success" : "error"}>
                {verResult ? "✓ valid HMAC" : "✗ invalid HMAC"}
              </Badge>
            </Output>
          )}
        </Card>
      )}

      <ErrorBanner>{err}</ErrorBanner>
    </>
  );
}

// ─── 3. Encrypt-then-HMAC ────────────────────────────────────────────────────
function EthPanel() {
  const [kE, setKE]     = useState(DEFAULT_KEY);
  const [kM, setKM]     = useState("fedcba9876543210fedcba9876543210");
  const [msg, setMsg]   = useState("encrypted with HMAC integrity");
  const [ethOut, setEthOut] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState(null);

  async function run() {
    setErr(null); setBusy(true);
    const r = await callApi("/api/pa10/eth_encrypt", { kE, kM, message: msg });
    if (r.ok) setEthOut(r.data); else setErr(r.error);
    setBusy(false);
  }

  return (
    <>
      <Card title="Encrypt-then-HMAC (EtH)">
        <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
          <code>EtH.Enc(kE, kM, m) = (CPA_Enc(kE, m), HMAC_kM(ciphertext))</code>.
          Achieves CCA2 security: MAC check fires before decryption on any tampered input.
          Used in TLS 1.2.
        </div>
        <div className="row">
          <div>
            <label>k_E (encryption key, hex)</label>
            <input type="text" value={kE} onChange={(e) => setKE(e.target.value)} />
          </div>
          <div>
            <label>k_M (HMAC key, hex)</label>
            <input type="text" value={kM} onChange={(e) => setKM(e.target.value)} />
          </div>
        </div>
        <div style={{ marginTop: 10 }}>
          <label>Plaintext</label>
          <textarea value={msg} onChange={(e) => setMsg(e.target.value)} />
        </div>
        <div style={{ marginTop: 12 }}>
          <Button id="pa10-eth" onClick={run} loading={busy}>Encrypt + HMAC</Button>
        </div>
        {ethOut && (
          <Output>
            <KV k="nonce"      v={ethOut.nonce} />
            <KV k="ciphertext" v={ethOut.ciphertext} success />
            <KV k="HMAC tag"   v={ethOut.tag} success />
          </Output>
        )}
      </Card>

      <ErrorBanner>{err}</ErrorBanner>
    </>
  );
}

function trunc(s, n = 50) {
  if (!s) return s;
  return s.length > n ? s.slice(0, n) + "…" : s;
}
