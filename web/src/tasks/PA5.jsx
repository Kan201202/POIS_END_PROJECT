// PA#5 — Message Authentication Codes.
// Three tabs:
//   1. Tag / Verify (basic round-trip)
//   2. EUF-CMA forgery game — server holds hidden key, oracle signs up to 50
//      messages, student tries to forge a new (m*, t*).
//   3. Length-extension demo on naive H(k‖m), motivating HMAC.

import { useState, useEffect } from "react";
import { Card, Button, Output, KV, Description, Badge, ToggleGroup, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

const DEFAULT_KEY = "0123456789abcdef0123456789abcdef";

export default function PA5() {
  const [tab, setTab] = useState("tag");

  return (
    <div>
      <Description>
        A <b>MAC</b> gives integrity and authenticity. We use <b>CBC-MAC</b> over the message blocks.
        EUF-CMA security: an adversary with access to a signing oracle still cannot forge a valid tag
        on a new message. Naive <code>H(k‖m)</code> is broken by length-extension — that motivates HMAC.
      </Description>

      <Card title="Section">
        <ToggleGroup
          value={tab}
          onChange={setTab}
          options={[
            { label: "Tag / Verify",      value: "tag" },
            { label: "EUF-CMA forgery game", value: "forge" },
            { label: "Length-extension",  value: "lext" },
          ]}
        />
      </Card>

      {tab === "tag"   && <TagPanel />}
      {tab === "forge" && <ForgeryGame />}
      {tab === "lext"  && <LengthExtension />}
    </div>
  );
}

// ─── 1. Tag / Verify ────────────────────────────────────────────────
function TagPanel() {
  const [key, setKey] = useState(DEFAULT_KEY);
  const [msg, setMsg] = useState("Message to authenticate");
  const [tag, setTag] = useState("");
  const [vmsg, setVmsg] = useState("Message to authenticate");
  const [vout, setVout] = useState(null);
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);

  async function genTag() {
    setErr(null); setBusy("t"); setVout(null);
    const r = await callApi("/api/pa5/mac", { key, message: msg });
    if (r.ok) { setTag(r.data.tag); setVmsg(msg); } else setErr(r.error);
    setBusy(null);
  }

  async function verify() {
    if (!tag) { setErr("Generate a tag first."); return; }
    setErr(null); setBusy("v");
    const r = await callApi("/api/pa5/verify", { key, message: vmsg, tag });
    if (r.ok) setVout(r.data); else setErr(r.error);
    setBusy(null);
  }

  return (
    <>
      <Card title="Generate tag">
        <label>Key k (hex)</label>
        <input type="text" value={key} onChange={(e) => setKey(e.target.value)} />
        <div style={{ marginTop: 10 }}>
          <label>Message</label>
          <textarea value={msg} onChange={(e) => setMsg(e.target.value)} />
        </div>
        <div style={{ marginTop: 12 }}>
          <Button onClick={genTag} loading={busy === "t"}>Generate tag</Button>
        </div>
        {tag && (
          <Output>
            <KV k="tag" v={tag} success />
          </Output>
        )}
      </Card>

      <Card title="Verify tag against (k, m)">
        <label>Message to verify against the tag</label>
        <textarea value={vmsg} onChange={(e) => setVmsg(e.target.value)} />
        <div style={{ marginTop: 10 }}>
          <label>Tag (hex)</label>
          <input type="text" value={tag} onChange={(e) => setTag(e.target.value)} />
        </div>
        <div style={{ marginTop: 12 }}>
          <Button onClick={verify} loading={busy === "v"} variant="secondary">Verify</Button>
        </div>
        {vout && (
          <Output>
            <Badge variant={vout.valid ? "success" : "error"}>
              {vout.valid ? "✓ valid tag" : "✗ invalid tag"}
            </Badge>
          </Output>
        )}
      </Card>

      <ErrorBanner>{err}</ErrorBanner>
    </>
  );
}

// ─── 2. EUF-CMA forgery game ────────────────────────────────────────
function ForgeryGame() {
  const [state, setState] = useState(null);
  const [signMsg, setSignMsg] = useState("transfer 100 USD");
  const [forgeMsg, setForgeMsg] = useState("transfer 999999 USD");
  const [forgeTag, setForgeTag] = useState("");
  const [last, setLast] = useState(null);
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);

  async function refreshState() {
    const r = await callApi("/api/pa5/forgery_state", {});
    if (r.ok) setState(r.data);
  }

  useEffect(() => { refreshState(); }, []);

  async function sign() {
    setErr(null); setBusy("s");
    const r = await callApi("/api/pa5/forgery_sign", { message: signMsg });
    if (r.ok) await refreshState();
    else setErr(r.error);
    setBusy(null);
  }

  async function submit() {
    setErr(null); setBusy("f"); setLast(null);
    const r = await callApi("/api/pa5/forgery_submit", { message: forgeMsg, tag: forgeTag });
    if (r.ok) { setLast(r.data); await refreshState(); }
    else setErr(r.error);
    setBusy(null);
  }

  async function reset() {
    setErr(null); setBusy("r"); setLast(null);
    await callApi("/api/pa5/forgery_reset", {});
    await refreshState();
    setBusy(null);
  }

  return (
    <>
      <Card
        title="Oracle state"
        sub={state ? `${state.signed_count} / ${state.max_signed} oracle queries used; ${state.attempts} forgery attempts, ${state.successes} successful` : "loading…"}
        action={<Button onClick={reset} loading={busy === "r"} variant="ghost">Reset game</Button>}
      >
        <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 6 }}>
          The server holds a hidden key. You can ask it to sign messages (oracle).
          Your goal: produce a valid tag for a message <i>not</i> in the list. EUF-CMA security says
          you can't.
        </div>
        {state && state.signed.length > 0 && (
          <Output label="Signed messages (m, t) seen so far">
            {state.signed.map((s, i) => (
              <div key={i} style={{ marginBottom: 4 }}>
                <KV k={`m${i}`} v={s.message} />
                <KV k={`t${i}`} v={s.tag.slice(0, 32) + "…"} />
              </div>
            ))}
          </Output>
        )}
      </Card>

      <Card title="Step 1 — Ask the oracle to sign a message">
        <label>Message</label>
        <input type="text" value={signMsg} onChange={(e) => setSignMsg(e.target.value)} />
        <div style={{ marginTop: 12 }}>
          <Button onClick={sign} loading={busy === "s"}>Sign with hidden key (~ 3 s)</Button>
        </div>
      </Card>

      <Card title="Step 2 — Submit a forgery (m*, t*)">
        <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
          Use a message you have <i>not</i> asked the oracle to sign. Type any tag (16-byte hex).
        </div>
        <label>Forged message m*</label>
        <input type="text" value={forgeMsg} onChange={(e) => setForgeMsg(e.target.value)} />
        <div style={{ marginTop: 10 }}>
          <label>Forged tag t* (32 hex chars)</label>
          <input type="text" value={forgeTag} onChange={(e) => setForgeTag(e.target.value)}
                 placeholder="aa11bb22cc33dd44ee55ff66aabbccdd" />
        </div>
        <div style={{ marginTop: 12 }}>
          <Button onClick={submit} loading={busy === "f"} disabled={!forgeTag}>
            Submit forgery
          </Button>
        </div>
        {last && (
          <Output>
            <KV k="valid tag?"        v={String(last.valid_tag)} />
            <KV k="message in list?"  v={String(last.is_existing_message)} />
            <Badge variant={last.forgery_succeeded ? "error" : "success"}>
              {last.forgery_succeeded
                ? "⚠ forgery succeeded — MAC broken!"
                : (last.is_existing_message
                    ? "rejected (message was already signed)"
                    : "✓ forgery rejected — EUF-CMA holds")}
            </Badge>
          </Output>
        )}
      </Card>

      <ErrorBanner>{err}</ErrorBanner>
    </>
  );
}

// ─── 3. Length-extension demo ───────────────────────────────────────
function LengthExtension() {
  const [m, setM] = useState("amount=100&to=alice");
  const [suffix, setSuffix] = useState("&amount=999999&to=mallory");
  const [out, setOut] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  async function run() {
    setErr(null); setBusy(true); setOut(null);
    const r = await callApi("/api/pa5/length_extension", {
      message: m, suffix, k_len: 16,
    });
    if (r.ok) setOut(r.data); else setErr(r.error);
    setBusy(false);
  }

  return (
    <Card title="Length-extension attack on naive H(k‖m)">
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10 }}>
        Defender publishes (m, tag) where <code>tag = H(k‖m)</code>. Attacker, knowing only{" "}
        <code>m</code>, <code>tag</code> and <code>|k|</code>, computes a valid tag for{" "}
        <code>m‖pad‖m'</code> for any chosen suffix <code>m'</code> — without knowing k.
        This is why HMAC's double-hash structure is required (PA#10).
      </div>
      <label>Original message m</label>
      <input type="text" value={m} onChange={(e) => setM(e.target.value)} />
      <div style={{ marginTop: 10 }}>
        <label>Attacker's suffix m'</label>
        <input type="text" value={suffix} onChange={(e) => setSuffix(e.target.value)} />
      </div>
      <div style={{ marginTop: 12 }}>
        <Button onClick={run} loading={busy}>Run attack</Button>
      </div>

      {out && (
        <Output>
          <KV k="m"                v={out.original_message} />
          <KV k="m'"               v={out.suffix} />
          <KV k="honest tag"       v={trunc(out.honest_tag, 50)} />
          <KV k="forged message (hex)" v={trunc(out.forged_message_hex, 60)} />
          <KV k="forged tag"       v={trunc(out.forged_tag, 50)} success />
          <KV k="recomputed tag"   v={trunc(out.recomputed_tag, 50)} />
          <Badge variant={out.attack_succeeded ? "error" : "success"}>
            {out.attack_succeeded
              ? "⚠ forged tag matches recomputed tag — naive MAC broken"
              : "attack failed (forged tag != real tag)"}
          </Badge>
          <div style={{ marginTop: 6, fontSize: 12, color: "var(--text-muted)" }}>
            The attacker produced this forged tag <i>without ever seeing k</i> — by continuing the
            Merkle-Damgård chain from the public tag.
          </div>
        </Output>
      )}
      <ErrorBanner>{err}</ErrorBanner>
    </Card>
  );
}

function trunc(s, n = 50) {
  if (!s) return s;
  return s.length > n ? s.slice(0, n) + "…" : s;
}