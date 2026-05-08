// PA#0 — Overview & cross-primitive reduction explorer (original A→B style).
import { useState } from "react";
import { Card, Button, Output, KV, Description, Badge, ErrorBanner, ToggleGroup, Collapse } from "../components/ui";
import { callApi } from "../api";

const PRIMITIVES = ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF", "HMAC"];

const ROUTES = {
  "OWF->PRG":   { chain: "HILL hard-core-bit construction",     pa: "PA#1" },
  "PRG->PRF":   { chain: "GGM tree construction",                pa: "PA#2" },
  "PRF->PRP":   { chain: "Luby-Rackoff 3-round Feistel",         pa: "PA#3" },
  "PRF->MAC":   { chain: "Mac_k(m) = F_k(m)",                    pa: "PA#5" },
  "PRP->MAC":   { chain: "switching lemma → PRF → MAC",          pa: "PA#5" },
  "CRHF->HMAC": { chain: "HMAC double-hash construction",        pa: "PA#10" },
  "HMAC->MAC":  { chain: "HMAC is a secure EUF-CMA MAC",         pa: "PA#10" },
  "MAC->PRF":   { chain: "MAC on uniform inputs is a PRF",       pa: "PA#5" },
  "PRG->OWF":   { chain: "f(s) = G(s) is a OWF",                 pa: "PA#1" },
  "PRF->PRG":   { chain: "G(s) = F_s(0) || F_s(1)",              pa: "PA#2" },
  "PRP->PRF":   { chain: "PRF/PRP switching lemma",              pa: "PA#3" },
};

export default function PA0() {
  const [foundation, setFoundation] = useState("AES");
  const [source, setSource] = useState("PRG");
  const [target, setTarget] = useState("PRF");
  const [direction, setDirection] = useState("forward");
  const [seed, setSeed] = useState("deadbeefcafebabe0123456789abcdef");
  const [msg, setMsg] = useState("48656c6c6f");
  const [out, setOut] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const A = direction === "forward" ? source : target;
  const B = direction === "forward" ? target : source;
  const key = `${A}->${B}`;
  const route = ROUTES[key];

  async function run() {
    setErr(null); setOut(null);
    if (source === target) { setErr("Source and target must differ."); return; }
    if (!/^[0-9a-fA-F]+$/.test(seed)) { setErr("Seed must be hex."); return; }

    setBusy(true);
    const k16 = seed.slice(0, 32).padEnd(32, "0");
    const x16 = msg.slice(0, 32).padEnd(32, "0");

    let col1 = null, col2 = null;
    let apiErr = null;

    // --- Left column: build A from foundation ---
    if (A === "PRG") {
      const r = await callApi("/api/pa1/prg", { seed: k16, length: 32 });
      if (r.ok) {
        col1 = { label: `${foundation} → PRG`, output: r.data.output };
      } else {
        apiErr = r.error;
        col1 = { label: `${foundation} → PRG`, output: `Not yet implemented (PA#1)` };
      }
    } else if (A === "PRF") {
      const r = await callApi("/api/pa2/prf", { key: k16, x: x16 });
      if (r.ok) {
        col1 = { label: `${foundation} → PRF`, output: r.data.output };
      } else {
        apiErr = r.error;
        col1 = { label: `${foundation} → PRF`, output: `Not yet implemented (PA#2)` };
      }
    } else if (A === "MAC") {
      const r = await callApi("/api/pa5/mac", { key: k16, message: "Hello" });
      if (r.ok) {
        col1 = { label: `${foundation} → MAC`, output: r.data.tag };
      } else {
        apiErr = r.error;
        col1 = { label: `${foundation} → MAC`, output: `Not yet implemented (PA#5)` };
      }
    } else {
      // Stub for primitives not yet wired (OWF, PRP, CRHF, HMAC)
      const stubPa = route ? route.pa : "—";
      col1 = { label: `${foundation} → ${A}`, output: `Not yet implemented (${stubPa})` };
    }

    // --- Right column: reduce A → B ---
    if (A === "PRG" && B === "PRF") {
      const r = await callApi("/api/pa2/prf", { key: k16, x: x16 });
      if (r.ok) {
        col2 = { label: `PRG → PRF (GGM)`, output: r.data.output };
      } else {
        apiErr = apiErr || r.error;
        col2 = { label: `PRG → PRF (GGM)`, output: `Not yet implemented (PA#2)` };
      }
    } else if (B === "MAC") {
      const r = await callApi("/api/pa5/mac", { key: k16, message: "Hello" });
      if (r.ok) {
        col2 = { label: `${A} → MAC`, output: r.data.tag };
      } else {
        apiErr = apiErr || r.error;
        col2 = { label: `${A} → MAC`, output: `Not yet implemented (PA#5)` };
      }
    } else if (route) {
      // All other known routes: show stub with PA number
      col2 = { label: `${A} → ${B}`, output: `Not yet implemented (${route.pa})` };
    } else {
      // No known route at all
      col2 = { label: `${A} → ${B}`, output: `No direct reduction path known` };
    }

    if (apiErr) setErr(apiErr);
    setOut({ col1, col2 });
    setBusy(false);
  }

  return (
    <div>
      <Description>
        The Clique Explorer demonstrates abstract reductions between Minicrypt primitives.
        Pick a foundation (<code>AES</code> or <code>DLP</code>), then build primitive A from the foundation,
        and reduce A to primitive B. The other 20 tasks let you exercise each construction directly.
      </Description>

      <Card title="Foundation & direction">
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
          <div>
            <label>Foundation</label>
            <ToggleGroup
              value={foundation}
              onChange={setFoundation}
              options={[{ label: "AES (PRP)", value: "AES" }, { label: "DLP", value: "DLP" }]}
            />
          </div>
          <div>
            <label>Direction</label>
            <ToggleGroup
              value={direction}
              onChange={setDirection}
              options={[{ label: "Forward A→B", value: "forward" }, { label: "Backward B→A", value: "backward" }]}
            />
          </div>
        </div>
      </Card>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <Card title={`Build ${A}`} sub={`from ${foundation}`}>
          <label>Source primitive</label>
          <select value={source} onChange={(e) => setSource(e.target.value)}>
            {PRIMITIVES.map((p) => <option key={p}>{p}</option>)}
          </select>
          <div style={{ marginTop: 10 }}>
            <label>Seed / key (hex)</label>
            <input type="text" value={seed} onChange={(e) => setSeed(e.target.value)} />
          </div>
          {out?.col1 && (
            <Output>
              <KV k="step" v={out.col1.label} />
              <KV k="output" v={out.col1.output} success />
            </Output>
          )}
        </Card>

        <Card title={`Reduce ${A} → ${B}`} sub={direction === "backward" ? "(backward)" : ""}>
          <label>Target primitive</label>
          <select value={target} onChange={(e) => setTarget(e.target.value)}>
            {PRIMITIVES.map((p) => <option key={p}>{p}</option>)}
          </select>
          <div style={{ marginTop: 10 }}>
            <label>Query / message (hex)</label>
            <input type="text" value={msg} onChange={(e) => setMsg(e.target.value)} />
          </div>
          {out?.col2 && (
            <Output>
              <KV k="step" v={out.col2.label} />
              <KV k="output" v={out.col2.output} success />
            </Output>
          )}
        </Card>
      </div>

      <ErrorBanner>{err}</ErrorBanner>

      <div style={{ marginTop: 14, display: "flex", justifyContent: "center", gap: 10 }}>
        <Button onClick={run} loading={busy}>{busy ? "Running…" : "Run reduction"}</Button>
      </div>

      {route && (
        <Collapse title={`Proof panel — ${key} reduction chain`}>
          <div className="kv-grid">
            <span className="k">Direction</span><span className="v">{direction}</span>
            <span className="k">Chain</span>    <span className="v">{foundation} → {A} → {B}</span>
            <span className="k">Theorem</span>  <span className="v">{route.chain}</span>
            <span className="k">Implements</span><span className="v"><Badge variant="info">{route.pa}</Badge></span>
          </div>
        </Collapse>
      )}
    </div>
  );
}
