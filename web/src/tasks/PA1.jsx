// PA#1 — One-Way Function & PRG (HILL construction).
import { useState } from "react";
import { Card, Button, Output, KV, Description, Badge, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

export default function PA1() {
  const [seed, setSeed] = useState("deadbeefcafebabe0123456789abcdef");
  const [length, setLength] = useState(32);
  const [prgOut, setPrgOut] = useState(null);
  const [owfOut, setOwfOut] = useState(null);
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);

  async function runOwf() {
    setErr(null); setBusy("owf");
    const r = await callApi("/api/pa1/owf", { x: seed });
    if (r.ok) setOwfOut(r.data); else setErr(r.error);
    setBusy(null);
  }

  async function runPrg() {
    setErr(null); setBusy("prg");
    const r = await callApi("/api/pa1/prg", { seed, length: Number(length) });
    if (r.ok) setPrgOut(r.data); else setErr(r.error);
    setBusy(null);
  }

  return (
    <div>
      <Description>
        A <b>One-Way Function</b> is easy to compute but hard to invert. We use the DLP-based OWF{" "}
        <code>f(x) = g^x mod p</code>. The <b>HILL construction</b> bootstraps any OWF (with hard-core
        predicate) into a Pseudorandom Generator that stretches an n-bit seed into arbitrarily many bits
        indistinguishable from random.
      </Description>

      <Card title="OWF — DLP" sub="f(x) = g^x mod p">
        <label>Input x (hex)</label>
        <input type="text" value={seed} onChange={(e) => setSeed(e.target.value)} />
        <div style={{ marginTop: 12 }}>
          <Button onClick={runOwf} loading={busy === "owf"}>Evaluate f(x)</Button>
        </div>
        {owfOut && (
          <Output>
            <KV k="input"  v={owfOut.input} />
            <KV k="f(x)"   v={owfOut.output} success />
            <KV k="scheme" v={owfOut.scheme} />
          </Output>
        )}
      </Card>

      <Card title="PRG — HILL construction" sub="G : {0,1}ⁿ → {0,1}^(n+ℓ)">
        <div className="row">
          <div>
            <label>Seed s (hex)</label>
            <input type="text" value={seed} onChange={(e) => setSeed(e.target.value)} />
          </div>
          <div className="narrow" style={{ width: 130 }}>
            <label>Output bytes</label>
            <input type="number" min={8} max={256} value={length} onChange={(e) => setLength(e.target.value)} />
          </div>
        </div>
        <div style={{ marginTop: 12 }}>
          <Button onClick={runPrg} loading={busy === "prg"}>Expand seed</Button>
        </div>
        {prgOut && (
          <Output>
            <KV k="seed"        v={prgOut.seed} />
            <KV k="output"      v={prgOut.output} success />
            <KV k="length"      v={`${prgOut.length} bytes`} />
            <KV k="ones-ratio"  v={prgOut.ones_ratio} />
            <div style={{ marginTop: 8 }}>
              <Badge variant={Math.abs(prgOut.ones_ratio - 0.5) < 0.05 ? "success" : "error"}>
                monobit {Math.abs(prgOut.ones_ratio - 0.5) < 0.05 ? "PASS" : "FAIL"}
              </Badge>
            </div>
          </Output>
        )}
      </Card>

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}
