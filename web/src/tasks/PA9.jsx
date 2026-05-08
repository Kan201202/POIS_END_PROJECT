// PA#9 — Birthday Attack: Live Demo
//
// Spec:
//  • Slider picks n ∈ {8, 10, 12, 14, 16}.
//  • Click "Run attack" → counter increments live → collision displayed.
//  • Live SVG chart: "hashes computed k" vs "collision probability P(k)"
//    overlaying theoretical curve 1 − e^(−k²/2ⁿ).
//  • Vertical marker at k = 2^(n/2); empirical collision marker overlaid.
//  • Run for n=12: confirm collision near 2^6 = 64.

import { useState, useRef } from "react";
import { Card, Button, Description, Badge, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

const N_OPTIONS = [8, 10, 12, 14, 16];

// ── Theory curve helper ───────────────────────────────────────────────────────
function theoryCurve(n, points = 80) {
  const expected = Math.pow(2, n / 2);
  const domain   = 3 * expected;
  const pts = [];
  for (let i = 0; i <= points; i++) {
    const k = (i / points) * domain;
    const p = 1 - Math.exp(-k * k / Math.pow(2, n));
    pts.push({ k, p });
  }
  return pts;
}

// ── SVG chart ────────────────────────────────────────────────────────────────
function BirthdayChart({ n, evals, collision }) {
  const W = 480, H = 200;
  const PAD = { l: 44, r: 16, t: 14, b: 36 };
  const cw = W - PAD.l - PAD.r;
  const ch = H - PAD.t - PAD.b;

  const expected = Math.pow(2, n / 2);
  const domain   = Math.max(3 * expected, (evals || 0) * 1.15 + 5);

  const pts = theoryCurve(n, 120).filter(p => p.k <= domain);

  const xScale = k  => PAD.l + (k / domain) * cw;
  const yScale = p  => PAD.t + ch - p * ch;

  const pathD = pts.map((p, i) =>
    `${i === 0 ? "M" : "L"}${xScale(p.k).toFixed(1)},${yScale(p.p).toFixed(1)}`
  ).join(" ");

  const xTicks = 5;
  const yTicks = [0, 0.25, 0.5, 0.75, 1.0];

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ display: "block", overflow: "visible" }}>
      {/* Grid */}
      {yTicks.map(p => (
        <line key={p}
          x1={PAD.l} x2={W - PAD.r}
          y1={yScale(p)} y2={yScale(p)}
          stroke="rgba(255,255,255,0.06)" strokeWidth="1"
        />
      ))}

      {/* Theory curve */}
      <path d={pathD} fill="none" stroke="#63b3ed" strokeWidth="2" opacity="0.9" />

      {/* Shaded area under curve */}
      <path
        d={`${pathD} L${xScale(pts[pts.length-1].k)},${yScale(0)} L${xScale(0)},${yScale(0)} Z`}
        fill="rgba(99,179,237,0.06)"
      />

      {/* Expected marker (vertical) at k=2^(n/2) */}
      <line
        x1={xScale(expected)} x2={xScale(expected)}
        y1={PAD.t} y2={H - PAD.b}
        stroke="#f6ad55" strokeWidth="1.5" strokeDasharray="5,3"
      />
      <text x={xScale(expected) + 4} y={PAD.t + 10} fill="#f6ad55" fontSize="10">
        2^(n/2)={Math.round(expected)}
      </text>

      {/* Empirical collision marker */}
      {evals && collision && (
        <>
          <line
            x1={xScale(evals)} x2={xScale(evals)}
            y1={PAD.t} y2={H - PAD.b}
            stroke="#68d391" strokeWidth="2" strokeDasharray="4,3"
          />
          <circle
            cx={xScale(evals)}
            cy={yScale(1 - Math.exp(-evals * evals / Math.pow(2, n)))}
            r="5" fill="#68d391" stroke="#fff" strokeWidth="1.5"
          />
          <text x={xScale(evals) + 6} y={PAD.t + 24} fill="#68d391" fontSize="10">
            k={evals}
          </text>
        </>
      )}

      {/* Axes */}
      <line x1={PAD.l} x2={W - PAD.r} y1={H - PAD.b} y2={H - PAD.b} stroke="rgba(255,255,255,0.2)" />
      <line x1={PAD.l} x2={PAD.l} y1={PAD.t} y2={H - PAD.b} stroke="rgba(255,255,255,0.2)" />

      {/* Y ticks */}
      {yTicks.map(p => (
        <g key={p}>
          <text x={PAD.l - 6} y={yScale(p) + 4} textAnchor="end" fill="rgba(255,255,255,0.45)" fontSize="9">
            {p.toFixed(2)}
          </text>
        </g>
      ))}

      {/* X ticks */}
      {Array.from({ length: xTicks + 1 }, (_, i) => {
        const k = Math.round((i / xTicks) * domain);
        return (
          <text key={i} x={xScale(k)} y={H - PAD.b + 14} textAnchor="middle" fill="rgba(255,255,255,0.45)" fontSize="9">
            {k}
          </text>
        );
      })}

      {/* Axis labels */}
      <text x={W / 2} y={H - 2} textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="10">
        k (hashes computed)
      </text>
      <text
        transform={`rotate(-90,10,${H / 2})`}
        x={10} y={H / 2}
        textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="10"
      >
        P(collision)
      </text>

      {/* Legend */}
      <line x1={W - PAD.r - 80} x2={W - PAD.r - 60} y1={PAD.t + 4} y2={PAD.t + 4} stroke="#63b3ed" strokeWidth="2" />
      <text x={W - PAD.r - 56} y={PAD.t + 8} fill="rgba(255,255,255,0.55)" fontSize="9">1−e^(−k²/2ⁿ)</text>
      <line x1={W - PAD.r - 80} x2={W - PAD.r - 60} y1={PAD.t + 17} y2={PAD.t + 17} stroke="#68d391" strokeWidth="2" strokeDasharray="4,3" />
      <text x={W - PAD.r - 56} y={PAD.t + 21} fill="rgba(255,255,255,0.55)" fontSize="9">empirical</text>
    </svg>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function PA9() {
  const [n, setN]           = useState(12);
  const [out, setOut]       = useState(null);
  const [busy, setBusy]     = useState(false);
  const [counter, setCounter] = useState(null);   // animated eval counter
  const [err, setErr]       = useState(null);
  const timerRef            = useRef(null);

  const expected = Math.pow(2, n / 2);

  async function runAttack() {
    setErr(null); setBusy(true); setOut(null); setCounter(0);
    clearInterval(timerRef.current);

    // Animate counter while server runs
    let fake = 0;
    timerRef.current = setInterval(() => {
      fake = Math.min(fake + Math.ceil(expected * 0.06), expected * 0.9);
      setCounter(Math.round(fake));
    }, 100);

    const r = await callApi("/api/pa9/birthday", { n_bits: n });
    clearInterval(timerRef.current);

    if (r.ok) {
      setOut(r.data);
      setCounter(r.data.evals);
    } else {
      setErr(r.error);
    }
    setBusy(false);
  }

  return (
    <div>
      <Description>
        The <b>birthday bound</b> says any hash with n-bit output can be broken in ~2<sup>n/2</sup>{" "}
        evaluations. Pick n with the slider, click <b>Run attack</b>, and watch the live counter hit
        a collision near the predicted mark. The chart overlays the theoretical probability{" "}
        <code>P(k) = 1 − e^(−k²/2ⁿ)</code> with the empirical collision point.
      </Description>

      {/* ── Controls ── */}
      <Card title="Birthday attack on truncated SHA-256">
        <div style={{ marginBottom: 16 }}>
          <label style={{ display: "flex", justifyContent: "space-between" }}>
            <span>Output bit-length n</span>
            <span style={{ fontFamily: "monospace", color: "var(--accent)" }}>
              n = {n} &nbsp;|&nbsp; 2<sup>n/2</sup> = {Math.round(expected)} expected evals
            </span>
          </label>
          {/* Slider */}
          <input
            id="pa9-slider"
            type="range"
            min={0} max={N_OPTIONS.length - 1} step={1}
            value={N_OPTIONS.indexOf(n)}
            onChange={(e) => { setN(N_OPTIONS[Number(e.target.value)]); setOut(null); setCounter(null); }}
            style={{ width: "100%", marginTop: 8 }}
          />
          {/* Tick labels */}
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
            {N_OPTIONS.map(v => (
              <span key={v} style={{ color: v === n ? "var(--accent)" : undefined, fontWeight: v === n ? 700 : 400 }}>
                {v}
              </span>
            ))}
          </div>
        </div>

        <Button id="pa9-run" onClick={runAttack} loading={busy}>
          Run attack (n = {n})
        </Button>

        {/* Live counter */}
        {(busy || out) && counter !== null && (
          <div style={{ marginTop: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
              <span>Hashes computed</span>
              <span style={{ fontFamily: "monospace", color: out?.collision_found ? "#68d391" : "var(--text)" }}>
                {counter.toLocaleString()}
                {out && ` / expected ~${Math.round(expected)}`}
              </span>
            </div>
            {/* Progress bar */}
            <div style={{ height: 8, borderRadius: 4, background: "rgba(99,179,237,0.12)", border: "1px solid rgba(99,179,237,0.2)", overflow: "hidden" }}>
              <div style={{
                height: "100%",
                width: `${Math.min((counter / (3 * expected)) * 100, 100)}%`,
                background: out?.collision_found
                  ? "linear-gradient(90deg,#48bb78,#68d391)"
                  : "linear-gradient(90deg,#63b3ed,#90cdf4)",
                borderRadius: 4,
                transition: "width 0.12s ease",
              }} />
            </div>
          </div>
        )}
      </Card>

      {/* ── Chart ── */}
      {(out || busy) && (
        <Card title={`Collision probability chart — n = ${n} bits`}>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8 }}>
            Blue curve: theoretical <code>1 − e^(−k²/2ⁿ)</code> &nbsp;·&nbsp;
            Orange dashed: expected collision at 2<sup>n/2</sup> = {Math.round(expected)} &nbsp;·&nbsp;
            Green dashed: empirical collision point
          </div>
          <div style={{ background: "rgba(0,0,0,0.2)", borderRadius: 8, padding: "8px 4px" }}>
            <BirthdayChart n={n} evals={out?.evals} collision={out?.collision_found} />
          </div>
        </Card>
      )}

      {/* ── Collision result ── */}
      {out && (
        <Card title="Result">
          {out.collision_found ? (
            <>
              <Badge variant="success">
                🎉 Collision found in {out.evals} evaluations
                {" "}(expected ~{out.expected_evals}, ratio {(out.evals / out.expected_evals).toFixed(2)}×)
              </Badge>

              <div style={{ display: "flex", gap: 16, marginTop: 14, flexWrap: "wrap" }}>
                <CollisionBox label="Input 1" input={out.x1} hash={out.h1} />
                <CollisionBox label="Input 2" input={out.x2} hash={out.h2} />
              </div>

              <div style={{ marginTop: 12, fontSize: 12, color: "var(--text-muted)" }}>
                Both hash to <code style={{ color: "var(--accent)" }}>{out.h1}</code> under
                the {n}-bit truncated hash. Time: {out.time_ms} ms.
              </div>
            </>
          ) : (
            <Badge variant="error">No collision in budget — {out.error}</Badge>
          )}
        </Card>
      )}

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────
function CollisionBox({ label, input, hash }) {
  return (
    <div style={{
      flex: 1, minWidth: 180,
      border: "1px solid rgba(104,211,145,0.4)",
      background: "rgba(104,211,145,0.06)",
      borderRadius: 8, padding: "10px 14px",
    }}>
      <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6 }}>{label}</div>
      <div style={{ fontFamily: "monospace", fontSize: 12, marginBottom: 4 }}>
        <span style={{ color: "var(--text-muted)" }}>x  = </span>{input}
      </div>
      <div style={{ fontFamily: "monospace", fontSize: 12 }}>
        <span style={{ color: "var(--text-muted)" }}>H(x) = </span>
        <span style={{ color: "#68d391", fontWeight: 600 }}>{hash}</span>
      </div>
    </div>
  );
}
