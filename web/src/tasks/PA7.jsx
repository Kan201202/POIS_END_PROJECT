// PA#7 — Merkle-Damgård Chain Viewer
//
// Spec:
//  • Student types an arbitrary message (text or hex).
//  • App splits it into blocks, applies MD-strengthening padding, and displays
//    each block as a labelled box.
//  • An animated chain shows z₀ → h(z₀,M₁) → h(z₁,M₂) → … with each
//    chaining value shown in hex.
//  • Editing any block re-computes the chain from that block onwards
//    (avalanche effect).
//
// Toy params: XOR compression, block_size = 8 bytes.

import { useState, useEffect, useRef } from "react";
import { Card, Button, Description, ErrorBanner } from "../components/ui";
import { callApi } from "../api";

// ── Colour coding ────────────────────────────────────────────────────────────
const KIND_STYLE = {
  message: { background: "rgba(99,179,237,0.18)", border: "1px solid rgba(99,179,237,0.6)" },
  mixed:   { background: "rgba(246,173,85,0.18)",  border: "1px solid rgba(246,173,85,0.6)" },
  padding: { background: "rgba(154,154,200,0.12)", border: "1px dashed rgba(154,154,200,0.5)" },
};
const LEGEND = [
  { kind: "message", label: "Message bytes" },
  { kind: "mixed",   label: "Msg + pad boundary" },
  { kind: "padding", label: "MD padding" },
];

export default function PA7() {
  const [msg, setMsg]           = useState("hello world");
  const [hexInput, setHexInput] = useState(false);
  const [out, setOut]           = useState(null);
  const [overrides, setOverrides] = useState({});   // { blockIdx: hexStr }
  const [busy, setBusy]         = useState(false);
  const [err, setErr]           = useState(null);
  const [highlighted, setHl]   = useState(null);   // index of animated step

  const timerRef = useRef(null);

  async function fetchChain(ov = overrides) {
    setErr(null); setBusy(true);
    const r = await callApi("/api/pa7/chain", {
      message: msg,
      hex_input: hexInput,
      overrides: ov,
    });
    if (r.ok) setOut(r.data);
    else setErr(r.error);
    setBusy(false);
  }

  // Reset overrides when message changes
  function handleMsgChange(v) { setMsg(v); setOverrides({}); setOut(null); }

  // Animate chain steps one by one when result arrives
  useEffect(() => {
    if (!out) return;
    setHl(null);
    clearInterval(timerRef.current);
    let step = 0;
    timerRef.current = setInterval(() => {
      setHl(step);
      step++;
      if (step >= out.chain.length) clearInterval(timerRef.current);
    }, 350);
    return () => clearInterval(timerRef.current);
  }, [out]);

  // Edit a block inline → send override and recompute
  async function editBlock(idx, newHex) {
    const ov = { ...overrides, [String(idx)]: newHex };
    setOverrides(ov);
    await fetchChain(ov);
  }

  function clearEdits() {
    setOverrides({});
    fetchChain({});
  }

  return (
    <div>
      <Description>
        The <b>Merkle-Damgård transform</b> pads the message with the strengthening rule (
        <code>1 ‖ 0* ‖ |M|</code>), splits it into 8-byte blocks, and chains them through a
        compression function <code>h(z, M)</code>:{" "}
        <code>z₀ = IV, z_i = h(z_&#123;i-1&#125;, M_i)</code>. Edit any block below to watch
        the <b>avalanche effect</b> ripple through the chain.
      </Description>

      {/* ── Input ── */}
      <Card title="Input message">
        <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 10 }}>
          <label style={{ margin: 0 }}>
            <input
              type="checkbox"
              checked={hexInput}
              onChange={(e) => setHexInput(e.target.checked)}
              style={{ marginRight: 6 }}
            />
            Hex input
          </label>
        </div>
        <input
          id="pa7-message"
          type="text"
          value={msg}
          onChange={(e) => handleMsgChange(e.target.value)}
          placeholder={hexInput ? "hex bytes, e.g. deadbeef01020304" : "type your message…"}
        />
        <div style={{ marginTop: 12, display: "flex", gap: 10, flexWrap: "wrap" }}>
          <Button id="pa7-hash" onClick={() => fetchChain(overrides)} loading={busy}>
            Compute chain
          </Button>
          {Object.keys(overrides).length > 0 && (
            <Button onClick={clearEdits} variant="ghost">Clear edits</Button>
          )}
        </div>
      </Card>

      {out && (
        <>
          {/* ── Legend ── */}
          <div style={{ display: "flex", gap: 16, fontSize: 12, marginBottom: 8, flexWrap: "wrap" }}>
            {LEGEND.map((l) => (
              <span key={l.kind} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{
                  width: 14, height: 14, borderRadius: 3,
                  display: "inline-block",
                  ...KIND_STYLE[l.kind],
                }} />
                {l.label}
              </span>
            ))}
            <span style={{ color: "var(--text-muted)", marginLeft: "auto" }}>
              Block size: {out.block_size} B · IV: <code>{out.iv}</code>
            </span>
          </div>

          {/* ── Block row ── */}
          <Card title="Padded blocks (click a block to edit — avalanche demo)">
            <div style={{ overflowX: "auto", paddingBottom: 4 }}>
              <div style={{ display: "flex", gap: 0, alignItems: "stretch", minWidth: "max-content" }}>
                {/* IV node */}
                <ChainNode label="z₀ = IV" value={out.iv} color="var(--accent)" />

                {out.blocks.map((blk, idx) => {
                  const step = out.chain[idx];
                  const isActive = highlighted !== null && idx <= highlighted;
                  return (
                    <div key={idx} style={{ display: "flex", alignItems: "center" }}>
                      {/* Arrow + h() label */}
                      <div style={{ textAlign: "center", padding: "0 4px" }}>
                        <div style={{
                          fontSize: 10, color: "var(--text-muted)", marginBottom: 2,
                          opacity: isActive ? 1 : 0.35,
                          transition: "opacity 0.3s",
                        }}>
                          h(z,M{idx + 1})
                        </div>
                        <div style={{
                          fontSize: 18, color: isActive ? "var(--accent)" : "var(--text-muted)",
                          transition: "color 0.3s",
                        }}>→</div>
                      </div>

                      {/* Block box */}
                      <BlockBox
                        blk={blk}
                        step={step}
                        isActive={isActive}
                        isEdited={overrides[String(idx)] !== undefined}
                        onEdit={(hex) => editBlock(idx, hex)}
                      />
                    </div>
                  );
                })}
              </div>
            </div>
          </Card>

          {/* ── Chain table ── */}
          <Card title="Chaining values">
            <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ color: "var(--text-muted)", textAlign: "left" }}>
                  <th style={{ padding: "4px 8px" }}>Step</th>
                  <th style={{ padding: "4px 8px" }}>z_in (hex)</th>
                  <th style={{ padding: "4px 8px" }}>Block M_i (hex)</th>
                  <th style={{ padding: "4px 8px" }}>z_out = h(z_in, M_i)</th>
                </tr>
              </thead>
              <tbody>
                {out.chain.map((c, i) => (
                  <tr key={i} style={{
                    background: c.edited
                      ? "rgba(246,173,85,0.12)"
                      : i <= (highlighted ?? -1) ? "rgba(99,179,237,0.06)" : "transparent",
                    transition: "background 0.3s",
                    borderTop: "1px solid var(--border)",
                  }}>
                    <td style={{ padding: "4px 8px", color: "var(--text-muted)" }}>
                      z{i} → z{i + 1}
                    </td>
                    <td style={{ padding: "4px 8px", fontFamily: "monospace" }}>{c.from_z}</td>
                    <td style={{ padding: "4px 8px", fontFamily: "monospace" }}>
                      {c.block_hex}
                      {c.edited && <span style={{ color: "var(--accent)", marginLeft: 6 }}>✎ edited</span>}
                    </td>
                    <td style={{ padding: "4px 8px", fontFamily: "monospace", color: "var(--accent)" }}>
                      {c.to_z}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div style={{
              marginTop: 14, padding: "10px 14px",
              background: "rgba(var(--accent-rgb, 99,179,237),0.12)",
              borderRadius: 8, display: "flex", gap: 12, alignItems: "center",
            }}>
              <span style={{ color: "var(--text-muted)", fontSize: 12 }}>Final digest</span>
              <code style={{ fontSize: 14, letterSpacing: 2 }}>{out.digest}</code>
            </div>
          </Card>

          {/* ── Padded message hex ── */}
          <Card title="Padded message (hex)">
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6 }}>
              {out.num_blocks} blocks × {out.block_size} bytes = {out.num_blocks * out.block_size} bytes total.
              MD-strengthening: <code>0x80</code> + zero padding + 8-byte big-endian length.
            </div>
            <PaddedHexView hex={out.padded_hex} blockSize={out.block_size} msgLen={out.message.length} />
          </Card>
        </>
      )}

      <ErrorBanner>{err}</ErrorBanner>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function ChainNode({ label, value, color }) {
  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center",
      justifyContent: "center", padding: "6px 10px", minWidth: 80,
    }}>
      <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 4 }}>{label}</div>
      <div style={{
        fontFamily: "monospace", fontSize: 11,
        color: color || "var(--text)",
        background: "rgba(99,179,237,0.1)", border: "1px solid rgba(99,179,237,0.4)",
        borderRadius: 6, padding: "4px 8px",
      }}>
        {value}
      </div>
    </div>
  );
}

function BlockBox({ blk, step, isActive, isEdited, onEdit }) {
  const [editing, setEditing] = useState(false);
  const [editVal, setEditVal] = useState("");

  function startEdit() {
    setEditVal(blk.hex);
    setEditing(true);
  }

  function commitEdit() {
    setEditing(false);
    if (editVal !== blk.hex) onEdit(editVal);
  }

  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center", gap: 4,
    }}>
      {/* Block box */}
      <div
        title="Click to edit"
        onClick={!editing ? startEdit : undefined}
        style={{
          ...KIND_STYLE[blk.kind],
          borderRadius: 6,
          padding: "6px 10px",
          minWidth: 88,
          cursor: editing ? "default" : "pointer",
          opacity: isActive ? 1 : 0.45,
          transition: "opacity 0.3s, box-shadow 0.2s",
          boxShadow: isEdited ? "0 0 0 2px var(--accent)" : "none",
          textAlign: "center",
        }}
      >
        <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 3 }}>
          {blk.label} ({blk.kind})
        </div>
        {editing ? (
          <input
            autoFocus
            value={editVal}
            onChange={(e) => setEditVal(e.target.value)}
            onBlur={commitEdit}
            onKeyDown={(e) => { if (e.key === "Enter") commitEdit(); if (e.key === "Escape") setEditing(false); }}
            style={{
              fontFamily: "monospace", fontSize: 11, width: 90,
              background: "transparent", border: "none", borderBottom: "1px solid var(--accent)",
              color: "var(--text)", outline: "none", textAlign: "center",
            }}
          />
        ) : (
          <div style={{ fontFamily: "monospace", fontSize: 11, letterSpacing: 1 }}>
            {(blk.edited_hex || blk.hex)}
          </div>
        )}
        <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2, maxWidth: 88, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {blk.text}
        </div>
      </div>

      {/* z_out label below the block */}
      <div style={{
        fontFamily: "monospace", fontSize: 10,
        color: isActive ? "var(--accent)" : "var(--text-muted)",
        transition: "color 0.3s",
      }}>
        z{blk.index + 1}: {step.to_z}
      </div>
    </div>
  );
}

function PaddedHexView({ hex, blockSize, msgLen }) {
  const bytes = hex.match(/.{2}/g) || [];
  const byteCount = msgLen;

  return (
    <div style={{ fontFamily: "monospace", fontSize: 11, lineHeight: 1.8, wordBreak: "break-all" }}>
      {bytes.map((b, i) => {
        const byteIndex = i;
        let bg = "transparent";
        let title = `byte ${i}`;
        if (byteIndex < byteCount) {
          bg = "rgba(99,179,237,0.2)";
          title = `message byte ${i}`;
        } else if (b === "80") {
          bg = "rgba(246,173,85,0.4)";
          title = "0x80 pad marker";
        } else if (i >= bytes.length - 8) {
          bg = "rgba(154,218,82,0.25)";
          title = `length field byte ${i - (bytes.length - 8)}`;
        } else {
          bg = "rgba(154,154,200,0.15)";
          title = `zero pad byte ${i}`;
        }

        const isBlockBoundary = i > 0 && i % blockSize === 0;
        return (
          <span key={i}>
            {isBlockBoundary && <span style={{ margin: "0 3px", color: "var(--text-muted)", opacity: 0.4 }}>|</span>}
            <span title={title} style={{ background: bg, padding: "0 1px", borderRadius: 2 }}>{b}</span>
          </span>
        );
      })}
    </div>
  );
}
