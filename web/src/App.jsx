// CS8.401 — Programming Assignments dashboard.
// Sidebar lists all tasks; clicking one renders its dedicated panel.

import { useState, useMemo } from "react";
import { TASKS, TASK_BY_ID } from "./tasks/registry";

export default function App() {
  const [activeId, setActiveId] = useState(() => {
    const hash = (window.location.hash || "").slice(1);
    return TASK_BY_ID[hash] ? hash : "pa0";
  });

  const sections = useMemo(() => {
    const out = {};
    for (const t of TASKS) {
      (out[t.section] ??= []).push(t);
    }
    return out;
  }, []);

  const active = TASK_BY_ID[activeId];
  const ActiveComponent = active.component;

  function selectTask(id) {
    setActiveId(id);
    window.location.hash = id;
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar-header">
          <p className="sidebar-title">CS8.401</p>
          <p className="sidebar-subtitle">Principles of Information Security</p>
        </div>

        {Object.entries(sections).map(([sec, items]) => (
          <div className="nav-section" key={sec}>
            <div className="nav-section-title">{sec}</div>
            {items.map((t) => (
              <div
                key={t.id}
                className={`nav-item ${activeId === t.id ? "active" : ""}`}
                onClick={() => selectTask(t.id)}
              >
                <span className="nav-item-id">PA#{t.num}</span>
                <span className="nav-item-name">{t.name}</span>
              </div>
            ))}
          </div>
        ))}

        <div style={{ padding: "20px", marginTop: 20, borderTop: "1px solid var(--border)", fontSize: 11, color: "var(--text-faint)", lineHeight: 1.6 }}>
          Team Suicide Squad<br />
          Raj · Kanishk · Shubham · Shobhan · Swaraj
        </div>
      </aside>

      <main className="main">
        <div className="task-header">
          <div className="task-tag">PA#{active.num} · {active.section}</div>
          <h1 className="task-title">{active.name}</h1>
          <p className="task-desc">{active.short}</p>
        </div>
        <ActiveComponent />
      </main>
    </div>
  );
}
