// Centralized API client.

const API = "http://localhost:5000";

export async function callApi(path, body = {}) {
  try {
    const res = await fetch(`${API}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      return { ok: false, error: data.error || `HTTP ${res.status}` };
    }
    return { ok: true, data };
  } catch (e) {
    return { ok: false, error: `Cannot reach API at ${API}. Is 'python api/app.py' running?` };
  }
}
