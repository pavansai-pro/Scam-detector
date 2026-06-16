const BASE = process.env.REACT_APP_API_URL || "";

export async function analyzeMessage(message) {
  const res = await fetch(`${BASE}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Analysis failed.");
  return data;
}

export async function checkHealth() {
  const res = await fetch(`${BASE}/api/health`);
  return res.json();
}
