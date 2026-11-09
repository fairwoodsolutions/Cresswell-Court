// Public availability: Airbnb blocked nights (from your Airbnb calendar link) plus your
// confirmed direct bookings (from the bookings database). Returns dates only, no personal data.
// Needs: secret AIRBNB_ICAL, and a D1 binding named DB.

function iso(s) { return s.slice(0, 4) + "-" + s.slice(4, 6) + "-" + s.slice(6, 8); }
function shift(dateIso, n) {
  const d = new Date(dateIso + "T00:00:00Z");
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}
function parseIcs(text) {
  const events = text.replace(/\r?\n[ \t]/g, "").split("BEGIN:VEVENT").slice(1);
  const out = [];
  for (const e of events) {
    const s = /DTSTART[^:\n]*:(\d{8})/.exec(e);
    const f = /DTEND[^:\n]*:(\d{8})/.exec(e);
    if (!s || !f) continue;
    const a = iso(s[1]);
    const last = shift(iso(f[1]), -1);
    if (last >= a) out.push([a, last]);
  }
  out.sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
  const merged = [];
  for (const r of out) {
    const c = merged[merged.length - 1];
    if (c && r[0] <= shift(c[1], 1)) { if (r[1] > c[1]) c[1] = r[1]; }
    else merged.push([r[0], r[1]]);
  }
  return merged;
}

const CORS = { "access-control-allow-origin": "*", "content-type": "application/json" };

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });
    let airbnb = null, direct = [];
    if (env.AIRBNB_ICAL) {
      try {
        const r = await fetch(env.AIRBNB_ICAL, { headers: { "user-agent": "Mozilla/5.0 (calendar sync)" }, cf: { cacheEverything: true, cacheTtl: 900 } });
        if (r.ok) airbnb = parseIcs(await r.text());
      } catch (e) { console.error("ical failed", String(e)); }
    }
    if (env.DB) {
      try {
        const rows = await env.DB.prepare("SELECT arrive, depart FROM bookings WHERE status = 'confirmed' ORDER BY arrive").all();
        direct = (rows.results || []).map((r) => [r.arrive, shift(r.depart, -1)]).filter((r) => r[1] >= r[0]);
      } catch (e) { console.error("db read failed", String(e)); }
    }
    if (airbnb === null && !env.DB) return new Response(JSON.stringify({ error: "calendar unavailable" }), { status: 502, headers: CORS });
    const out = { directBooked: direct, updated: new Date().toISOString() };
    if (airbnb !== null) out.airbnbBooked = airbnb;
    return new Response(JSON.stringify(out), { headers: { ...CORS, "cache-control": "public, max-age=60" } });
  },
};
