// Private admin for Cresswell Court bookings. Sits behind Cloudflare Access (one-time email code).
// Every request is also verified in code against the Access token, so it fails closed.
// Needs: D1 binding DB; variables ACCESS_TEAM (your team name) and ACCESS_AUD (application AUD tag);
// optional AVAIL_URL (public availability Worker, to show Airbnb nights on the calendar).

const FIELDS = ["status","source","name","email","phone","guests","arrive","depart","total","amount_paid","deposit_state","marketing","heard_via","guest_notes","admin_notes"];
const STATUSES = ["request","awaiting_payment","confirmed","declined","cancelled"];
const DEPOSIT = ["none","requested","held","returned"];
const SOURCES = ["website","airbnb-enquiry","phone","email","other"];
const isDate = (s) => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s + "T00:00:00Z"));
const nightsBetween = (a, b) => Math.round((Date.parse(b + "T00:00:00Z") - Date.parse(a + "T00:00:00Z")) / 864e5);

// ---------- Access JWT verification ----------
let jwksCache = { at: 0, keys: null };
const b64uToBytes = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const b = atob(s); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
const b64uJson = (s) => JSON.parse(new TextDecoder().decode(b64uToBytes(s)));

async function getKeys(iss, force) {
  if (!force && jwksCache.keys && Date.now() - jwksCache.at < 3600e3) return jwksCache.keys;
  const r = await fetch(iss + "/cdn-cgi/access/certs");
  if (!r.ok) throw new Error("certs " + r.status);
  const j = await r.json();
  jwksCache = { at: Date.now(), keys: j.keys || [] };
  return jwksCache.keys;
}
async function verifyAccess(request, env) {
  if (!env.ACCESS_TEAM || !env.ACCESS_AUD) return null;             // not configured: deny
  const tok = request.headers.get("cf-access-jwt-assertion");
  if (!tok) return null;
  const parts = tok.split(".");
  if (parts.length !== 3) return null;
  try {
    const head = b64uJson(parts[0]), pay = b64uJson(parts[1]);
    if (head.alg !== "RS256") return null;
    const iss = "https://" + env.ACCESS_TEAM + ".cloudflareaccess.com";
    if (pay.iss !== iss) return null;
    const aud = Array.isArray(pay.aud) ? pay.aud : [pay.aud];
    if (!aud.includes(env.ACCESS_AUD)) return null;
    const now = Math.floor(Date.now() / 1000);
    if (typeof pay.exp !== "number" || pay.exp < now) return null;
    if (typeof pay.nbf === "number" && pay.nbf > now + 60) return null;
    let keys = await getKeys(iss, false);
    let jwk = keys.find((k) => k.kid === head.kid);
    if (!jwk) { keys = await getKeys(iss, true); jwk = keys.find((k) => k.kid === head.kid); }
    if (!jwk) return null;
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uToBytes(parts[2]), new TextEncoder().encode(parts[0] + "." + parts[1]));
    return ok ? (pay.email || "admin") : null;
  } catch (e) { console.error("jwt", String(e)); return null; }
}

// ---------- helpers ----------
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
function makeRef() {
  const d = new Date();
  const r = crypto.getRandomValues(new Uint32Array(1))[0].toString(36).toUpperCase().padStart(6, "0").slice(0, 5);
  return "CC" + String(d.getUTCFullYear()).slice(2) + String(d.getUTCMonth() + 1).padStart(2, "0") + "-" + r;
}
function validate(b, partial) {
  const o = {};
  for (const f of FIELDS) if (b[f] !== undefined) o[f] = b[f];
  const txt = (k, n) => { if (k in o) o[k] = String(o[k] == null ? "" : o[k]).slice(0, n); };
  txt("name", 100); txt("email", 200); txt("phone", 40); txt("heard_via", 200); txt("guest_notes", 2000); txt("admin_notes", 4000);
  for (const k of ["guests", "total", "amount_paid"]) if (k in o) o[k] = Math.max(0, Math.min(100000, Math.round(Number(o[k]) || 0)));
  if ("marketing" in o) o.marketing = o.marketing ? 1 : 0;
  if ("status" in o && !STATUSES.includes(o.status)) return { error: "bad status" };
  if ("deposit_state" in o && !DEPOSIT.includes(o.deposit_state)) return { error: "bad deposit state" };
  if ("source" in o && !SOURCES.includes(o.source)) o.source = "other";
  if ("arrive" in o && !isDate(o.arrive)) return { error: "bad arrival date" };
  if ("depart" in o && !isDate(o.depart)) return { error: "bad departure date" };
  if (!partial) {
    if (!isDate(o.arrive) || !isDate(o.depart)) return { error: "dates required" };
  }
  return { o };
}
async function overlapping(env, arrive, depart, excludeId) {
  const r = await env.DB.prepare("SELECT id, ref, name, arrive, depart FROM bookings WHERE status='confirmed' AND id != ? AND arrive < ? AND depart > ?").bind(excludeId || 0, depart, arrive).all();
  return r.results || [];
}
const csvCell = (v) => { let s = v == null ? "" : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };

// ---------- mailer (service binding) ----------
async function mailer(env, path, body) {
  if (!env.MAILER) return json({ error: "The mailer Worker is not connected yet (add the MAILER service binding to this Worker)." }, 500);
  const r = await env.MAILER.fetch("https://mailer" + path, { method: "POST", body: JSON.stringify(body) });
  let j = {}; try { j = await r.json(); } catch (e) {}
  return json(j, r.ok ? 200 : (r.status >= 400 ? r.status : 500));
}
const upsert = (env, k, v) => env.DB.prepare("INSERT INTO settings (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(k, v).run();

// ---------- API ----------
async function api(request, env, url, who) {
  const method = request.method;
  const path = url.pathname;
  if (method !== "GET" && request.headers.get("x-requested-with") !== "cc-admin") return json({ error: "bad request" }, 400);
  const now = new Date().toISOString();

  if (path === "/api/bookings" && method === "GET") {
    const r = await env.DB.prepare("SELECT * FROM bookings ORDER BY arrive DESC, id DESC").all();
    let threads = {}, unmatched = [];
    try {
      const t = await env.DB.prepare("SELECT booking_id, COUNT(*) AS n, SUM(CASE WHEN direction = 'in' AND read_at IS NULL THEN 1 ELSE 0 END) AS unread, MAX(created_at) AS last_at FROM messages WHERE kind = 'msg' AND booking_id > 0 GROUP BY booking_id").all();
      for (const x of t.results || []) threads[x.booking_id] = { n: x.n, unread: x.unread || 0, last_at: x.last_at };
      const p = await env.DB.prepare("SELECT m.booking_id, m.direction, substr(m.body,1,140) AS body FROM messages m JOIN (SELECT booking_id, MAX(id) AS mid FROM messages WHERE kind = 'msg' AND booking_id > 0 GROUP BY booking_id) x ON m.id = x.mid").all();
      for (const x of p.results || []) if (threads[x.booking_id]) { threads[x.booking_id].dir = x.direction; threads[x.booking_id].preview = x.body; }
      const u = await env.DB.prepare("SELECT id, from_addr, subject, substr(body,1,600) AS body, created_at FROM messages WHERE direction = 'in' AND (booking_id IS NULL) ORDER BY id DESC LIMIT 50").all();
      unmatched = u.results || [];
    } catch (e) { /* messages table not created yet */ }
    return json({ bookings: r.results || [], who, threads, unmatched });
  }
  if (path === "/api/export.csv" && method === "GET") {
    const q = url.searchParams, from = q.get("from") || "", to = q.get("to") || "", by = q.get("by") === "paid" ? "paid_at" : "arrive";
    if ((from && !isDate(from)) || (to && !isDate(to))) return json({ error: "bad dates" }, 400);
    const r = await env.DB.prepare("SELECT * FROM bookings WHERE (? = '' OR substr(" + by + ",1,10) >= ?) AND (? = '' OR substr(" + by + ",1,10) <= ?) ORDER BY " + by).bind(from, from, to, to).all();
    const rows = r.results || [];
    const cols = ["ref","status","source","name","email","phone","guests","arrive","depart","nights","total","amount_paid","paid_at","stripe_ref","deposit_state","marketing","heard_via","guest_notes","admin_notes","created_at","updated_at"];
    const sum = rows.filter((x) => x.status === "confirmed").reduce((t, x) => t + (x.amount_paid || 0), 0);
    const csv = [cols.join(",")].concat(rows.map((x) => cols.map((c) => csvCell(x[c])).join(","))).concat(["", csvCell("Total paid (confirmed bookings)") + ",,,,,,,,,,," + sum]).join("\r\n");
    return new Response(csv, { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": 'attachment; filename="cresswell-bookings' + (from || to ? "-" + (from || "start") + "-to-" + (to || "end") : "") + '.csv"', "cache-control": "no-store" } });
  }
  if (path === "/api/bookings" && method === "POST") {
    let b; try { b = await request.json(); } catch (e) { return json({ error: "bad json" }, 400); }
    const v = validate(b, false); if (v.error) return json(v, 400);
    const o = v.o;
    const nights = nightsBetween(o.arrive, o.depart);
    if (nights < 1 || nights > 60) return json({ error: "departure must be after arrival" }, 400);
    const status = o.status || "confirmed";
    if (status === "confirmed" && !b.force) { const c = await overlapping(env, o.arrive, o.depart, 0); if (c.length) return json({ error: "overlap", with: c }, 409); }
    const ref = makeRef();
    await env.DB.prepare("INSERT INTO bookings (ref,status,source,name,email,phone,guests,arrive,depart,nights,total,amount_paid,deposit_state,marketing,heard_via,guest_notes,admin_notes,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
      .bind(ref, status, o.source || "phone", o.name || "", o.email || "", o.phone || "", o.guests || 2, o.arrive, o.depart, nights, o.total || 0, o.amount_paid || 0, o.deposit_state || "none", o.marketing || 0, o.heard_via || "", o.guest_notes || "", o.admin_notes || "", now, now).run();
    return json({ ok: true, ref });
  }
  const m = /^\/api\/bookings\/(\d+)$/.exec(path);
  if (m && method === "PATCH") {
    const id = Number(m[1]);
    let b; try { b = await request.json(); } catch (e) { return json({ error: "bad json" }, 400); }
    const cur = await env.DB.prepare("SELECT * FROM bookings WHERE id = ?").bind(id).first();
    if (!cur) return json({ error: "not found" }, 404);
    const v = validate(b, true); if (v.error) return json(v, 400);
    const o = v.o;
    const arrive = o.arrive || cur.arrive, depart = o.depart || cur.depart;
    const nights = nightsBetween(arrive, depart);
    if (nights < 1 || nights > 60) return json({ error: "departure must be after arrival" }, 400);
    const status = o.status || cur.status;
    if (status === "confirmed" && !b.force) { const c = await overlapping(env, arrive, depart, id); if (c.length) return json({ error: "overlap", with: c }, 409); }
    const sets = [], vals = [];
    for (const k of Object.keys(o)) { sets.push(k + " = ?"); vals.push(o[k]); }
    sets.push("nights = ?", "updated_at = ?"); vals.push(nights, now);
    await env.DB.prepare("UPDATE bookings SET " + sets.join(", ") + " WHERE id = ?").bind(...vals, id).run();
    return json({ ok: true });
  }
  if (m && method === "DELETE") {
    await env.DB.prepare("DELETE FROM bookings WHERE id = ?").bind(Number(m[1])).run();
    return json({ ok: true });
  }
  if (path === "/api/purge" && method === "POST") {
    // Retention: requests/declined/cancelled older than 12 months; confirmed 6 years after departure.
    const d = new Date(); const y1 = new Date(d); y1.setUTCFullYear(d.getUTCFullYear() - 1); const y6 = new Date(d); y6.setUTCFullYear(d.getUTCFullYear() - 6);
    const a = await env.DB.prepare("DELETE FROM bookings WHERE status IN ('request','declined','cancelled') AND created_at < ?").bind(y1.toISOString()).run();
    const b2 = await env.DB.prepare("DELETE FROM bookings WHERE status = 'confirmed' AND depart < ?").bind(y6.toISOString().slice(0, 10)).run();
    return json({ ok: true, removed: ((a.meta && a.meta.changes) || 0) + ((b2.meta && b2.meta.changes) || 0) });
  }
  const mm = /^\/api\/bookings\/(\d+)\/messages$/.exec(path);
  if (mm && method === "GET") {
    const id = Number(mm[1]);
    const r = await env.DB.prepare("SELECT id, direction, kind, from_addr, to_addr, subject, body, read_at, created_at FROM messages WHERE booking_id = ? ORDER BY id ASC LIMIT 500").bind(id).all();
    await env.DB.prepare("UPDATE messages SET read_at = ? WHERE booking_id = ? AND direction = 'in' AND read_at IS NULL").bind(now, id).run();
    return json({ messages: r.results || [] });
  }
  const ms = /^\/api\/bookings\/(\d+)\/message$/.exec(path);
  if (ms && method === "POST") {
    let b = {}; try { b = await request.json(); } catch (e) {}
    return mailer(env, "/message", { id: Number(ms[1]), body: b.body, subject: b.subject });
  }
  const ma = /^\/api\/messages\/(\d+)\/(assign|dismiss)$/.exec(path);
  if (ma && method === "POST") {
    let b = {}; try { b = await request.json(); } catch (e) {}
    const target = ma[2] === "dismiss" ? 0 : Number(b.booking_id);
    if (ma[2] === "assign" && !(target > 0)) return json({ error: "Choose a booking" }, 400);
    await env.DB.prepare("UPDATE messages SET booking_id = ?, read_at = ? WHERE id = ? AND booking_id IS NULL").bind(target, ma[2] === "dismiss" ? now : null, Number(ma[1])).run();
    return json({ ok: true });
  }
  const m2 = /^\/api\/bookings\/(\d+)\/(paylink|send|markpaid|refund)$/.exec(path);
  if (m2 && method === "POST") {
    const id = Number(m2[1]);
    let b = {}; try { b = await request.json(); } catch (e) {}
    if (m2[2] === "paylink") return mailer(env, "/paylink", { id });
    if (m2[2] === "send") return mailer(env, "/send", { id, kind: b.kind });
    if (m2[2] === "refund") return mailer(env, "/refund", { id, amount: b.amount });
    const cur = await env.DB.prepare("SELECT * FROM bookings WHERE id = ?").bind(id).first();
    if (!cur) return json({ error: "not found" }, 404);
    if (!b.force) { const c = await overlapping(env, cur.arrive, cur.depart, id); if (c.length) return json({ error: "overlap", with: c }, 409); }
    const amount = b.amount != null ? Math.max(0, Math.min(100000, Math.round(Number(b.amount) || 0))) : (cur.total || 0);
    await env.DB.prepare("UPDATE bookings SET status = 'confirmed', paid_at = COALESCE(paid_at, ?), amount_paid = ?, updated_at = ? WHERE id = ?").bind(now, amount, now, id).run();
    return json({ ok: true });
  }
  if (path === "/api/settings" && method === "GET") {
    const live = await env.DB.prepare("SELECT v FROM settings WHERE k = 'emails_live'").first();
    const cfg = await env.DB.prepare("SELECT v FROM settings WHERE k = 'cfg'").first();
    let c = {}; try { c = JSON.parse((cfg && cfg.v) || "{}"); } catch (e) {}
    const fw = await env.DB.prepare("SELECT v FROM settings WHERE k = 'inbound_forward'").first();
    return json({ live: !!live && live.v === "1", cfg: c, forward: !fw || fw.v !== "0" });
  }
  if (path === "/api/settings" && method === "PUT") {
    let b; try { b = await request.json(); } catch (e) { return json({ error: "bad json" }, 400); }
    if (b.cfg) {
      const c = {}; for (const [k, v] of Object.entries(b.cfg || {})) c[String(k).slice(0, 40)] = String(v == null ? "" : v).slice(0, 3000);
      await upsert(env, "cfg", JSON.stringify(c));
      await upsert(env, "emails_live", b.live ? "1" : "0");
    }
    if (typeof b.forward === "boolean") await upsert(env, "inbound_forward", b.forward ? "1" : "0");
    return json({ ok: true });
  }
  if (path === "/api/test-email" && method === "POST") {
    let b = {}; try { b = await request.json(); } catch (e) {}
    return mailer(env, "/test", { kind: b.kind, to: who });
  }
  return json({ error: "not found" }, 404);
}

export default {
  async fetch(request, env) {
    const who = await verifyAccess(request, env);
    if (!who) return new Response("Not authorised", { status: 401, headers: { "cache-control": "no-store" } });
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith("/api/")) return await api(request, env, url, who);
      if (url.pathname === "/" || url.pathname === "/index.html") {
        return new Response(PAGE.replace("__AVAIL__", JSON.stringify(env.AVAIL_URL || "")), { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY", "referrer-policy": "no-referrer", "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self' https://*.workers.dev; img-src 'self' data:; base-uri 'none'; form-action 'self'" } });
      }
      return new Response("Not found", { status: 404 });
    } catch (e) {
      console.error("admin error", String(e));
      return json({ error: "server error" }, 500);
    }
  },
};

const PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Cresswell Court</title>
<style>
:root{--bg:#f5f5f7;--card:#fff;--ink:#1d1d1f;--grey:#6e6e73;--soft:#a1a1a6;--line:#e5e5ea;--fill:#f2f2f7;--accent:#0071e3;--accent-ink:#fff;--green:#248a3d;--green-bg:#e3f4e8;--amber:#b25e00;--amber-bg:#fff1d6;--red:#d70015;--red-bg:#fde8ea;--blue-bg:#e5f0fd;--air:#d8d8de;--shadow:0 1px 2px rgba(0,0,0,.04),0 8px 24px rgba(0,0,0,.06);color-scheme:light}
@media(prefers-color-scheme:dark){:root{--bg:#000;--card:#1c1c1e;--ink:#f5f5f7;--grey:#98989d;--soft:#636366;--line:#2c2c2e;--fill:#2c2c2e;--accent:#2997ff;--green:#30d158;--green-bg:#12301c;--amber:#ffb340;--amber-bg:#3a2a0a;--red:#ff6961;--red-bg:#3a1417;--blue-bg:#0f2a47;--air:#3a3a3c;--shadow:0 8px 24px rgba(0,0,0,.5);color-scheme:dark}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.45 -apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
button,input,select,textarea{font:inherit;color:inherit}
button{cursor:pointer}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.top{position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--bg) 82%,transparent);-webkit-backdrop-filter:saturate(180%) blur(20px);backdrop-filter:saturate(180%) blur(20px);border-bottom:1px solid var(--line)}
.top-in{max-width:1120px;margin:0 auto;padding:12px 20px;display:flex;align-items:center;gap:16px}
.brand{font-weight:650;font-size:16px;letter-spacing:-.01em;white-space:nowrap}
.brand small{display:block;font-weight:400;font-size:11px;color:var(--grey);letter-spacing:0}
.seg{display:flex;gap:2px;background:var(--fill);border-radius:10px;padding:3px;margin:0 auto}
.seg button{border:0;background:none;padding:6px 16px;border-radius:8px;font-weight:500;font-size:14px;color:var(--grey)}
.seg button.on{background:var(--card);color:var(--ink);box-shadow:0 1px 3px rgba(0,0,0,.12)}
.btn{border:0;border-radius:980px;padding:9px 18px;font-weight:500;font-size:14px;background:var(--fill);color:var(--ink);text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:6px;white-space:nowrap;transition:filter .12s}
.btn:hover{filter:brightness(.96)}.btn:active{filter:brightness(.9)}
.btn.pri{background:var(--accent);color:var(--accent-ink)}
.btn.grn{background:var(--green);color:#fff}
.btn.dng{background:var(--red-bg);color:var(--red)}
.btn.sm{padding:6px 13px;font-size:13px}
.btn.lg{padding:12px 22px;font-size:15px}
.btn[disabled]{opacity:.45;cursor:default;filter:none}
.btn.text{background:none;padding:6px 4px;color:var(--accent)}
.btn.text.dng{color:var(--red);background:none}
main{max-width:1120px;margin:0 auto;padding:24px 20px 110px}
h1{font-size:30px;letter-spacing:-.025em;margin:0;font-weight:700;line-height:1.15}
.sub{color:var(--grey);margin:4px 0 0}
h2{font-size:19px;letter-spacing:-.015em;margin:0;font-weight:650}
h3{font-size:13px;margin:0 0 10px;color:var(--grey);font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.card{background:var(--card);border-radius:18px;box-shadow:var(--shadow);padding:20px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:22px 0}
.stat{background:var(--card);border-radius:18px;box-shadow:var(--shadow);padding:16px 18px;text-align:left;border:0;display:block;width:100%}
.stat:hover{transform:translateY(-1px)}
.stat .n{font-size:34px;font-weight:700;letter-spacing:-.03em;line-height:1.1}
.stat .l{color:var(--grey);font-size:13px;margin-top:2px}
.stat.hot .n{color:var(--amber)}.stat.ok .n{color:var(--green)}
.cols{display:grid;grid-template-columns:1.25fr 1fr;gap:16px;align-items:start}
.sechead{display:flex;align-items:baseline;justify-content:space-between;margin:0 0 12px}
.item{display:flex;gap:12px;align-items:center;padding:13px 0;border-top:1px solid var(--line)}
.item:first-child{border-top:0;padding-top:2px}
.dot{flex:none;width:10px;height:10px;border-radius:50%;background:var(--soft)}
.dot.amber{background:#ff9f0a}.dot.red{background:var(--red)}.dot.blue{background:var(--accent)}.dot.green{background:#34c759}
.item .t{flex:1;min-width:0}
.item .t b{font-weight:600;display:block}
.item .t span{color:var(--grey);font-size:13px;display:block}
.empty{text-align:center;color:var(--grey);padding:26px 10px}
.empty .big{font-size:34px;margin-bottom:4px}
.chip{flex:none;width:46px;text-align:center;border-radius:11px;background:var(--fill);padding:5px 0 4px;line-height:1.1}
.chip b{display:block;font-size:19px;font-weight:700}.chip i{font-style:normal;font-size:11px;color:var(--grey);text-transform:uppercase;letter-spacing:.04em}
.chip.in{background:var(--green-bg)}.chip.in i,.chip.in b{color:var(--green)}
.chip.out{background:var(--blue-bg)}.chip.out i,.chip.out b{color:var(--accent)}
.chip.air{background:var(--air)}
.pill{display:inline-block;padding:2px 10px;border-radius:980px;font-size:12px;font-weight:600;background:var(--fill);color:var(--grey);white-space:nowrap}
.pill.request{background:var(--amber-bg);color:var(--amber)}.pill.awaiting_payment{background:var(--blue-bg);color:var(--accent)}.pill.confirmed{background:var(--green-bg);color:var(--green)}.pill.declined,.pill.cancelled{background:var(--red-bg);color:var(--red)}
.now{background:var(--green-bg);border-radius:18px;padding:16px 20px;margin:0 0 16px;display:flex;gap:12px;align-items:center;justify-content:space-between;color:var(--green)}
.now b{color:var(--ink)}
.bar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:18px 0 14px}
.bar .seg{margin:0}
.bar input[type=search]{flex:1;min-width:160px;max-width:300px;border:0;background:var(--fill);border-radius:10px;padding:9px 14px}
.list{background:var(--card);border-radius:18px;box-shadow:var(--shadow);overflow:hidden}
.row{display:flex;gap:14px;align-items:center;padding:14px 18px;border-top:1px solid var(--line);width:100%;border-left:0;border-right:0;border-bottom:0;background:none;text-align:left}
.row:first-child{border-top:0}
.row:hover{background:var(--fill)}
.av{flex:none;width:40px;height:40px;border-radius:50%;background:var(--fill);display:grid;place-items:center;font-weight:600;color:var(--grey)}
.row .t{flex:1;min-width:0}.row .t b{font-weight:600;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.row .t span{color:var(--grey);font-size:13px;display:block}
.row .r{text-align:right;flex:none}.row .r span{display:block;font-size:13px;color:var(--grey);margin-top:3px}
.row .go{color:var(--soft);font-size:18px}
.grp{padding:10px 18px 6px;background:var(--fill);font-size:12px;font-weight:600;color:var(--grey);text-transform:uppercase;letter-spacing:.05em}
.calhead{display:flex;align-items:center;gap:10px;margin:0 0 14px}
.calhead h2{flex:1;font-size:24px}
.cal{display:grid;grid-template-columns:repeat(7,1fr);gap:4px;background:var(--card);border-radius:18px;box-shadow:var(--shadow);padding:12px}
.cal .dw{text-align:center;font-size:12px;font-weight:600;color:var(--grey);padding:6px 0}
.cd{border:0;border-radius:10px;background:var(--fill);min-height:78px;padding:6px 7px;text-align:left;display:flex;flex-direction:column;justify-content:space-between;overflow:hidden;position:relative}
.cd .num{font-size:14px;font-weight:600}
.cd .lb{font-size:11px;line-height:1.2;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block}
.cd.e{background:none;cursor:default}
.cd.conf{background:#0071e3;color:#fff}.cd.req{background:#ffb020;color:#3a2600}.cd.pay{background:#d6e8ff;color:#004a99;box-shadow:inset 0 0 0 2px #0071e3}.cd.air{background:#d70015;color:#fff}
@media(prefers-color-scheme:dark){.cd.conf{background:#0a84ff;color:#fff}.cd.pay{background:#0f2a47;color:#8cc4ff;box-shadow:inset 0 0 0 2px #0a84ff}.cd.air{background:#e5303a;color:#fff}.cd.req{background:#ffb340;color:#2a1c00}}
.cd.conf.today .num,.cd.air.today .num,.cd.req.today .num{background:#fff;color:#1d1d1f}
.cd.past{opacity:.55}
.cd.today .num{background:var(--accent);color:#fff;border-radius:50%;width:24px;height:24px;display:grid;place-items:center;margin:-2px 0 0 -3px}
.leg{display:flex;gap:16px;flex-wrap:wrap;color:var(--grey);font-size:13px;margin:14px 2px 0}
.leg i{display:inline-block;width:12px;height:12px;border-radius:4px;margin-right:6px;vertical-align:-1px}

.navn{display:inline-block;min-width:18px;padding:0 6px;margin-left:6px;border-radius:980px;background:var(--red);color:#fff;font-size:11px;font-weight:700;line-height:18px;text-align:center}
.tlist{max-height:380px;overflow-y:auto;display:flex;flex-direction:column;gap:6px;padding:4px 2px 10px;margin:6px 0 4px;-webkit-overflow-scrolling:touch}
.tday{align-self:center;font-size:11px;font-weight:600;color:var(--soft);text-transform:uppercase;letter-spacing:.05em;margin:8px 0 2px}
.tsys{align-self:center;font-size:12px;color:var(--soft);text-align:center;padding:2px 8px}
.bub{max-width:82%;padding:9px 13px;border-radius:18px;line-height:1.4}
.bub .bt{white-space:pre-wrap;word-wrap:break-word;overflow-wrap:anywhere}
.bub .bm{font-size:11px;margin-top:4px;opacity:.65}
.bub.in{align-self:flex-start;background:var(--fill);color:var(--ink);border-bottom-left-radius:6px}
.bub.out{align-self:flex-end;background:var(--accent);color:var(--accent-ink);border-bottom-right-radius:6px}
.tcomp{border-top:1px solid var(--line);padding-top:12px;margin-top:6px}
.tcomp textarea{width:100%;min-height:74px;resize:vertical}
.tcomp .qr{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0 2px}
.tcomp .qr button{border:1px solid var(--line);background:none;color:var(--accent);border-radius:980px;padding:4px 11px;font-size:12.5px;cursor:pointer}
.tcomp .sendrow{display:flex;gap:10px;align-items:center;justify-content:space-between;margin-top:8px}
.tcomp .sendrow span{font-size:12px;color:var(--grey);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.udot{width:10px;height:10px;border-radius:50%;background:var(--accent);flex:none}
.prev{display:block;color:var(--grey);font-size:13.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
.prev.un{color:var(--ink);font-weight:600}
.um{padding:14px 0;border-top:1px solid var(--line)}.um:first-of-type{border-top:0}
.um pre{white-space:pre-wrap;font:inherit;margin:6px 0 10px;color:var(--grey);max-height:160px;overflow:auto}
.um .btnrow{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.um select{max-width:100%;padding:8px 10px;border-radius:10px;border:1px solid var(--line);background:var(--card);color:var(--ink);font:inherit;font-size:14px}
.scrim{position:fixed;inset:0;background:rgba(0,0,0,.35);z-index:40;opacity:0;pointer-events:none;transition:opacity .2s}
.scrim.on{opacity:1;pointer-events:auto}
.sheet{position:fixed;top:0;right:0;bottom:0;width:min(560px,100%);background:var(--bg);z-index:41;transform:translateX(104%);transition:transform .28s cubic-bezier(.2,.8,.2,1);display:flex;flex-direction:column;box-shadow:-10px 0 40px rgba(0,0,0,.18)}
.sheet.on{transform:none}
.sh-top{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--line);background:var(--card)}
.sh-top b{font-size:13px;color:var(--grey);font-weight:500}
.x{border:0;background:var(--fill);width:32px;height:32px;border-radius:50%;font-size:18px;line-height:1;color:var(--grey)}
.sh-body{flex:1;overflow:auto;padding:18px;display:flex;flex-direction:column;gap:14px;-webkit-overflow-scrolling:touch}
.sh-foot{padding:12px 18px calc(12px + env(safe-area-inset-bottom));border-top:1px solid var(--line);background:var(--card);display:flex;gap:10px;justify-content:flex-end;align-items:center}
.sh-foot .msg{margin-right:auto;color:var(--grey);font-size:13px}
.hero h2{font-size:26px;letter-spacing:-.025em}
.hero .meta{color:var(--grey);margin:4px 0 12px}
.hero .acts{display:flex;gap:8px;flex-wrap:wrap}
.next{border-radius:16px;padding:16px;background:var(--card);box-shadow:var(--shadow)}
.next.req{background:var(--amber-bg)}.next.pay{background:var(--blue-bg)}.next.ok{background:var(--green-bg)}
.next p{margin:0 0 12px}
.next .acts{display:flex;gap:8px;flex-wrap:wrap}
.chk{display:flex;gap:10px;align-items:center;padding:8px 0;border-top:1px solid rgba(128,128,128,.18)}
.chk:first-of-type{border-top:0}
.chk .ic{flex:none;width:22px;height:22px;border-radius:50%;display:grid;place-items:center;font-size:13px;font-weight:700;background:var(--fill);color:var(--soft)}
.chk.done .ic{background:#34c759;color:#fff}.chk.bad .ic{background:var(--red);color:#fff}.chk.todo .ic{background:#ff9f0a;color:#fff}
.chk .t{flex:1;min-width:0;font-weight:500}.chk .t small{display:block;color:var(--grey);font-weight:400;font-size:12.5px}
.money{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;text-align:center;margin-bottom:12px}
.money div{background:var(--fill);border-radius:12px;padding:10px 4px}
.money b{display:block;font-size:20px;letter-spacing:-.02em}.money span{font-size:12px;color:var(--grey)}
.prog{height:6px;background:var(--fill);border-radius:99px;overflow:hidden;margin:0 0 12px}.prog i{display:block;height:100%;background:#34c759}
.kv{display:flex;justify-content:space-between;gap:12px;padding:7px 0;border-top:1px solid var(--line);font-size:14px}
.kv:first-of-type{border-top:0}.kv span{color:var(--grey)}.kv b{font-weight:500;text-align:right;word-break:break-word}
details{background:var(--card);border-radius:16px;box-shadow:var(--shadow)}
details>summary{list-style:none;cursor:pointer;padding:14px 18px;font-weight:600;display:flex;justify-content:space-between;align-items:center}
details>summary::-webkit-details-marker{display:none}
details>summary:after{content:"\\203A";color:var(--soft);font-size:20px;transition:transform .15s}
details[open]>summary:after{transform:rotate(90deg)}
details>.in{padding:0 18px 18px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.g2 .full{grid-column:1/-1}
label.f{display:block;font-size:12.5px;color:var(--grey);font-weight:500}
label.f input,label.f select,label.f textarea{display:block;width:100%;margin-top:5px;border:1px solid var(--line);background:var(--card);border-radius:10px;padding:10px 12px;font-size:15px}
label.f textarea{min-height:84px;resize:vertical}
label.f input:focus,label.f select:focus,label.f textarea:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:transparent}
.tog{display:flex;gap:12px;align-items:center;justify-content:space-between;padding:4px 0}
.tog input{appearance:none;-webkit-appearance:none;flex:none;width:51px;height:31px;border-radius:99px;background:var(--soft);position:relative;border:0;margin:0;cursor:pointer;transition:background .2s}
.tog input:after{content:"";position:absolute;top:2px;left:2px;width:27px;height:27px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.3);transition:transform .2s}
.tog input:checked{background:#34c759}.tog input:checked:after{transform:translateX(20px)}
.more{display:flex;flex-direction:column;align-items:flex-start;gap:2px;padding:0 14px 12px}
.warn{background:var(--amber-bg);color:var(--amber);border-radius:12px;padding:10px 14px;font-size:13.5px;font-weight:500}
.modal{position:fixed;inset:0;z-index:60;display:grid;place-items:center;padding:20px;background:rgba(0,0,0,.4)}
.dlg{background:var(--card);border-radius:20px;padding:22px;width:min(400px,100%);box-shadow:0 20px 60px rgba(0,0,0,.35)}
.dlg h2{font-size:18px;margin-bottom:6px}.dlg p{margin:0 0 14px;color:var(--grey);white-space:pre-line}
.dlg .btns{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
.dlg label.f{margin-top:10px}
.toast{position:fixed;left:50%;bottom:calc(88px + env(safe-area-inset-bottom));transform:translate(-50%,20px);background:#1d1d1f;color:#fff;padding:12px 18px;border-radius:14px;z-index:70;font-size:14px;max-width:min(520px,92vw);opacity:0;pointer-events:none;transition:all .25s;box-shadow:0 10px 30px rgba(0,0,0,.35)}
.toast.on{opacity:1;transform:translate(-50%,0)}.toast.err{background:var(--red)}
.set{display:flex;flex-direction:column;gap:14px;max-width:720px}
.set .card h2{margin-bottom:4px}.set .card .sub{margin:0 0 14px;font-size:13.5px}
.set .stack{display:flex;flex-direction:column;gap:12px}
.btnrow{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}
.linkbtn{display:block}
@media(max-width:820px){
 .cols{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}
 .top-in{padding:10px 16px}.brand small{display:none}
 .top .seg{position:fixed;left:12px;right:12px;bottom:calc(10px + env(safe-area-inset-bottom));z-index:30;margin:0;padding:4px;border-radius:16px;background:color-mix(in srgb,var(--card) 88%,transparent);-webkit-backdrop-filter:blur(20px);backdrop-filter:blur(20px);box-shadow:var(--shadow)}
 .top .seg button{flex:1;padding:10px 4px;font-size:13px}
 .top .spacer{flex:1}
 main{padding:18px 14px 110px}h1{font-size:26px}
 .sheet{width:100%}
 .cd{min-height:58px;padding:4px 5px}.cd .lb{font-size:9.5px}
 .row .r span{display:none}
 .g2{grid-template-columns:1fr}
}
</style></head><body>
<header class="top"><div class="top-in">
 <div class="brand">Cresswell Court<small>3 Cresswell Court, Tenby</small></div>
 <nav class="seg" id="nav"><button data-t="today">Today</button><button data-t="inbox">Inbox<span class="navn" id="inboxN" style="display:none"></span></button><button data-t="cal">Calendar</button><button data-t="book">Bookings</button><button data-t="set">Settings</button></nav>
 <div class="spacer"></div>
 <button class="btn pri" id="add">+ New booking</button>
</div></header>
<main id="view"></main>
<div class="scrim" id="scrim"></div>
<aside class="sheet" id="sheet" role="dialog" aria-modal="true" aria-label="Details"></aside>
<div class="toast" id="toast" role="status"></div>
<script>
var AVAIL=__AVAIL__, T={}, UNM=[], B=[], air=[], WHO="", tab="today", bf="action", bq="", calOff=0, openId=null, dirty=false, toastT=null;
var $=function(i){return document.getElementById(i)};
function h(tag,attrs,kids){var e=document.createElement(tag);for(var k in (attrs||{})){var v=attrs[k];if(v==null||v===false)continue;if(k==="class")e.className=v;else if(k==="text")e.textContent=v;else if(k.slice(0,2)==="on")e[k]=v;else e.setAttribute(k,v)}(kids||[]).forEach(function(c){if(c==null||c===false)return;e.appendChild(typeof c==="string"?document.createTextNode(c):c)});return e}
function pad(n){return String(n).padStart(2,"0")}
function key(d){return d.getFullYear()+"-"+pad(d.getMonth()+1)+"-"+pad(d.getDate())}
function dt(s){return new Date(s+"T12:00:00")}
function nice(s){return dt(s).toLocaleDateString("en-GB",{weekday:"short",day:"numeric",month:"short"})}
function niceY(s){return dt(s).toLocaleDateString("en-GB",{weekday:"short",day:"numeric",month:"short",year:"numeric"})}
function gbp(n){return "£"+(n||0).toLocaleString("en-GB")}
function diff(a,b){return Math.round((dt(b)-dt(a))/864e5)}
function todayK(){return key(new Date())}
function inDays(n){var d=new Date();d.setDate(d.getDate()+n);return key(d)}
function ago(iso){if(!iso)return "";var m=Math.round((Date.now()-Date.parse(iso))/6e4);if(m<60)return m<=1?"just now":m+" min ago";var hh=Math.round(m/60);if(hh<24)return hh+" hr ago";var d=Math.round(hh/24);return d+" day"+(d===1?"":"s")+" ago"}
function when(s){var n=diff(todayK(),s);if(n===0)return "today";if(n===1)return "tomorrow";if(n>1&&n<8)return "in "+n+" days";return nice(s)}
var LBL={request:"New request",awaiting_payment:"Awaiting payment",confirmed:"Confirmed",declined:"Declined",cancelled:"Cancelled"};
function pill(s){return h("span",{class:"pill "+s,text:LBL[s]||s})}
function isActive(b){return b.status==="request"||b.status==="awaiting_payment"||b.status==="confirmed"}
function hasNote(b,t){return String(b.admin_notes||"").indexOf(t)>=0}
function bookingsOn(k){return B.filter(function(b){return isActive(b)&&b.arrive<=k&&k<b.depart})}
function airOn(k){for(var i=0;i<air.length;i++)if(k>=air[i][0]&&k<=air[i][1])return true;return false}
function bal(b){return Math.max(0,(b.total||0)-(b.amount_paid||0))}
function api(method,path,body){return fetch(path,{method:method,headers:{"content-type":"application/json","x-requested-with":"cc-admin"},body:body?JSON.stringify(body):undefined}).then(function(r){return r.json().then(function(j){return{status:r.status,j:j}}).catch(function(){return{status:r.status,j:{}}})})}
function toast(t,err){var e=$("toast");e.textContent=t;e.className="toast on"+(err?" err":"");clearTimeout(toastT);toastT=setTimeout(function(){e.className="toast"},err?6000:3500)}

/* ---------- dialogs ---------- */
function dlg(o){return new Promise(function(res){
  var done=function(v){m.remove();document.removeEventListener("keydown",kd,true);res(v)};
  var fields=(o.fields||[]).map(function(f){
    var el=f.type==="select"?h("select",{id:"dl_"+f.id},f.options.map(function(x){var op=h("option",{value:x[0],text:x[1]});if(x[0]===f.value)op.selected=true;return op})):h("input",{id:"dl_"+f.id,type:f.type||"text",value:f.value==null?"":String(f.value),placeholder:f.placeholder||""});
    return h("label",{class:"f"},[f.label,el])});
  var go=h("button",{class:"btn "+(o.danger?"dng":"pri"),text:o.ok||"OK",onclick:function(){var out={};(o.fields||[]).forEach(function(f){out[f.id]=$("dl_"+f.id).value});done(o.fields?out:true)}});
  var m=h("div",{class:"modal",onclick:function(e){if(e.target===m)done(null)}},[h("div",{class:"dlg",role:"alertdialog"},[h("h2",{text:o.title}),o.text?h("p",{text:o.text}):null].concat(fields).concat([h("div",{class:"btns"},[o.hideCancel?null:h("button",{class:"btn",text:"Cancel",onclick:function(){done(null)}}),go])]))]);
  var kd=function(e){if(e.key==="Escape"){e.stopPropagation();done(null)}else if(e.key==="Enter"&&e.target.tagName!=="TEXTAREA"){e.preventDefault();go.click()}};
  document.addEventListener("keydown",kd,true);document.body.appendChild(m);var f1=m.querySelector("input,select");(f1||go).focus();
})}

/* ---------- sheet ---------- */
function openSheet(label,body,foot){
  var s=$("sheet");s.textContent="";
  s.appendChild(h("div",{class:"sh-top"},[h("b",{text:label}),h("button",{class:"x",type:"button","aria-label":"Close",text:"×",onclick:function(){closeSheet()}})]));
  s.appendChild(h("div",{class:"sh-body",id:"shbody"},body));
  if(foot)s.appendChild(h("div",{class:"sh-foot"},foot));
  $("scrim").classList.add("on");s.classList.add("on");dirty=false;
}
function closeSheet(force){
  if(dirty&&!force){dlg({title:"Discard changes?",text:"You have unsaved changes on this booking.",ok:"Discard",danger:true}).then(function(v){if(v)closeSheet(true)});return}
  $("sheet").classList.remove("on");$("scrim").classList.remove("on");openId=null;dirty=false;
}
$("scrim").onclick=function(){closeSheet()};
document.addEventListener("keydown",function(e){if(e.key==="Escape"&&$("sheet").classList.contains("on")&&!document.querySelector(".modal"))closeSheet()});

/* ---------- data ---------- */
function load(){return api("GET","/api/bookings").then(function(r){B=r.j.bookings||[];WHO=r.j.who||"";T=r.j.threads||{};UNM=r.j.unmatched||[];badge();return fetch(AVAIL).then(function(x){return x.json()}).catch(function(){return{}})}).then(function(a){air=a.airbnbBooked||[];render();if(openId)refreshSheet()}).catch(function(){toast("Could not load bookings. Try refreshing.",true)})}
function refreshSheet(){var b=B.filter(function(x){return x.id===openId})[0];if(b&&!dirty)bookingSheet(b);else if(!b)closeSheet(true)}

/* ---------- navigation ---------- */
function go(t){tab=t;try{history.replaceState(null,"","#"+t)}catch(e){}render();window.scrollTo(0,0)}
function render(){
  document.querySelectorAll("#nav button").forEach(function(b){b.classList.toggle("on",b.dataset.t===tab)});
  var v=$("view");v.textContent="";
  if(tab==="today")return today(v);
  if(tab==="inbox")return inbox(v);
  if(tab==="cal")return cal(v);
  if(tab==="book")return books(v);
  if(tab==="set")return settings(v);
}
document.querySelectorAll("#nav button").forEach(function(b){b.onclick=function(){if(dirty){closeSheet();return}closeSheet(true);go(b.dataset.t)}});
$("add").onclick=function(){bookingSheet(null)};


/* ---------- messages ---------- */
var BASET=document.title,QR=[["Thanks for your message","Hello {n},\\n\\nThank you for your message. "],["Looking forward","Hello {n},\\n\\nThank you for booking direct. We are looking forward to welcoming you, and your arrival details will follow by email nearer the time. "],["Arrival time?","Hello {n},\\n\\nPlease let us know roughly what time you expect to arrive, and we will make sure everything is ready. "]];
function badge(){var n=0;for(var k in T)n+=T[k].unread||0;n+=UNM.length;var e=$("inboxN");if(e){e.textContent=n||"";e.style.display=n?"":"none"}try{document.title=(n?"("+n+") ":"")+BASET}catch(x){}}
function hm(iso){var d=new Date(iso);return d.toLocaleTimeString("en-GB",{hour:"2-digit",minute:"2-digit"})}
function fn1(b){return String(b.name||"").trim().split(/\\s+/)[0]||"Guest"}
var curSubj="";
function drawMsgs(list,msgs,b){
  list.textContent="";curSubj="";
  var vis=msgs;
  if(!vis.length){list.appendChild(h("p",{class:"sub",style:"text-align:center;margin:18px 8px",text:b.email?"No messages yet. What you write here is emailed to "+b.email+", and their replies appear in this thread.":"This booking has no email address, so messages cannot be sent."}));return}
  var last="";
  vis.forEach(function(m){
    var day=new Date(m.created_at).toDateString();
    if(day!==last){last=day;list.appendChild(h("div",{class:"tday",text:new Date(m.created_at).toLocaleDateString("en-GB",{weekday:"short",day:"numeric",month:"short"})}))}
    if(m.kind==="auto"){list.appendChild(h("div",{class:"tsys",text:"Email sent: "+m.subject+" · "+hm(m.created_at)}));return}
    var out=m.direction==="out";
    if(!out&&m.subject)curSubj=/^re:/i.test(m.subject)?m.subject:"Re: "+m.subject;
    list.appendChild(h("div",{class:"bub "+(out?"out":"in")},[h("div",{class:"bt",text:m.body}),h("div",{class:"bm",text:(out?"You":fn1(b))+" · "+hm(m.created_at)})]))
  });
  list.scrollTop=list.scrollHeight;
}
function refreshThread(id){
  var list=$("tlist");if(!list)return Promise.resolve();
  var b=B.filter(function(x){return x.id===id})[0];if(!b)return Promise.resolve();
  return api("GET","/api/bookings/"+id+"/messages").then(function(r){
    if(r.status>=400||!$("tlist"))return;
    var n=(r.j.messages||[]).length;
    if(list.dataset.n!==String(n)){list.dataset.n=n;drawMsgs(list,r.j.messages||[],b)}
    if(T[id]&&T[id].unread){T[id].unread=0;badge()}
  });
}
function threadCard(b){
  var list=h("div",{class:"tlist",id:"tlist"}),ta=h("textarea",{id:"tmsg",placeholder:"Write a message to "+fn1(b)+"…"}),btn=h("button",{class:"btn pri",type:"button",text:"Send"});
  var card=h("div",{class:"card",id:"msgcard"},[h("h3",{text:"Messages"}),list]);
  if(!b.email){card.appendChild(h("p",{class:"sub",text:"Add the guest's email address to this booking to message them."}));return card}
  var qr=h("div",{class:"qr"},QR.map(function(q){return h("button",{type:"button",text:q[0],onclick:function(){var v=q[1].replace("{n}",fn1(b));ta.value=ta.value?ta.value+"\\n\\n"+v:v;ta.focus();ta.setSelectionRange(ta.value.length,ta.value.length)}})}));
  function send(){
    var t=ta.value.trim();if(!t){toast("Write a message first.",true);return}
    btn.disabled=true;btn.textContent="Sending…";
    api("POST","/api/bookings/"+b.id+"/message",{body:t,subject:curSubj||undefined}).then(function(x){
      btn.disabled=false;btn.textContent="Send";
      if(x.status>=400){toast(x.j.error||"The message could not be sent.",true);return}
      ta.value="";toast("Sent to "+b.email+".");list.dataset.n="";refreshThread(b.id);
    }).catch(function(){btn.disabled=false;btn.textContent="Send";toast("The message could not be sent.",true)});
  }
  btn.onclick=send;
  ta.addEventListener("keydown",function(e){if((e.ctrlKey||e.metaKey)&&e.key==="Enter"){e.preventDefault();send()}});
  card.appendChild(h("div",{class:"tcomp"},[ta,qr,h("div",{class:"sendrow"},[h("span",{text:"Emailed to "+b.email+" from booking@cresswellcourt.co.uk"}),btn])]));
  setTimeout(function(){refreshThread(b.id)},0);
  return card;
}
function openThread(id){openB(id);setTimeout(function(){var c=$("msgcard");if(c)c.scrollIntoView({block:"center"})},350)}
function inbox(v){
  v.appendChild(h("h1",{text:"Inbox"}));
  v.appendChild(h("p",{class:"sub",text:"Messages with your guests. What you write is sent as an email from booking@cresswellcourt.co.uk, and replies come back here."}));
  if(UNM.length){
    var uc=h("div",{class:"card",style:"margin-top:20px"},[h("h3",{text:"Not matched to a booking"}),h("p",{class:"sub",style:"margin-top:4px",text:"These came from an address that is not on any booking. Link each to a booking, or dismiss it."})]);
    UNM.forEach(function(m){
      var sel=h("select",{});sel.appendChild(h("option",{value:"",text:"Choose a booking…"}));
      B.slice(0,80).forEach(function(b){sel.appendChild(h("option",{value:b.id,text:(b.name||"Guest")+" · "+nice(b.arrive)+" · "+b.ref}))});
      uc.appendChild(h("div",{class:"um"},[h("b",{text:m.from_addr}),h("span",{class:"sub",style:"margin-left:8px",text:ago(m.created_at)}),h("div",{style:"color:var(--grey);font-size:13.5px",text:m.subject||"(no subject)"}),h("pre",{text:m.body}),
        h("div",{class:"btnrow"},[sel,h("button",{class:"btn sm pri",type:"button",text:"Link",onclick:function(){if(!sel.value){toast("Choose a booking first.",true);return}api("POST","/api/messages/"+m.id+"/assign",{booking_id:Number(sel.value)}).then(function(x){if(x.status>=400){toast(x.j.error||"Could not link.",true);return}toast("Linked.");load()})}}),h("button",{class:"btn sm",type:"button",text:"Dismiss",onclick:function(){api("POST","/api/messages/"+m.id+"/dismiss",{}).then(function(){load()})}})])]))});
    v.appendChild(uc);
  }
  var rows=B.filter(function(b){return T[b.id]}).sort(function(a,b){var ua=T[a.id].unread>0,ub=T[b.id].unread>0;if(ua!==ub)return ua?-1:1;return T[a.id].last_at<T[b.id].last_at?1:-1});
  var card=h("div",{class:"card",style:"margin-top:20px;padding:6px 18px"});
  if(!rows.length)card.appendChild(h("p",{class:"sub",style:"padding:22px 0;text-align:center",text:"No conversations yet. Open any booking and use Message to start one."}));
  rows.forEach(function(b){var th=T[b.id];
    card.appendChild(h("button",{class:"row",style:"padding-left:0;padding-right:0",type:"button",onclick:function(){openThread(b.id)}},[
      h("div",{class:"av",text:((b.name||"?").trim()[0]||"?").toUpperCase()}),
      h("div",{class:"t",style:"min-width:0"},[h("b",{text:b.name||"(no name)"}),h("span",{class:"prev"+(th.unread>0?" un":""),text:(th.dir==="out"?"You: ":"")+(th.preview||"")}),h("span",{style:"font-size:12px;color:var(--soft)",text:nice(b.arrive)+" → "+nice(b.depart)+" · "+b.ref})]),
      h("div",{style:"display:flex;flex-direction:column;align-items:flex-end;gap:6px;flex:none"},[h("span",{style:"font-size:12px;color:var(--soft)",text:ago(th.last_at)}),th.unread>0?h("span",{class:"udot"}):null])]))});
  v.appendChild(card);
}
function poll(){
  if(document.hidden)return;
  api("GET","/api/bookings").then(function(r){
    if(r.status>=400||!r.j.bookings)return;
    var before=JSON.stringify([T,UNM]),prev=0,now=0;for(var k in T)prev+=T[k].unread||0;
    B=r.j.bookings;T=r.j.threads||{};UNM=r.j.unmatched||[];badge();
    for(var k2 in T)now+=T[k2].unread||0;
    if(now>prev)toast("New message from a guest.");
    if(JSON.stringify([T,UNM])===before)return;
    if(openId){if($("tlist"))refreshThread(openId)}
    else if(tab==="inbox"||tab==="today")render();
  }).catch(function(){});
}
setInterval(poll,45000);
document.addEventListener("visibilitychange",function(){if(!document.hidden)poll()});

/* ---------- Today ---------- */
function todos(){
  var t=todayK(),out=[];
  B.forEach(function(b){
    if(b.status==="request")out.push({lvl:"amber",pri:1,t:"New request from "+(b.name||"guest"),s:niceY(b.arrive)+" to "+niceY(b.depart)+" · "+b.nights+" nights · "+gbp(b.total)+" · received "+ago(b.created_at),b:b,a:"Review"});
    else if(b.status==="awaiting_payment"){var age=Math.round((Date.now()-Date.parse(b.link_sent_at||b.updated_at||b.created_at))/864e5);out.push({lvl:age>=2?"red":"blue",pri:2,t:"Waiting for payment: "+(b.name||"guest"),s:gbp(bal(b))+" due · "+nice(b.arrive)+(age>=2?" · link sent "+age+" days ago, consider a nudge":""),b:b,a:"Open"})}
    else if(b.status==="confirmed"&&b.depart>=t){
      if(b.source!=="airbnb-enquiry"&&!hasNote(b,"AIRBNB BLOCKED"))out.push({lvl:"amber",pri:3,t:"Block the dates on Airbnb",s:(b.name||"guest")+" · "+nice(b.arrive)+" to "+nice(b.depart),b:b,a:"Done",fn:function(){return markBlocked(b)}});
      if(bal(b)>0)out.push({lvl:"red",pri:2,t:"Balance outstanding: "+gbp(bal(b)),s:(b.name||"guest")+" · arrives "+when(b.arrive),b:b,a:"Open"});
      if(!hasNote(b,"GUEST DETAILS RECEIVED")&&b.arrive<=inDays(21))out.push({lvl:"blue",pri:4,t:"Guest details not received yet",s:(b.name||"guest")+" · arrives "+when(b.arrive),b:b,a:"Open"});
      if(b.deposit_state==="requested")out.push({lvl:"blue",pri:4,t:"Damage deposit requested, not yet received",s:(b.name||"guest")+" · arrives "+when(b.arrive),b:b,a:"Open"});
    }
  });
  B.forEach(function(b){var th=T[b.id];if(th&&th.unread>0)out.push({lvl:"red",pri:0,t:"New message from "+(b.name||"guest"),s:(th.preview||"").slice(0,90),b:b,a:"Reply",fn:function(){openThread(b.id)}})});
  if(UNM.length)out.push({lvl:"amber",pri:0,t:UNM.length+(UNM.length>1?" emails":" email")+" not matched to a booking",s:UNM[0].from_addr+" · "+(UNM[0].subject||"(no subject)"),a:"Review",fn:function(){go("inbox")}});
  return out.sort(function(a,b){return a.pri-b.pri});
}
function markBlocked(b){var n=String(b.admin_notes||"");return api("PATCH","/api/bookings/"+b.id,{admin_notes:(n?n+"\\n":"")+"AIRBNB BLOCKED (marked done "+todayK()+")"}).then(function(x){if(x.status>=400){toast(x.j.error||"Could not save.",true);return}toast("Marked as done.");load()})}
function today(v){
  var t=todayK(),h24=new Date().getHours(),hi=h24<12?"Good morning":h24<18?"Good afternoon":"Good evening";
  var act=B.filter(isActive),reqs=B.filter(function(b){return b.status==="request"}),pays=B.filter(function(b){return b.status==="awaiting_payment"});
  var conf=B.filter(function(b){return b.status==="confirmed"}),wk=conf.filter(function(b){return b.arrive>=t&&b.arrive<=inDays(7)});
  var stay=conf.filter(function(b){return b.arrive<=t&&t<b.depart})[0];
  var nextA=conf.filter(function(b){return b.arrive>t}).sort(function(a,b){return a.arrive<b.arrive?-1:1})[0];
  var yr=String(new Date().getFullYear()),rev=conf.filter(function(b){return b.arrive.slice(0,4)===yr}).reduce(function(s,b){return s+(b.amount_paid||0)},0);
  v.appendChild(h("h1",{text:hi}));
  v.appendChild(h("p",{class:"sub",text:new Date().toLocaleDateString("en-GB",{weekday:"long",day:"numeric",month:"long",year:"numeric"})}));
  v.appendChild(h("div",{class:"stats"},[
    stat(reqs.length,"New requests",reqs.length?"hot":"",function(){bf="action";go("book")}),
    stat(pays.length,"Awaiting payment"+(pays.length?" ("+gbp(pays.reduce(function(s,b){return s+bal(b)},0))+")":""),"",function(){bf="action";go("book")}),
    stat(wk.length,"Arriving in the next 7 days",wk.length?"ok":"",function(){bf="up";go("book")}),
    stat(stay?"In house":(nextA?diff(t,nextA.arrive)+"d":"–"),stay?stay.name+" until "+nice(stay.depart):(nextA?"Until next arrival ("+(nextA.name||"guest")+")":"No upcoming direct stays"),"",function(){go("cal")})]));
  var left=h("div",{class:"card"},[h("div",{class:"sechead"},[h("h2",{text:"Needs your attention"})])]);
  var td=todos();
  if(!td.length)left.appendChild(h("div",{class:"empty"},[h("div",{class:"big",text:"✓"}),"You are all caught up."]));
  td.forEach(function(x){left.appendChild(h("div",{class:"item"},[h("span",{class:"dot "+x.lvl}),h("div",{class:"t"},[h("b",{text:x.t}),h("span",{text:x.s})]),h("button",{class:"btn sm"+(x.fn?" pri":""),text:x.a,onclick:function(){if(x.fn)x.fn();else openB(x.b.id)}})]))});
  var right=h("div",{},[]);
  if(stay)right.appendChild(h("div",{class:"now"},[h("div",{},[h("b",{text:stay.name||"Guest"}),h("div",{text:"Staying now · checks out "+when(stay.depart)})]),h("button",{class:"btn sm",text:"Open",onclick:function(){openB(stay.id)}})]));
  var up=h("div",{class:"card"},[h("div",{class:"sechead"},[h("h2",{text:"Coming up"}),h("span",{class:"sub",text:"next 30 days"})])]);
  var ev=[],lim=inDays(30);
  conf.concat(B.filter(function(b){return b.status==="awaiting_payment"})).forEach(function(b){
    if(b.arrive>=t&&b.arrive<=lim)ev.push({d:b.arrive,k:"in",b:b});
    if(b.depart>=t&&b.depart<=lim)ev.push({d:b.depart,k:"out",b:b});
  });
  air.forEach(function(r){if(r[0]>=t&&r[0]<=lim)ev.push({d:r[0],k:"air",r:r})});
  ev.sort(function(a,b){return a.d<b.d?-1:a.d>b.d?1:(a.k==="out"?-1:1)});
  if(!ev.length)up.appendChild(h("div",{class:"empty",text:"Nothing in the next 30 days."}));
  ev.forEach(function(e){
    var d=dt(e.d),c=h("div",{class:"chip "+e.k},[h("b",{text:String(d.getDate())}),h("i",{text:d.toLocaleDateString("en-GB",{month:"short"})})]);
    var tt=e.k==="air"?"Airbnb booking":(e.k==="in"?"Check-in: ":"Check-out: ")+(e.b.name||"guest");
    var ss=e.k==="air"?"Nights "+nice(e.r[0])+" to "+nice(e.r[1]):when(e.d)+(e.k==="in"?" · "+e.b.nights+" nights · "+e.b.guests+" guest"+(e.b.guests===1?"":"s"):"")+(e.b.status==="awaiting_payment"?" · not yet paid":"");
    var row=h("div",{class:"item"},[c,h("div",{class:"t"},[h("b",{text:tt}),h("span",{text:ss})]),e.b?h("span",{class:"go",text:"›"}):null]);
    if(e.b){row.style.cursor="pointer";row.onclick=function(){openB(e.b.id)}}
    up.appendChild(row)});
  right.appendChild(up);
  right.appendChild(h("p",{class:"sub",style:"margin:14px 6px 0;font-size:13px",text:"Direct bookings paid for "+yr+": "+gbp(rev)}));
  v.appendChild(h("div",{class:"cols"},[left,right]));
}
function stat(n,label,cls,fn){return h("button",{class:"stat "+(cls||""),type:"button",onclick:fn},[h("div",{class:"n",text:String(n)}),h("div",{class:"l",text:label})])}

/* ---------- Calendar ---------- */
function cal(v){
  var now=new Date(),first=new Date(now.getFullYear(),now.getMonth()+calOff,1),dim=new Date(first.getFullYear(),first.getMonth()+1,0).getDate(),lead=(first.getDay()+6)%7,t=todayK();
  v.appendChild(h("div",{class:"calhead"},[h("h2",{text:first.toLocaleDateString("en-GB",{month:"long",year:"numeric"})}),
    h("button",{class:"btn sm",text:"Today",onclick:function(){calOff=0;render()}}),
    h("button",{class:"btn sm","aria-label":"Previous month",text:"‹",onclick:function(){calOff--;render()}}),
    h("button",{class:"btn sm","aria-label":"Next month",text:"›",onclick:function(){calOff++;render()}})]));
  var g=h("div",{class:"cal"},["Mon","Tue","Wed","Thu","Fri","Sat","Sun"].map(function(x){return h("div",{class:"dw",text:x})}));
  for(var i=0;i<lead;i++)g.appendChild(h("div",{class:"cd e"}));
  for(var d=1;d<=dim;d++){(function(d){
    var k=first.getFullYear()+"-"+pad(first.getMonth()+1)+"-"+pad(d),bs=bookingsOn(k),cls="cd",lb="";
    var arr=B.filter(function(b){return isActive(b)&&b.arrive===k})[0],dep=B.filter(function(b){return isActive(b)&&b.depart===k})[0];
    if(bs.some(function(b){return b.status==="confirmed"}))cls+=" conf";else if(bs.some(function(b){return b.status==="request"}))cls+=" req";else if(bs.length)cls+=" pay";else if(airOn(k))cls+=" air";
    if(k<t)cls+=" past";if(k===t)cls+=" today";
    if(arr)lb=(arr.name||"Guest").split(" ")[0];else if(dep&&!bs.length)lb="Check-out";else if(!bs.length&&airOn(k)&&!airOn(inDays(diff(t,k)-1)))lb="Airbnb";
    g.appendChild(h("button",{class:cls,type:"button",onclick:function(){day(k)}},[h("span",{class:"num",text:String(d)}),h("span",{class:"lb",text:lb})]))})(d)}
  v.appendChild(g);
  v.appendChild(h("div",{class:"leg"},[h("span",{},[h("i",{style:"background:#0071e3"}),"Our bookings"]),h("span",{},[h("i",{style:"background:#d6e8ff;box-shadow:inset 0 0 0 2px #0071e3"}),"Awaiting payment"]),h("span",{},[h("i",{style:"background:#ffb020"}),"Request (dates not held)"]),h("span",{},[h("i",{style:"background:#d70015"}),"Airbnb"]),h("span",{text:"Tap a day for details."})]));
}
function day(k){
  var bs=B.filter(function(b){return isActive(b)&&((b.arrive<=k&&k<b.depart)||b.depart===k)});
  if(bs.length===1&&bs[0].depart!==k){openB(bs[0].id);return}
  var body=[h("div",{class:"hero"},[h("h2",{text:niceY(k)})])];
  var c=h("div",{class:"card"},[]);
  bs.forEach(function(b){c.appendChild(h("button",{class:"row",style:"padding-left:0;padding-right:0",type:"button",onclick:function(){closeSheet(true);openB(b.id)}},[h("div",{class:"t"},[h("b",{text:b.name||"Guest"}),h("span",{text:(b.depart===k?"Checks out today":nice(b.arrive)+" to "+nice(b.depart))+" · "+b.ref})]),pill(b.status),h("span",{class:"go",text:"›"})]))});
  if(!bs.length)c.appendChild(h("p",{style:"margin:0",class:"sub",text:airOn(k)?"Booked on Airbnb. Guest details are in your Airbnb inbox.":"This night is free."}));
  else if(airOn(k))c.appendChild(h("p",{class:"sub",text:"Also blocked on Airbnb: check for a clash."}));
  body.push(c);
  openSheet("Day",body,[h("button",{class:"btn pri",text:"Add booking from this date",onclick:function(){bookingSheet(null,k)}})]);
}

/* ---------- Bookings list ---------- */
function books(v){
  var t=todayK();
  v.appendChild(h("h1",{text:"Bookings"}));
  var tabs=[["action","Needs action"],["up","Upcoming"],["past","Past"],["all","All"]];
  var seg=h("div",{class:"seg"},tabs.map(function(x){return h("button",{type:"button",class:bf===x[0]?"on":"",text:x[1],onclick:function(){bf=x[0];render()}})}));
  var q=h("input",{type:"search",placeholder:"Search name, email or reference",value:bq,"aria-label":"Search"});
  q.oninput=function(){bq=q.value;drawList()};
  v.appendChild(h("div",{class:"bar"},[seg,q]));
  var holder=h("div",{id:"blist"});v.appendChild(holder);drawList();
  function drawList(){
    var t=todayK(),list=B.filter(function(b){
      if(bq){var s=(b.name+" "+b.email+" "+b.ref+" "+b.phone).toLowerCase();if(s.indexOf(bq.toLowerCase())<0)return false}
      if(bf==="action")return b.status==="request"||b.status==="awaiting_payment"||(b.status==="confirmed"&&b.depart>=t&&(bal(b)>0||(b.source!=="airbnb-enquiry"&&!hasNote(b,"AIRBNB BLOCKED"))));
      if(bf==="up")return isActive(b)&&b.depart>=t;
      if(bf==="past")return b.depart<t;
      return true});
    list.sort(function(a,b){return bf==="up"?(a.arrive<b.arrive?-1:1):bf==="action"?(a.created_at<b.created_at?1:-1):(a.arrive<b.arrive?1:-1)});
    holder.textContent="";
    if(!list.length){holder.appendChild(h("div",{class:"list"},[h("div",{class:"empty"},[h("div",{class:"big",text:bf==="action"?"✓":"–"}),bq?"No bookings match your search.":bf==="action"?"Nothing needs action.":"Nothing here yet."])]));return}
    var box=h("div",{class:"list"}),lastM="";
    list.forEach(function(b){
      var m=dt(b.arrive).toLocaleDateString("en-GB",{month:"long",year:"numeric"});
      if(bf!=="action"&&m!==lastM){box.appendChild(h("div",{class:"grp",text:m}));lastM=m}
      var owe=b.status==="confirmed"||b.status==="awaiting_payment"?(bal(b)>0?gbp(bal(b))+" due":"Paid "+gbp(b.amount_paid)):"";
      box.appendChild(h("button",{class:"row",type:"button",onclick:function(){openB(b.id)}},[h("div",{class:"av",text:((b.name||"?").trim()[0]||"?").toUpperCase()}),h("div",{class:"t"},[h("b",{text:b.name||"(no name)"}),h("span",{text:nice(b.arrive)+" → "+nice(b.depart)+" · "+b.nights+" night"+(b.nights===1?"":"s")+" · "+b.guests+" guest"+(b.guests===1?"":"s")})]),h("div",{class:"r"},[pill(b.status),h("span",{text:owe||gbp(b.total)})]),h("span",{class:"go",text:"›"})]))});
    holder.appendChild(box);
  }
}

/* ---------- Booking sheet ---------- */
function openB(id){var b=B.filter(function(x){return x.id===id})[0];if(b)bookingSheet(b)}
function fld(label,el,full){return h("label",{class:"f"+(full?" full":"")},[label,el])}
function inp(id,val,type){return h("input",{id:id,type:type||"text",value:val==null?"":String(val)})}
function sel_(id,opts,val,names){var s=h("select",{id:id});opts.forEach(function(o){var op=h("option",{value:o,text:names?names[o]:o});if(o===val)op.selected=true;s.appendChild(op)});return s}
function chk(state,title,sub,btn){return h("div",{class:"chk "+state},[h("span",{class:"ic",text:state==="done"?"✓":state==="bad"?"!":state==="todo"?"•":""}),h("div",{class:"t"},[title,sub?h("small",{text:sub}):null]),btn||null])}
function emailSt(v){if(!v)return["","not sent"];if(String(v).indexOf("ERR")===0)return["bad","failed ("+v+")"];return["done","sent "+String(v).slice(0,10)]}
function needSaved(){if(dirty){toast("Save your changes first, then try again.",true);return true}return false}
function act(path,body,msg,id){toast("Working…");return api("POST",path,body).then(function(x){if(x.status>=400){toast(x.j.error||"That did not work.",true);return}toast((x.j.warning||msg)+(x.j.link?" Link copied below.":""),!!x.j.warning);return load()})}
function bookingSheet(b,startDay){
  var isNew=!b;
  b=b||{status:"confirmed",source:"phone",guests:2,arrive:startDay||"",depart:"",total:0,amount_paid:0,deposit_state:"none",marketing:0};
  openId=isNew?null:b.id;
  var body=[],ta=function(id,val){var t=h("textarea",{id:id});t.value=val||"";return t};
  var mk=h("input",{id:"f_marketing",type:"checkbox"});mk.checked=!!b.marketing;
  if(!isNew){
    var acts=[];
    if(b.email)if(b.email)acts.push(h("button",{class:"btn sm pri",type:"button",text:"Message",onclick:function(){var c=$("msgcard");if(c){c.scrollIntoView({behavior:"smooth",block:"center"});var t=$("tmsg");if(t)t.focus()}}}));
    if(b.phone)acts.push(h("a",{class:"btn sm",href:"tel:"+String(b.phone).replace(/[^0-9+]/g,""),text:"Call"}));
    body.push(h("div",{class:"hero"},[h("div",{style:"display:flex;gap:10px;align-items:center;margin-bottom:6px"},[pill(b.status),h("span",{class:"sub",style:"margin:0;font-size:13px",text:b.ref})]),h("h2",{text:b.name||"(no name)"}),h("div",{class:"meta",text:niceY(b.arrive)+" → "+niceY(b.depart)+" · "+b.nights+" night"+(b.nights===1?"":"s")+" · "+b.guests+" guest"+(b.guests===1?"":"s")}),h("div",{class:"acts"},acts)]));
    var nx=null,id=b.id;
    if(b.status==="request")nx=h("div",{class:"next req"},[h("p",{text:"New request. If the dates suit, send the secure payment link. Dates are held once it is paid."}),h("div",{class:"acts"},[h("button",{class:"btn pri",text:"Approve & send payment link",onclick:function(){if(needSaved())return;dlg({title:"Send payment link?",text:"A Stripe link for "+gbp(bal(b))+" will be created and emailed to "+(b.email||"the guest")+".",ok:"Send link"}).then(function(v){if(v)act("/api/bookings/"+id+"/paylink",{},"Payment link sent.")})}}),h("button",{class:"btn dng",text:"Decline",onclick:function(){dlg({title:"Decline this request?",text:"The status will change to Declined. No email is sent.",ok:"Decline",danger:true}).then(function(v){if(v)setStatus(b,"declined")})}})])]);
    else if(b.status==="awaiting_payment")nx=h("div",{class:"next pay"},[h("p",{text:"Payment link sent. The dates are not held until it is paid. Payment normally confirms the booking automatically."}),h("div",{class:"acts"},[h("button",{class:"btn grn",text:"Mark as paid & confirm",onclick:function(){if(needSaved())return;dlg({title:"Mark as paid?",text:"Records "+gbp(b.total)+" as paid in full and confirms the booking. Remember to block the dates on Airbnb.",ok:"Mark as paid"}).then(function(v){if(v)act("/api/bookings/"+id+"/markpaid",{},"Marked as paid and confirmed.")})}}),h("button",{class:"btn",text:"Resend payment link",onclick:function(){if(needSaved())return;act("/api/bookings/"+id+"/send",{kind:"link"},"Payment link emailed again.")}})])]);
    else if(b.status==="confirmed"){
      var pre=emailSt(b.prearrival_sent_at),gd=hasNote(b,"GUEST DETAILS RECEIVED"),bl=hasNote(b,"AIRBNB BLOCKED")||b.source==="airbnb-enquiry";
      nx=h("div",{class:"next"},[h("h3",{text:"Checklist"}),
        chk(bal(b)>0?"todo":"done",bal(b)>0?"Balance of "+gbp(bal(b))+" outstanding":"Paid in full"),
        chk(bl?"done":"todo",bl?"Airbnb dates blocked":"Block the dates on Airbnb",bl&&b.source!=="airbnb-enquiry"?"Marked done":"",bl?null:h("button",{class:"btn sm pri",text:"Done",onclick:function(){markBlocked(b)}})),
        chk(gd?"done":"todo",gd?"Guest details received":"Guest details not received yet",gd?"See the notes below":"The guest adds these from the link in their confirmation email"),
        chk(pre[0],"Arrival information email",pre[0]?pre[1]:"Sent automatically 3 days before arrival")])}
    else nx=h("div",{class:"next"},[h("p",{style:"margin:0;color:var(--grey)",text:"This booking is "+(LBL[b.status]||b.status).toLowerCase()+". The dates are free for other guests."})]);
    body.push(nx);
    body.push(threadCard(b));
    var pctv=b.total>0?Math.min(100,Math.round((b.amount_paid||0)*100/b.total)):0;
    var pay=h("div",{class:"card"},[h("h3",{text:"Payment"}),h("div",{class:"money"},[h("div",{},[h("b",{text:gbp(b.total)}),h("span",{text:"Total"})]),h("div",{},[h("b",{text:gbp(b.amount_paid)}),h("span",{text:"Paid"})]),h("div",{},[h("b",{style:bal(b)>0?"color:var(--red)":"",text:gbp(bal(b))}),h("span",{text:"Balance"})])]),h("div",{class:"prog"},[h("i",{style:"width:"+pctv+"%"})])]);
    if(b.payment_link){var lk=h("div",{class:"kv"},[h("span",{text:"Payment link"}),h("button",{class:"btn text",type:"button",text:"Copy link",onclick:function(){try{navigator.clipboard.writeText(b.payment_link);toast("Payment link copied.")}catch(e){toast("Could not copy.",true)}}})]);pay.appendChild(lk)}
    if((b.amount_paid||0)>0)pay.appendChild(h("div",{class:"btnrow",style:"margin-top:8px"},[h("button",{class:"btn sm",text:"Refund via Stripe…",onclick:function(){if(needSaved())return;dlg({title:"Refund via Stripe",text:"The money is returned to the guest's card. This cannot be undone.",ok:"Refund",danger:true,fields:[{id:"amt",label:"Amount to refund (£). Paid so far: "+gbp(b.amount_paid),type:"number",value:b.amount_paid}]}).then(function(v){if(!v)return;var n=Math.round(Number(v.amt));if(!(n>=1)||n>b.amount_paid){toast("Enter an amount between £1 and "+gbp(b.amount_paid)+".",true);return}act("/api/bookings/"+id+"/refund",{amount:n},"Refunded "+gbp(n)+".")})}})]));
    body.push(pay);
    var em=h("div",{class:"card"},[h("h3",{text:"Guest emails"})]);
    [["ack","Request received",b.ack_sent_at],["link","Payment link",b.link_sent_at],["confirm","Confirmation and receipt",b.confirm_sent_at],["pre","Arrival information",b.prearrival_sent_at]].forEach(function(k){var s=emailSt(k[2]);em.appendChild(chk(s[0],k[1],s[1],b.email?h("button",{class:"btn sm",text:k[2]?"Resend":"Send",onclick:function(){if(needSaved())return;dlg({title:(k[2]?"Resend":"Send")+" "+k[1].toLowerCase()+"?",text:"To "+b.email,ok:"Send"}).then(function(v){if(v)act("/api/bookings/"+id+"/send",{kind:k[0]},"Email sent.")})}}):null))});
    body.push(em);
  }
  var f=h("div",{class:"in"},[h("div",{class:"g2"},[
    fld("Status",sel_("f_status",["request","awaiting_payment","confirmed","declined","cancelled"],b.status,LBL)),
    fld("Source",sel_("f_source",["website","airbnb-enquiry","phone","email","other"],b.source)),
    fld("Name",inp("f_name",b.name),true),fld("Email",inp("f_email",b.email,"email")),fld("Phone",inp("f_phone",b.phone,"tel")),
    fld("Arrive",inp("f_arrive",b.arrive,"date")),fld("Depart",inp("f_depart",b.depart,"date")),
    fld("Guests",inp("f_guests",b.guests,"number")),fld("Heard about us via",inp("f_heard",b.heard_via)),
    fld("Total price (£)",inp("f_total",b.total,"number")),fld("Paid so far (£)",inp("f_paid",b.amount_paid,"number")),
    fld("Damage deposit",sel_("f_dep",["none","requested","held","returned"],b.deposit_state),true),
    fld("What the guest wrote",ta("f_gnotes",b.guest_notes),true),
    fld("Your private notes (guest details appear here)",ta("f_anotes",b.admin_notes),true),
    h("div",{class:"full tog"},[h("span",{text:"Guest agreed to availability emails"}),mk])])]);
  body.push(h("details",isNew?{open:"open"}:{},[h("summary",{text:isNew?"Booking details":"Edit details & notes"}),f]));
  if(isNew)body.push(h("p",{class:"warn",text:"After confirming a booking, block the dates on Airbnb straight away."}));
  if(!isNew){
    var mo=h("div",{class:"more"},[
      b.status!=="confirmed"?h("button",{class:"btn text",text:"Confirm & hold dates without payment",onclick:function(){if(needSaved())return;dlg({title:"Confirm without payment?",text:"The dates will be held as confirmed. No payment is recorded.",ok:"Confirm"}).then(function(v){if(v)setStatus(b,"confirmed")})}}):null,
      b.status!=="cancelled"?h("button",{class:"btn text dng",text:"Cancel booking",onclick:function(){if(needSaved())return;dlg({title:"Cancel this booking?",text:"The dates are released. Any refund is done separately with the Refund button.",ok:"Cancel booking",danger:true}).then(function(v){if(v)setStatus(b,"cancelled")})}}):null,
      h("button",{class:"btn text dng",text:"Delete record permanently",onclick:function(){dlg({title:"Delete permanently?",text:"This removes the record completely and cannot be undone.",ok:"Delete",danger:true}).then(function(v){if(v)api("DELETE","/api/bookings/"+b.id,null).then(function(){toast("Record deleted.");closeSheet(true);load()})})}})]);
    body.push(h("details",{},[h("summary",{text:"More actions"}),mo]));
  }
  var sv=h("button",{class:"btn pri",id:"savebtn",text:isNew?"Create booking":"Save changes",onclick:function(){save(b)}});
  var foot=[h("span",{class:"msg",id:"shmsg",text:isNew?"":""}),h("button",{class:"btn",text:"Close",onclick:function(){closeSheet()}}),sv];
  var keep=isNew?0:($("shbody")?$("shbody").scrollTop:0);
  openSheet(isNew?"New booking":"Booking",body,foot);
  var sb=$("sheet");sb.oninput=sb.onchange=function(e){if(e.target&&e.target.id&&e.target.id.indexOf("f_")===0){dirty=true;$("shmsg").textContent="Unsaved changes"}};
  if(keep)$("shbody").scrollTop=keep;
}
function setStatus(b,s){$("f_status").value=s;save(b)}
function save(b,force){
  var body={status:$("f_status").value,source:$("f_source").value,name:$("f_name").value,email:$("f_email").value,phone:$("f_phone").value,guests:$("f_guests").value,arrive:$("f_arrive").value,depart:$("f_depart").value,total:$("f_total").value,amount_paid:$("f_paid").value,deposit_state:$("f_dep").value,heard_via:$("f_heard").value,marketing:$("f_marketing").checked,guest_notes:$("f_gnotes").value,admin_notes:$("f_anotes").value};
  if(force)body.force=true;
  if(!body.arrive||!body.depart){toast("Please enter arrival and departure dates.",true);return}
  var go2=function(){
    var r=b.id?api("PATCH","/api/bookings/"+b.id,body):api("POST","/api/bookings",body);
    r.then(function(x){
      if(x.status===409){dlg({title:"Dates overlap",text:"This overlaps confirmed booking "+x.j.with.map(function(w){return w.ref+" ("+w.name+")"}).join(", ")+". Save anyway?",ok:"Save anyway",danger:true}).then(function(v){if(v)save(b,true)});return}
      if(x.status>=400){toast(x.j.error||"Could not save.",true);return}
      toast(b.id?"Saved.":"Booking created.");dirty=false;if(!b.id)closeSheet(true);load()});
  };
  if(body.status==="confirmed"&&!force){var clash=false;for(var d=dt(body.arrive);key(d)<body.depart;d.setDate(d.getDate()+1))if(airOn(key(d)))clash=true;
    if(clash){dlg({title:"Blocked on Airbnb",text:"Some of these nights are already booked on Airbnb. Confirm anyway?",ok:"Confirm anyway",danger:true}).then(function(v){if(v)go2()});return}}
  go2();
}

/* ---------- Settings ---------- */
var CFGF=[["checkin_time","Check-in time","from 3pm",1,"Arrival"],["checkout_time","Check-out time","by 10am",1,"Arrival"],["access_text","How to get in: lockbox location, code, instructions",null,4,"Arrival"],["contact_phone","Phone number for guests",null,1,"Arrival"],["address","Address shown to guests",null,2,"Arrival"],["parking","Parking",null,3,"Stay"],["wifi","Wi-Fi name and password",null,2,"Stay"],["house_rules","House rules",null,5,"Stay"],["checkout_text","Before you leave",null,3,"Stay"],["confirm_extra","Extra text for the confirmation email (optional)",null,3,"Stay"]];
function settings(v){
  v.appendChild(h("h1",{text:"Settings"}));
  var wrap=h("div",{class:"set",style:"margin-top:20px"});v.appendChild(wrap);
  wrap.appendChild(h("p",{class:"sub",text:"Loading…"}));
  api("GET","/api/settings").then(function(x){
    wrap.textContent="";var s=x.j,c=s.cfg||{};
    var live=h("input",{id:"e_live",type:"checkbox"});live.checked=!!s.live;
    var em=h("div",{class:"card"},[h("h2",{text:"Guest emails"}),h("p",{class:"sub",text:"Request received, payment link, confirmation and receipt, and arrival information 3 days before check-in."}),
      h("div",{class:"tog"},[h("span",{text:"Send guest emails automatically"}),live])]);
    wrap.appendChild(em);
    var groups={};CFGF.forEach(function(f){(groups[f[4]]=groups[f[4]]||[]).push(f)});
    var titles={Arrival:"Arrival information (needed for the 3-day email)",Stay:"During the stay"};
    Object.keys(groups).forEach(function(g){
      var card=h("div",{class:"card"},[h("h2",{text:titles[g]||g}),h("div",{class:"stack",style:"margin-top:12px"},groups[g].map(function(f){var t=h(f[3]>1?"textarea":"input",{id:"c_"+f[0],placeholder:f[2]||""});if(f[3]>1)t.rows=f[3];t.value=c[f[0]]||"";return fld(f[1],t)}))]);wrap.appendChild(card)});
    wrap.appendChild(h("div",{class:"btnrow",style:"margin:0"},[h("button",{class:"btn pri lg",text:"Save email settings",onclick:function(){var cfg={};CFGF.forEach(function(f){cfg[f[0]]=$("c_"+f[0]).value});api("PUT","/api/settings",{live:$("e_live").checked,cfg:cfg}).then(function(r){toast(r.status<400?"Settings saved.":(r.j.error||"Could not save."),r.status>=400)})}})]));
    var fw=h("input",{id:"e_fw",type:"checkbox"});fw.checked=s.forward!==false;
    fw.onchange=function(){api("PUT","/api/settings",{forward:fw.checked}).then(function(r){toast(r.status<400?"Saved.":"Could not save.",r.status>=400)})};
    wrap.appendChild(h("div",{class:"card"},[h("h2",{text:"Guest replies"}),h("p",{class:"sub",text:"Guest replies arrive in the Inbox here. You can also receive a copy in your normal mailbox so nothing is missed. Switch this off once you are happy using the Inbox."}),h("div",{class:"tog"},[h("span",{text:"Also forward guest replies to 3cresswellcourt@gmail.com"}),fw])]));
    wrap.appendChild(h("div",{class:"card"},[h("h2",{text:"Send yourself a test"}),h("p",{class:"sub",text:"Sent to "+(WHO||"your sign-in address")+". Save first so the test uses your latest text."}),h("div",{class:"btnrow",style:"margin:0"},[["ack","Request received"],["link","Payment link"],["confirm","Confirmation"],["pre","Arrival info"]].map(function(k){return h("button",{class:"btn sm",text:k[1],onclick:function(){act("/api/test-email",{kind:k[0]},"Test email sent to you.")}})}))]));
    wrap.appendChild(h("div",{class:"card"},[h("h2",{text:"Your data"}),h("p",{class:"sub",text:"Export bookings for your accounts, or tidy up old records."}),
      h("div",{class:"btnrow",style:"margin:0"},[
        h("a",{class:"btn sm",href:"/api/export.csv",text:"Export all (CSV)"}),
        h("button",{class:"btn sm",text:"Export by dates…",onclick:function(){dlg({title:"Export bookings",ok:"Download",fields:[{id:"from",label:"From date (optional)",type:"date"},{id:"to",label:"To date (optional)",type:"date"},{id:"by",label:"Filter by",type:"select",value:"arrive",options:[["arrive","Arrival date"],["paid","Payment date"]]}]}).then(function(v){if(v)location.href="/api/export.csv?from="+encodeURIComponent(v.from)+"&to="+encodeURIComponent(v.to)+"&by="+v.by})}}),
        h("button",{class:"btn sm dng",text:"Delete expired records…",onclick:function(){dlg({title:"Delete expired records?",text:"Removes requests, declined and cancelled records older than 12 months, and confirmed stays that ended over 6 years ago.",ok:"Delete",danger:true}).then(function(v){if(v)api("POST","/api/purge",{}).then(function(r){toast("Removed "+r.j.removed+" record(s).");load()})})}})])]));
  });
}

/* ---------- start ---------- */
(function(){var hsh=(location.hash||"").slice(1);if(["today","inbox","cal","book","set"].indexOf(hsh)>=0)tab=hsh})();
load().then(function(){
  var q=new URLSearchParams(location.search).get("ref");
  if(q){var b=B.filter(function(x){return x.ref===q})[0];if(b)bookingSheet(b)}
});
</script></body></html>
`;
