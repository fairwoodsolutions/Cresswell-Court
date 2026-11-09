// Public intake: receives a booking request from cresswellcourt.co.uk, stores it in the
// bookings database (status "request") and emails you. Bindings needed: DB (D1) and EMAIL.
import { EmailMessage } from "cloudflare:email";

const FROM = "booking@cresswellcourt.co.uk";
const TO = "3cresswellcourt@gmail.com";
const ADMIN_URL = "https://admin.cresswellcourt.co.uk";
const ALLOWED_ORIGINS = ["https://cresswellcourt.co.uk", "https://www.cresswellcourt.co.uk"];

const clean = (s, max) => String(s == null ? "" : s).replace(/[\r\n]+/g, " ").trim().slice(0, max);
const longText = (s, max) => String(s == null ? "" : s).replace(/\r/g, "").trim().slice(0, max);
const isDate = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s + "T00:00:00Z"));
const nightsBetween = (a, b) => Math.round((Date.parse(b + "T00:00:00Z") - Date.parse(a + "T00:00:00Z")) / 864e5);

function b64(text) {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/.{1,76}/g, "$&\r\n");
}
function buildMime(subject, replyTo, body) {
  return [
    "From: Cresswell Court website <" + FROM + ">",
    "To: " + TO,
    "Reply-To: " + replyTo,
    "Subject: " + subject,
    "Date: " + new Date().toUTCString(),
    "Message-ID: <" + crypto.randomUUID() + "@cresswellcourt.co.uk>",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
    "",
    b64(body),
  ].join("\r\n");
}
function makeRef() {
  const d = new Date();
  const r = crypto.getRandomValues(new Uint32Array(1))[0].toString(36).toUpperCase().padStart(6, "0").slice(0, 5);
  return "CC" + String(d.getUTCFullYear()).slice(2) + String(d.getUTCMonth() + 1).padStart(2, "0") + "-" + r;
}


// ---------- Stripe webhook: marks a booking paid ----------
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function verifyStripe(raw, header, secret) {
  if (!header || !secret) return false;
  const parts = Object.fromEntries(header.split(",").map((kv) => { const i = kv.indexOf("="); return [kv.slice(0, i).trim(), kv.slice(i + 1)]; }));
  const t = Number(parts.t);
  if (!t || Math.abs(Date.now() / 1000 - t) > 300) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const expected = hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(t + "." + raw)));
  return header.split(",").some((kv) => kv.trim().startsWith("v1=") && kv.trim().slice(3) === expected);
}
async function stripeWebhook(request, env) {
  const raw = await request.text();
  if (!(await verifyStripe(raw, request.headers.get("stripe-signature"), env.STRIPE_WEBHOOK_SECRET))) return new Response("bad signature", { status: 400 });
  let ev; try { ev = JSON.parse(raw); } catch (e) { return new Response("bad json", { status: 400 }); }
  if (ev.type !== "checkout.session.completed" && ev.type !== "checkout.session.async_payment_succeeded") return new Response("ignored", { status: 200 });
  const s = (ev.data && ev.data.object) || {};
  if (s.payment_status !== "paid") return new Response("not paid", { status: 200 });
  const ref = s.client_reference_id || (s.metadata && s.metadata.ref) || "";
  const bk = await env.DB.prepare("SELECT * FROM bookings WHERE ref = ? OR (stripe_ref != '' AND stripe_ref = ?)").bind(ref, s.payment_link || "-").first();
  if (!bk) { console.error("webhook: no booking for", ref); return new Response("no booking", { status: 200 }); }
  if (bk.paid_at) return new Response("already recorded", { status: 200 });
  const now = new Date().toISOString();
  const amount = Math.round((Number(s.amount_total) || 0) / 100);
  const clash = await env.DB.prepare("SELECT ref FROM bookings WHERE status = 'confirmed' AND id != ? AND arrive < ? AND depart > ?").bind(bk.id, bk.depart, bk.arrive).all();
  const warn = (clash.results || []).length ? "\nWARNING " + now.slice(0, 10) + ": dates overlap confirmed booking " + clash.results.map((c) => c.ref).join(", ") : "";
  await env.DB.prepare("UPDATE bookings SET status = 'confirmed', amount_paid = amount_paid + ?, paid_at = ?, admin_notes = COALESCE(admin_notes, '') || ?, updated_at = ? WHERE id = ?").bind(amount, now, "\nStripe payment received " + now.slice(0, 10) + warn, now, bk.id).run();
  return new Response("ok", { status: 200 });
}


// ---------- guest reviews ----------
const SELF = "https://cresswell-enquiries.3cresswellcourt.workers.dev";
async function reviewSecret(env) {
  const r = await env.DB.prepare("SELECT v FROM settings WHERE k = 'review_secret'").first();
  if (r && r.v) return r.v;
  const v = hex(crypto.getRandomValues(new Uint8Array(24)));
  await env.DB.prepare("INSERT OR IGNORE INTO settings (k, v) VALUES ('review_secret', ?)").bind(v).run();
  const r2 = await env.DB.prepare("SELECT v FROM settings WHERE k = 'review_secret'").first();
  return r2.v;
}
async function rtoken(env, msg) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(await reviewSecret(env)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg))).slice(0, 24);
}
const monthName = (d) => new Date(d + "T12:00:00Z").toLocaleDateString("en-GB", { month: "long", year: "numeric", timeZone: "UTC" });
const escH = (s) => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
async function notifyHost(env, subject, text) {
  try { await env.EMAIL.send(new EmailMessage(FROM, TO, buildMime(subject, TO, text))); }
  catch (e1) { try { await env.EMAIL.send({ from: FROM, to: TO, subject, text, replyTo: TO }); } catch (e2) { console.error("notify failed", String(e2)); } }
}
async function reviewRoutes(request, env, path, reply) {
  const url = new URL(request.url);
  if (path === "/reviews" && request.method === "GET") {
    const rows = (await env.DB.prepare("SELECT name, rating, body, stay, source FROM reviews WHERE status = 'approved' ORDER BY id DESC LIMIT 60").all()).results || [];
    const st = (await env.DB.prepare("SELECT COUNT(*) AS n, AVG(rating) AS a FROM reviews WHERE status = 'approved' AND source = 'direct'").first()) || {};
    return reply({ reviews: rows, direct: { count: st.n || 0, average: st.a ? Math.round(st.a * 10) / 10 : null } }, 200);
  }
  if (path === "/review-info" && request.method === "GET") {
    const ref = clean(url.searchParams.get("ref"), 30), k = clean(url.searchParams.get("k"), 40);
    if (!ref || k !== (await rtoken(env, "review:" + ref))) return reply({ error: "invalid link" }, 403);
    const b = await env.DB.prepare("SELECT id, name, arrive, depart, status FROM bookings WHERE ref = ?").bind(ref).first();
    if (!b || b.status !== "confirmed") return reply({ error: "invalid link" }, 403);
    const done = await env.DB.prepare("SELECT id FROM reviews WHERE booking_id = ?").bind(b.id).first();
    return reply({ first: String(b.name || "").trim().split(/\s+/)[0], stay: monthName(b.depart), done: !!done }, 200);
  }
  if (path === "/review" && request.method === "POST") {
    let d; try { d = await request.json(); } catch (e) { return reply({ error: "bad request" }, 400); }
    if (d.website) return reply({ ok: true }, 200);
    const ref = clean(d.ref, 30);
    if (!ref || clean(d.k, 40) !== (await rtoken(env, "review:" + ref))) return reply({ error: "invalid link" }, 403);
    const b = await env.DB.prepare("SELECT id, name, depart, status FROM bookings WHERE ref = ?").bind(ref).first();
    if (!b || b.status !== "confirmed") return reply({ error: "invalid link" }, 403);
    if (await env.DB.prepare("SELECT id FROM reviews WHERE booking_id = ?").bind(b.id).first()) return reply({ error: "already reviewed" }, 409);
    const rating = Math.round(Number(d.rating));
    const body = longText(d.body, 1500);
    const name = clean(d.name, 60) || String(b.name || "").trim().split(/\s+/)[0] || "Guest";
    if (!(rating >= 1 && rating <= 5) || body.length < 10 || d.consent !== true) return reply({ error: "invalid" }, 400);
    const now = new Date().toISOString();
    const res = await env.DB.prepare("INSERT INTO reviews (booking_id, ref, name, rating, body, stay, source, status, created_at) VALUES (?,?,?,?,?,?,'direct','pending',?)").bind(b.id, ref, name, rating, body, monthName(b.depart), now).run();
    const id = res.meta && res.meta.last_row_id ? res.meta.last_row_id : (await env.DB.prepare("SELECT id FROM reviews WHERE booking_id = ?").bind(b.id).first()).id;
    const t = await rtoken(env, "mod:" + id);
    await notifyHost(env, "New guest review (" + rating + "/5) from " + name,
      "Review from " + name + ", stay " + monthName(b.depart) + " (" + ref + ")\nRating: " + rating + "/5\n\n" + body + "\n\nApprove or reject it here (it is not shown on the site until you approve):\n" + SELF + "/mod?id=" + id + "&t=" + t);
    return reply({ ok: true }, 200);
  }
  if (path === "/mod") {
    const id = Number(url.searchParams.get("id")), t = clean(url.searchParams.get("t"), 40);
    const page = (inner) => new Response('<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:Arial,sans-serif;max-width:560px;margin:30px auto;padding:0 16px;color:#111">' + inner + "</body>", { headers: { "content-type": "text/html; charset=utf-8", "x-robots-tag": "noindex" } });
    if (!id || t !== (await rtoken(env, "mod:" + id))) return page("<p>Invalid link.</p>");
    const r = await env.DB.prepare("SELECT * FROM reviews WHERE id = ?").bind(id).first();
    if (!r) return page("<p>Review not found.</p>");
    if (request.method === "POST") {
      const fd = await request.formData(); const a = fd.get("a");
      if (a !== "approve" && a !== "reject") return page("<p>Bad request.</p>");
      await env.DB.prepare("UPDATE reviews SET status = ? WHERE id = ?").bind(a === "approve" ? "approved" : "rejected", id).run();
      return page("<h2>Done</h2><p>Review " + (a === "approve" ? "approved and now showing on the site" : "rejected and hidden") + ".</p>");
    }
    return page("<h2>Guest review</h2><p><b>" + escH(r.name) + "</b>, " + escH(r.stay) + ", " + r.rating + "/5</p><p style='white-space:pre-wrap'>" + escH(r.body) + "</p><p>Status: " + escH(r.status) + "</p><form method='post'><button name='a' value='approve' style='padding:12px 20px;margin-right:8px'>Approve</button><button name='a' value='reject' style='padding:12px 20px'>Reject</button></form><p style='color:#666;font-size:13px'>Only reject reviews that are abusive, about something else or not from a guest. Do not hide honest criticism.</p>");
  }
  return null;
}

export default {
  async fetch(request, env) {
    if (new URL(request.url).pathname === "/stripe-webhook" && request.method === "POST") return stripeWebhook(request, env);
    const origin = request.headers.get("origin") || "";
    const cors = {
      "access-control-allow-origin": ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": "content-type",
      "vary": "origin",
    };
    const reply = (obj, status) => new Response(JSON.stringify(obj), { status, headers: { ...cors, "content-type": "application/json" } });

    if (request.method === "OPTIONS") return new Response(null, { headers: cors });
    { const rp = new URL(request.url).pathname; if (rp === "/reviews" || rp === "/review-info" || rp === "/review" || rp === "/mod" || rp === "/guest-info" || rp === "/guest") { if (rp !== "/mod" && !ALLOWED_ORIGINS.includes(origin) && request.method !== "GET") return reply({ error: "not allowed" }, 403); const rr = (rp === "/guest" || rp === "/guest-info") ? await guestRoutes(request, env, rp, reply) : await reviewRoutes(request, env, rp, reply); if (rr) return rr; } }
    if (request.method !== "POST") return reply({ error: "POST only" }, 405);
    if (!ALLOWED_ORIGINS.includes(origin)) return reply({ error: "not allowed" }, 403);

    let d;
    try { d = await request.json(); } catch (e) { return reply({ error: "bad request" }, 400); }
    if (d.website) return reply({ ok: true }, 200);                 // honeypot

    const name = clean(d.name, 100);
    const email = clean(d.email, 200);
    const phone = clean(d.phone, 40);
    const arrive = clean(d.arrive, 10);
    const depart = clean(d.depart, 10);
    const guests = Math.max(1, Math.min(10, parseInt(d.guests, 10) || 1));
    const total = Math.max(0, Math.min(100000, Math.round(Number(d.total) || 0)));
    const nights = isDate(arrive) && isDate(depart) ? nightsBetween(arrive, depart) : 0;
    const today = new Date().toISOString().slice(0, 10);
    if (!name || !/^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$/.test(email)) return reply({ error: "invalid" }, 400);
    if (nights < 1 || nights > 60 || arrive < today) return reply({ error: "invalid dates" }, 400);
    if (d.consent !== true) return reply({ error: "consent needed" }, 400);

    const marketing = d.marketing === true ? 1 : 0;
    const heard = clean(d.heard, 200);
    const notes = longText(d.notes, 2000);
    const ref = makeRef();
    const now = new Date().toISOString();

    let stored = false;
    try {
      await env.DB.prepare(
        "INSERT INTO bookings (ref,status,source,name,email,phone,guests,arrive,depart,nights,total,marketing,heard_via,guest_notes,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(ref, "request", "website", name, email, phone, guests, arrive, depart, nights, total, marketing, heard, notes, now, now).run();
      stored = true;
    } catch (e) { console.error("db insert failed", String(e)); }

    const body = [
      "Booking request " + ref,
      "Name: " + name,
      "Email: " + email,
      phone ? "Phone: " + phone : null,
      "Guests: " + guests,
      "Arrive: " + arrive,
      "Depart: " + depart + " (" + nights + " nights)",
      "Indicative price: GBP " + total,
      "Availability emails: " + (marketing ? "yes" : "no"),
      heard ? "Heard about us via: " + heard : null,
      notes ? "Notes: " + notes : null,
      "",
      stored ? "Open in admin: " + ADMIN_URL + "/?ref=" + ref : "WARNING: this request was NOT saved to the database.",
    ].filter((x) => x !== null).join("\n");

    let emailed = false;
    const subject = "Booking request from " + name;
    try {
      await env.EMAIL.send(new EmailMessage(FROM, TO, buildMime(subject, email, body)));
      emailed = true;
    } catch (e1) {
      console.error("classic send failed", String(e1));
      try {
        await env.EMAIL.send({ from: FROM, to: TO, subject, text: body, replyTo: email });
        emailed = true;
      } catch (e2) { console.error("new send failed", String(e2)); }
    }
    if (!stored && !emailed) return reply({ error: "send failed" }, 502);
    return reply({ ok: true, ref }, 200);
  },
};

// ---------- guest details after payment ----------
async function guestRoutes(request, env, path, reply) {
  const url = new URL(request.url);
  if (path === "/guest-info" && request.method === "GET") {
    const ref = clean(url.searchParams.get("ref"), 30), k = clean(url.searchParams.get("k"), 40);
    if (!ref || k !== (await rtoken(env, "guest:" + ref))) return reply({ error: "invalid link" }, 403);
    const b = await env.DB.prepare("SELECT name, guests, arrive, depart, status, admin_notes FROM bookings WHERE ref = ?").bind(ref).first();
    if (!b || b.status !== "confirmed") return reply({ error: "invalid link" }, 403);
    return reply({ name: b.name, guests: b.guests, arrive: b.arrive, depart: b.depart, done: String(b.admin_notes || "").indexOf("GUEST DETAILS RECEIVED") >= 0 }, 200);
  }
  if (path === "/guest" && request.method === "POST") {
    let d; try { d = await request.json(); } catch (e) { return reply({ error: "bad request" }, 400); }
    if (d.website) return reply({ ok: true }, 200);
    const ref = clean(d.ref, 30);
    if (!ref || clean(d.k, 40) !== (await rtoken(env, "guest:" + ref))) return reply({ error: "invalid link" }, 403);
    const b = await env.DB.prepare("SELECT id, name, guests, arrive, depart, status, admin_notes FROM bookings WHERE ref = ?").bind(ref).first();
    if (!b || b.status !== "confirmed") return reply({ error: "invalid link" }, 403);
    if (String(b.admin_notes || "").indexOf("GUEST DETAILS RECEIVED") >= 0) return reply({ error: "already sent" }, 409);
    const lead = clean(d.lead, 100) || String(b.name || "");
    const addr = longText(d.address, 300).replace(/\n+/g, ", ");
    const nat = clean(d.nationality, 60);
    const two = Number(b.guests) >= 2;
    const g2n = two ? clean(d.g2name, 100) : "", g2c = two ? clean(d.g2nat, 60) : "";
    if (addr.length < 8 || !nat || (two && (!g2n || !g2c)) || d.agree !== true) return reply({ error: "invalid" }, 400);
    const now = new Date().toISOString();
    const block = "\n\nGUEST DETAILS RECEIVED " + now.slice(0, 10) + "\nLead guest: " + lead + " (" + nat + ")\nHome address: " + addr + (two ? "\nSecond guest: " + g2n + " (" + g2c + ")" : "") + "\nHoliday Let Agreement accepted: yes (version 3 Nov 2026)";
    await env.DB.prepare("UPDATE bookings SET admin_notes = COALESCE(admin_notes, '') || ?, updated_at = ? WHERE id = ?").bind(block, now, b.id).run();
    await notifyHost(env, "Guest details received for " + ref, "Guest details received for " + ref + " (" + b.arrive + " to " + b.depart + ")." + block + "\n\nThey are saved in the booking's private notes in the admin area.");
    return reply({ ok: true }, 200);
  }
  return null;
}
