// Cresswell Court mailer. Private Worker: no public routes. Sends the guest emails and creates Stripe payment links.
// Runs every minute (Cron Trigger) and is also called by the admin Worker through a service binding named MAILER.
// Bindings: DB (D1), EMAIL (Email Sending). Secret: STRIPE_SECRET_KEY.
const FROM = { email: "booking@cresswellcourt.co.uk", name: "Cresswell Court" };
const HOST = "3cresswellcourt@gmail.com";
const SITE = "https://cresswellcourt.co.uk";
const ADMIN = "https://admin.cresswellcourt.co.uk";
const REQUIRED = ["access_text", "checkin_time", "checkout_time"];
const DEFAULTS = {
  address: "3 Cresswell Court, Tenby, Pembrokeshire",
  checkin_time: "", checkout_time: "", access_text: "", wifi: "", parking: "Private off-road parking, with a space right outside the front door.",
  house_rules: "No pets.\nThe apartment is for a couple or a single guest only.\nPlease treat the apartment and the neighbours with respect, and keep noise down late at night.",
  checkout_text: "Please leave the apartment tidy, put rubbish in the bins and switch off lights and heating.",
  contact_phone: "", confirm_extra: "",
};

// ---------- small helpers ----------
const esc = (t) => String(t == null ? "" : t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const nl = (t) => esc(t).replace(/\n/g, "<br>");
const gbp = (n) => "£" + (Number(n) || 0).toLocaleString("en-GB");
const dfmt = (s) => new Date(s + "T12:00:00Z").toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
const first = (n) => String(n || "").trim().split(/\s+/)[0] || "there";
const londonDate = (offsetDays = 0) => {
  const d = new Date(Date.now() + offsetDays * 864e5);
  return new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/London", year: "numeric", month: "2-digit", day: "2-digit" }).format(d);
};
async function getSetting(env, k) { const r = await env.DB.prepare("SELECT v FROM settings WHERE k = ?").bind(k).first(); return r ? r.v : null; }
async function getCfg(env) {
  let c = {}; try { c = JSON.parse((await getSetting(env, "cfg")) || "{}"); } catch (e) {}
  return { ...DEFAULTS, ...c };
}
const isLive = async (env) => (await getSetting(env, "emails_live")) === "1";

// ---------- templates ----------
function layout(title, inner) {
  return '<!doctype html><html><body style="margin:0;background:#F5EFE4;font-family:Arial,Helvetica,sans-serif;color:#12303A">' +
    '<div style="max-width:600px;margin:0 auto;padding:24px 16px"><div style="background:#ffffff;border-radius:10px;padding:28px 26px">' +
    '<div style="margin-bottom:14px"><img src="' + SITE + '/logo.png" width="44" height="44" alt="" style="vertical-align:middle;border-radius:8px"> <span style="font-family:Georgia,serif;font-size:21px;vertical-align:middle;margin-left:8px">Cresswell Court</span></div><div style="font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:#3F5C66;margin-bottom:10px">3 Cresswell Court, Tenby</div>' +
    '<h1 style="font-family:Georgia,serif;font-size:26px;line-height:1.2;margin:0 0 16px">' + esc(title) + "</h1>" + inner +
    '<p style="margin:22px 0 0;font-size:15px;line-height:1.5">Lloyd &amp; Paula<br><a href="' + SITE + '" style="color:#B8432C">cresswellcourt.co.uk</a></p></div>' +
    '<p style="font-size:12px;color:#3F5C66;line-height:1.5;margin:14px 6px">You are receiving this because of your booking enquiry at cresswellcourt.co.uk. Reply to this email if you have any questions.</p></div></body></html>';
}
const p = (t) => '<p style="font-size:15px;line-height:1.55;margin:0 0 14px">' + t + "</p>";
const h2 = (t) => '<h2 style="font-family:Georgia,serif;font-size:18px;margin:22px 0 6px">' + esc(t) + "</h2>";
function table(rows) {
  return '<table style="width:100%;border-collapse:collapse;margin:6px 0 16px">' + rows.map((r) =>
    '<tr><td style="padding:7px 0;border-bottom:1px solid #e6e0d4;font-size:14px;color:#3F5C66;width:42%">' + esc(r[0]) + '</td><td style="padding:7px 0;border-bottom:1px solid #e6e0d4;font-size:14px;font-weight:bold">' + r[1] + "</td></tr>").join("") + "</table>";
}
const stayRows = (b) => [["Reference", esc(b.ref)], ["Arrive", esc(dfmt(b.arrive))], ["Depart", esc(dfmt(b.depart))], ["Nights", esc(b.nights)], ["Guests", esc(b.guests)]];
const button = (href, label) => '<p style="margin:18px 0"><a href="' + esc(href) + '" style="background:#12303A;color:#ffffff;text-decoration:none;padding:13px 22px;border-radius:7px;font-weight:bold;font-size:15px;display:inline-block">' + esc(label) + "</a></p>";
const calLink = (b, cfg) => '<p style="margin:0 0 14px"><a href="https://calendar.google.com/calendar/render?action=TEMPLATE&amp;text=' + encodeURIComponent("Stay at 3 Cresswell Court, Tenby") + "&amp;dates=" + b.arrive.replace(/-/g, "") + "/" + b.depart.replace(/-/g, "") + "&amp;location=" + encodeURIComponent(cfg.address) + '" style="color:#B8432C">Add your stay to your calendar</a></p>';
const plain = (html) => html.replace(/<br\s*\/?>/g, "\n").replace(/<\/td><td[^>]*>/g, ": ").replace(/<\/(p|h1|h2|tr|div)>/g, "\n").replace(/<a [^>]*href="([^"]+)"[^>]*>([^<]*)<\/a>/g, "$2 ($1)").replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/\n{3,}/g, "\n\n").trim();

const TEMPLATES = {
  ack(b) {
    return { subject: "We have your request for 3 Cresswell Court", html: layout("Thank you, " + first(b.name),
      p("We have received your request to stay at 3 Cresswell Court and will reply the same day.") +
      table(stayRows(b).concat([["Indicative price", gbp(b.total)]])) +
      p("<b>What happens next:</b> we check the dates and, if they are free, send you a secure card payment link.") +
      p("Please note that your dates are not secured until payment is received. Until then they remain available to other guests, including on Airbnb.")) };
  },
  link(b) {
    const due = Math.max(0, (b.total || 0) - (b.amount_paid || 0));
    return { subject: "Pay to secure your stay at 3 Cresswell Court", html: layout("Your dates are available",
      p("Hello " + esc(first(b.name)) + ", good news: the dates you asked for are free.") + table(stayRows(b).concat([["Amount to pay", gbp(due)]])) +
      button(b.payment_link, "Pay " + gbp(due) + " securely by card") +
      p("Your dates are secured only once payment is received, and they remain available to other guests until then, so please pay as soon as you can. You will get a confirmation straight after.") +
      p("If the button does not work, copy this link into your browser:<br>" + esc(b.payment_link))) };
  },
  confirm(b, cfg) {
    const paid = b.amount_paid || 0, bal = Math.max(0, (b.total || 0) - paid);
    return { subject: "Booking confirmed: 3 Cresswell Court, " + dfmt(b.arrive), html: layout("Booking confirmed",
      p("Thank you, " + esc(first(b.name)) + ". We have received your payment and your stay is confirmed.") +
      h2("Payment receipt") + table([["Reference", esc(b.ref)], ["Date paid", esc(dfmt((b.paid_at || new Date().toISOString()).slice(0, 10)))], ["Amount paid", gbp(paid)], ["Payment method", "Card (processed by Stripe)"], ["Balance due", gbp(bal)]]) +
      h2("Your stay") + table(stayRows(b)) +
      p("<b>Address:</b> " + esc(cfg.address)) +
      calLink(b, cfg) +
      (b.guest_url ? h2("One more step: your guest details") + p("Please tell us who is staying. It takes about a minute, and we need it before you arrive.") + button(b.guest_url, "Add guest details") : "") + h2("Cancellation terms") + p("14 days or more before arrival: full refund. 7 to 13 days before arrival: 50% refund. Fewer than 7 days: no refund. To cancel, reply to this email.") +
      p("About three days before you arrive we will email you the access details and house rules.") +
      (cfg.confirm_extra ? p(nl(cfg.confirm_extra)) : "")) };
  },
  pre(b, cfg) {
    const sec = (t, v) => (v ? h2(t) + p(nl(v)) : "");
    return { subject: "Your stay at 3 Cresswell Court: access details and house rules", html: layout("Getting ready for your stay",
      p("Hello " + esc(first(b.name)) + ", we are looking forward to welcoming you on <b>" + esc(dfmt(b.arrive)) + "</b>.") +
      table([["Check-in", esc(cfg.checkin_time)], ["Check-out", esc(dfmt(b.depart)) + ", " + esc(cfg.checkout_time)], ["Address", esc(cfg.address)]]) +
      calLink(b, cfg) +
      (b.guest_url ? p("<b>We still need your guest details before you arrive.</b> It takes about a minute.") + button(b.guest_url, "Add guest details") : "") + sec("Getting in", cfg.access_text) + sec("Parking", cfg.parking) + sec("Wi-Fi", cfg.wifi) + sec("House rules", cfg.house_rules) + sec("Before you leave", cfg.checkout_text) +
      p("<b>Need anything?</b> Reply to this email" + (cfg.contact_phone ? " or call " + esc(cfg.contact_phone) : "") + ".")) };
  },
};
TEMPLATES.review = (b) => ({ subject: "How was your stay at 3 Cresswell Court?", html: layout("How was your stay?",
  p("Hello " + esc(first(b.name)) + ", thank you for staying with us. We hope you had a lovely time in Tenby.") +
  p("If you have a minute, we would be very grateful for a short review. It helps other guests choose, and we read every one.") +
  button(b.review_url || SITE + "/review.html", "Leave a review") +
  p("If anything was not right, please reply to this email and we will do our best to put it right.")) });
function host(kind, b, note) {
  const inner = p("<b>Please ensure AirBnB calendar is updated and dates blocked as soon as booking confirmed</b>") +
    table([["Reference", esc(b.ref)], ["Guest", esc(b.name) + " (" + esc(b.email) + ")"], ["Stay", esc(b.arrive) + " to " + esc(b.depart) + " (" + esc(b.nights) + " nights)"], ["Paid", gbp(b.amount_paid)]]) +
    (note ? p("<b>" + esc(note) + "</b>") : "") + p('<a href="' + ADMIN + "/?ref=" + esc(b.ref) + '">Open in admin</a>');
  return { subject: "PAID: " + b.ref + " " + b.name + " - block Airbnb dates", html: layout("Payment received", inner) };
}

async function sendMail(env, to, tpl, replyTo) {
  const text = plain(tpl.html);
  return env.EMAIL.send({ from: FROM, to, subject: tpl.subject, html: tpl.html, text, replyTo: replyTo || (to === HOST ? HOST : FROM.email) });
}

// ---------- messages ----------
async function logMsg(env, m) {
  try {
    await env.DB.prepare("INSERT INTO messages (booking_id, direction, kind, from_addr, to_addr, subject, body, read_at, created_at) VALUES (?,?,?,?,?,?,?,?,?)")
      .bind(m.booking_id, m.direction, m.kind || "msg", m.from_addr || FROM.email, m.to_addr || "", m.subject || "", m.body || "", new Date().toISOString(), new Date().toISOString()).run();
  } catch (e) { console.error("logMsg", String(e)); }
}
function messageHtml(body, ref) {
  const paras = String(body).trim().split(/\n{2,}/).map((p) => '<p style="margin:0 0 14px">' + nl(p) + "</p>").join("");
  return '<div style="font:16px/1.55 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1c1c1e;max-width:560px">' + paras +
    '<p style="margin:18px 0 0">Lloyd &amp; Paula<br>3 Cresswell Court, Tenby</p>' +
    '<p style="margin:22px 0 0;font-size:12px;color:#8a8a8e">Booking reference ' + esc(ref) + ". Just reply to this email to reach us.</p></div>";
}
const missing = (cfg) => REQUIRED.filter((k) => !String(cfg[k] || "").trim() || /\[/.test(cfg[k]));

// ---------- Stripe ----------
async function createLink(env, b) {
  if (!env.STRIPE_SECRET_KEY) throw new Error("STRIPE_SECRET_KEY is not set");
  const due = Math.max(0, (b.total || 0) - (b.amount_paid || 0));
  if (due < 1) throw new Error("Nothing to pay: set a total price first");
  const f = new URLSearchParams();
  f.set("line_items[0][price_data][currency]", "gbp");
  f.set("line_items[0][price_data][unit_amount]", String(due * 100));
  f.set("line_items[0][price_data][product_data][name]", "3 Cresswell Court, Tenby");
  f.set("line_items[0][price_data][product_data][description]", dfmt(b.arrive) + " to " + dfmt(b.depart) + " (" + b.nights + " nights)");
  f.set("custom_text[submit][message]", "Cancellation terms: 14 days or more before arrival, full refund. 7 to 13 days before arrival, 50% refund. Fewer than 7 days, no refund. To cancel, reply to your confirmation email. Refunds go to the original card.");
  f.set("payment_intent_data[statement_descriptor]", "CRESSWELL_COURT");
  f.set("line_items[0][quantity]", "1");
  f.set("metadata[ref]", b.ref);
  f.set("payment_intent_data[metadata][ref]", b.ref);
  f.set("payment_intent_data[description]", "Booking " + b.ref + ", 3 Cresswell Court");
  f.set("restrictions[completed_sessions][limit]", "1");
  f.set("after_completion[type]", "redirect");
  f.set("after_completion[redirect][url]", SITE + "/thanks.html");
  const r = await fetch("https://api.stripe.com/v1/payment_links", { method: "POST", headers: { authorization: "Bearer " + env.STRIPE_SECRET_KEY, "content-type": "application/x-www-form-urlencoded" }, body: f });
  const j = await r.json();
  if (!r.ok) throw new Error("Stripe: " + ((j.error && j.error.message) || r.status));
  const q = new URLSearchParams({ client_reference_id: b.ref });
  if (b.email) q.set("prefilled_email", b.email);
  return { url: j.url + (j.url.includes("?") ? "&" : "?") + q.toString(), id: j.id };
}

// ---------- review invitations ----------
const hex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, "0")).join("");
async function reviewToken(env, ref, kind) {
  let sec = await getSetting(env, "review_secret");
  if (!sec) {
    await env.DB.prepare("INSERT OR IGNORE INTO settings (k, v) VALUES ('review_secret', ?)").bind(hex(crypto.getRandomValues(new Uint8Array(24)))).run();
    sec = await getSetting(env, "review_secret");
  }
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(sec), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode((kind || "review") + ":" + ref))).slice(0, 24);
}
async function sendReviewInvite(env, b) {
  b.review_url = SITE + "/review.html?ref=" + encodeURIComponent(b.ref) + "&k=" + (await reviewToken(env, b.ref));
  try { await sendMail(env, b.email, TEMPLATES.review(b)); }
  catch (e) { await env.DB.prepare("INSERT OR REPLACE INTO review_invites (booking_id, sent_at) VALUES (?, ?)").bind(b.id, "ERR " + String((e && e.code) || (e && e.message) || e).slice(0, 80)).run(); throw e; }
  await env.DB.prepare("INSERT OR REPLACE INTO review_invites (booking_id, sent_at) VALUES (?, ?)").bind(b.id, new Date().toISOString()).run();
}

// ---------- sending a booking email and recording it ----------
const COL = { ack: "ack_sent_at", link: "link_sent_at", confirm: "confirm_sent_at", pre: "prearrival_sent_at" };
async function deliver(env, kind, b, force) {
  const cfg = await getCfg(env);
  if (kind === "pre" && missing(cfg).length) throw new Error("Fill in " + missing(cfg).join(", ") + " in the Emails tab first");
  if (!b.email) throw new Error("No guest email address");
  if (kind === "confirm" || (kind === "pre" && String(b.admin_notes || "").indexOf("GUEST DETAILS RECEIVED") < 0)) b.guest_url = SITE + "/guest.html?ref=" + encodeURIComponent(b.ref) + "&k=" + (await reviewToken(env, b.ref, "guest"));
  const tpl = TEMPLATES[kind](b, cfg);
  try {
    await sendMail(env, b.email, tpl);
  } catch (e) {
    if (!force) await env.DB.prepare("UPDATE bookings SET " + COL[kind] + " = ? WHERE id = ?").bind("ERR " + String((e && e.code) || e.message).slice(0, 80), b.id).run();
    throw e;
  }
  await env.DB.prepare("UPDATE bookings SET " + COL[kind] + " = ? WHERE id = ?").bind(new Date().toISOString(), b.id).run();
  await logMsg(env, { booking_id: b.id, direction: "out", kind: "auto", to_addr: b.email, subject: tpl.subject, body: tpl.subject });
  if (kind === "confirm") { try { await sendMail(env, HOST, host("paid", b)); } catch (e) { console.error("host notice", String(e)); } }
}

// ---------- the minute-by-minute queue ----------
async function runQueue(env) {
  if (!(await isLive(env))) return { skipped: "emails are off" };
  const out = { ack: 0, link: 0, confirm: 0, pre: 0, review: 0, errors: [] };
  const cfg = await getCfg(env);
  const run = async (kind, sql, ...binds) => {
    const rows = (await env.DB.prepare(sql).bind(...binds).all()).results || [];
    for (const b of rows) { try { await deliver(env, kind, b, false); out[kind]++; } catch (e) { out.errors.push(b.ref + " " + kind + ": " + String((e && e.message) || e)); } }
  };
  await run("ack", "SELECT * FROM bookings WHERE status = 'request' AND source = 'website' AND ack_sent_at IS NULL AND email != '' AND created_at > ? LIMIT 10", new Date(Date.now() - 3 * 864e5).toISOString());
  await run("link", "SELECT * FROM bookings WHERE status = 'awaiting_payment' AND payment_link != '' AND link_sent_at IS NULL AND email != '' LIMIT 10");
  await run("confirm", "SELECT * FROM bookings WHERE status = 'confirmed' AND paid_at IS NOT NULL AND confirm_sent_at IS NULL AND email != '' LIMIT 10");
  try {
    const due = (await env.DB.prepare("SELECT * FROM bookings b WHERE status = 'confirmed' AND email != '' AND depart >= ? AND depart <= ? AND NOT EXISTS (SELECT 1 FROM review_invites r WHERE r.booking_id = b.id) LIMIT 10").bind(londonDate(-4), londonDate(-1)).all()).results || [];
    for (const b of due) { try { await sendReviewInvite(env, b); out.review++; } catch (e) { out.errors.push(b.ref + " review: " + String((e && e.message) || e)); } }
  } catch (e) { out.errors.push("review queue: " + String((e && e.message) || e)); }
  if (!missing(cfg).length) await run("pre", "SELECT * FROM bookings WHERE status = 'confirmed' AND prearrival_sent_at IS NULL AND email != '' AND arrive >= ? AND arrive <= ? LIMIT 10", londonDate(0), londonDate(3));
  return out;
}

// ---------- internal API (service binding from the admin Worker only) ----------
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });
async function booking(env, id) { return env.DB.prepare("SELECT * FROM bookings WHERE id = ?").bind(Number(id)).first(); }
export default {
  async scheduled(event, env, ctx) { ctx.waitUntil(runQueue(env).then((r) => { if (r && r.errors && r.errors.length) console.error(JSON.stringify(r)); })); },
  async fetch(request, env) {
    if (request.method !== "POST") return json({ error: "not found" }, 404);
    const path = new URL(request.url).pathname;
    let b = {}; try { b = await request.json(); } catch (e) {}
    try {
      if (path === "/paylink") {
        const bk = await booking(env, b.id); if (!bk) return json({ error: "not found" }, 404);
        const link = await createLink(env, bk);
        await env.DB.prepare("UPDATE bookings SET status = 'awaiting_payment', payment_link = ?, stripe_ref = ?, link_sent_at = NULL, updated_at = ? WHERE id = ?").bind(link.url, link.id, new Date().toISOString(), bk.id).run();
        let sent = false;
        if (await isLive(env)) { bk.payment_link = link.url; try { await deliver(env, "link", bk, false); sent = true; } catch (e) { return json({ ok: true, link: link.url, sent: false, warning: String(e.message || e) }); } }
        return json({ ok: true, link: link.url, sent, warning: sent ? "" : "Guest emails are switched off, so the link was not emailed. Switch them on in the Emails tab, or send it yourself." });
      }
      if (path === "/send") {
        if (!COL[b.kind]) return json({ error: "bad kind" }, 400);
        const bk = await booking(env, b.id); if (!bk) return json({ error: "not found" }, 404);
        if (b.kind === "link" && !bk.payment_link) return json({ error: "No payment link yet" }, 400);
        await deliver(env, b.kind, bk, true);
        return json({ ok: true });
      }
if (path === "/refund") {
if (!env.STRIPE_SECRET_KEY) return json({ error: "STRIPE_SECRET_KEY is not set" }, 400);
const bk = await booking(env, b.id); if (!bk) return json({ error: "not found" }, 404);
const paid = bk.amount_paid || 0;
const amt = Math.round(Number(b.amount));
if (!(amt >= 1) || amt > paid) return json({ error: "Enter a refund between 1 and " + paid + " pounds" }, 400);
if (!bk.stripe_ref) return json({ error: "No Stripe payment is linked to this booking. Refund it in the Stripe dashboard." }, 400);
const H = { authorization: "Bearer " + env.STRIPE_SECRET_KEY };
const sr = await fetch("https://api.stripe.com/v1/checkout/sessions?payment_link=" + encodeURIComponent(bk.stripe_ref) + "&limit=100", { headers: H });
const sj = await sr.json(); if (!sr.ok) return json({ error: "Stripe: " + ((sj.error && sj.error.message) || sr.status) }, 502);
const s = (sj.data || []).find((x) => x.client_reference_id === bk.ref && x.payment_status === "paid" && x.payment_intent);
if (!s) return json({ error: "Could not find the card payment in Stripe. Refund it in the Stripe dashboard." }, 404);
const f = new URLSearchParams({ payment_intent: s.payment_intent, amount: String(amt * 100) }); f.set("metadata[ref]", bk.ref);
const rr = await fetch("https://api.stripe.com/v1/refunds", { method: "POST", headers: { ...H, "content-type": "application/x-www-form-urlencoded", "idempotency-key": "refund-" + bk.ref + "-" + paid + "-" + amt }, body: f });
const rj = await rr.json(); if (!rr.ok) return json({ error: "Stripe: " + ((rj.error && rj.error.message) || rr.status) }, 502);
const now = new Date().toISOString(); const left = paid - amt;
await env.DB.prepare("UPDATE bookings SET amount_paid = ?, status = ?, admin_notes = COALESCE(admin_notes, '') || ?, updated_at = ? WHERE id = ?").bind(left, left === 0 ? "cancelled" : bk.status, "\nRefunded £" + amt + " via Stripe on " + now.slice(0, 10) + (left === 0 ? " (booking cancelled)" : ""), now, bk.id).run();
return json({ ok: true, warning: "Refunded £" + amt + " to the guest's card" + (left === 0 ? " and the booking is cancelled" : "") + ". Please unblock the dates on Airbnb." });
}
      if (path === "/message") {
        const bk = await booking(env, b.id); if (!bk) return json({ error: "not found" }, 404);
        const text = String(b.body || "").trim();
        if (!text) return json({ error: "Write a message first" }, 400);
        if (text.length > 5000) return json({ error: "That message is too long (5000 characters max)" }, 400);
        if (!/^[^@\s]+@[^@\s]+$/.test(bk.email || "")) return json({ error: "This booking has no valid guest email address" }, 400);
        const subject = String(b.subject || "").trim().slice(0, 200) || ("Your stay at 3 Cresswell Court (" + bk.ref + ")");
        await sendMail(env, bk.email, { subject, html: messageHtml(text, bk.ref) });
        await logMsg(env, { booking_id: bk.id, direction: "out", kind: "msg", to_addr: bk.email, subject, body: text });
        return json({ ok: true });
      }
      if (path === "/test") {
        if (!TEMPLATES[b.kind] || !/^[^@\s]+@[^@\s]+$/.test(b.to || "")) return json({ error: "bad request" }, 400);
        const cfg = await getCfg(env);
        const demo = { id: 0, ref: "CC0000-TEST", name: "Alex Example", email: b.to, guests: 2, nights: 3, arrive: londonDate(30), depart: londonDate(33), total: 366, amount_paid: 366, paid_at: new Date().toISOString(), payment_link: SITE + "/?test" };
        await sendMail(env, b.to, { ...TEMPLATES[b.kind](demo, { ...cfg, access_text: cfg.access_text || "[access details not filled in yet]", checkin_time: cfg.checkin_time || "[check-in time]", checkout_time: cfg.checkout_time || "[check-out time]" }), subject: "[TEST] " + TEMPLATES[b.kind](demo, cfg).subject });
        return json({ ok: true });
      }
      if (path === "/run") return json(await runQueue(env));
      return json({ error: "not found" }, 404);
    } catch (e) { return json({ error: String((e && e.message) || e), code: e && e.code }, 500); }
  },
};
