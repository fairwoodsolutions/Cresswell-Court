// Cresswell Court inbox. Email Worker: receives mail sent to booking@cresswellcourt.co.uk, files it against the right booking.
// Bindings: DB (D1). Optional: forwards a copy to the host address (setting inbound_forward).
const HOST = "3cresswellcourt@gmail.com";
const OWN = "booking@cresswellcourt.co.uk";


// ---- minimal MIME parser (text bodies, headers, multipart, QP/base64, charsets, RFC2047 words) ----
function dec(bytes, cs) { try { return new TextDecoder((cs || "utf-8").toLowerCase().replace(/^"|"$/g, "")).decode(bytes); } catch (e) { return new TextDecoder("utf-8").decode(bytes); } }
function b64bytes(s) { const b = atob(s.replace(/[^A-Za-z0-9+/=]/g, "")); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
function qpbytes(s) { s = s.replace(/=\r?\n/g, ""); const out = []; for (let i = 0; i < s.length; i++) { const c = s[i]; if (c === "=" && /^[0-9A-Fa-f]{2}$/.test(s.substr(i + 1, 2))) { out.push(parseInt(s.substr(i + 1, 2), 16)); i += 2; } else out.push(s.charCodeAt(i) & 255); } return new Uint8Array(out); }
function word(h) { return String(h || "").replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g, (m, cs, e, t) => e.toLowerCase() === "b" ? dec(b64bytes(t), cs) : dec(qpbytes(t.replace(/_/g, " ")), cs)).replace(/\?=\s+=\?/g, ""); }
function splitMsg(str) { const i = str.search(/\r?\n\r?\n/); if (i < 0) return { head: str, body: "" }; const m = /\r?\n\r?\n/.exec(str.slice(i)); return { head: str.slice(0, i), body: str.slice(i + m[0].length) }; }
function heads(h) { const o = {}; h.replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/).forEach((l) => { const k = l.indexOf(":"); if (k > 0) { const n = l.slice(0, k).toLowerCase(); if (!(n in o)) o[n] = l.slice(k + 1).trim(); } }); return o; }
function param(v, name) { const m = new RegExp(name + '\\s*=\\s*(?:"([^"]*)"|([^;\\s]+))', "i").exec(v || ""); return m ? (m[1] != null ? m[1] : m[2]) : ""; }
function walk(str, out) {
  const { head, body } = splitMsg(str), H = heads(head), ct = (H["content-type"] || "text/plain").toLowerCase();
  if (/^multipart\//.test(ct)) {
    const bd = param(H["content-type"], "boundary"); if (!bd) return;
    str = body; const parts = body.split("--" + bd); parts.slice(1).forEach((p) => { if (/^--/.test(p)) return; walk(p.replace(/^\r?\n/, ""), out); });
    return;
  }
  if (/^text\/(plain|html)/.test(ct) && !/attachment/i.test(H["content-disposition"] || "")) {
    const te = (H["content-transfer-encoding"] || "7bit").toLowerCase(), cs = param(H["content-type"], "charset") || "utf-8";
    let bytes = te === "base64" ? b64bytes(body) : te === "quoted-printable" ? qpbytes(body) : new Uint8Array([...body].map((c) => c.charCodeAt(0) & 255));
    const t = dec(bytes, cs); if (/html/.test(ct)) out.html = out.html || t; else out.text = out.text || t;
  }
}
function parseMime(buf) {
  const raw = new TextDecoder("latin1").decode(buf), out = {}; walk(raw, out);
  const H = heads(splitMsg(raw).head), fm = /<([^>]+)>/.exec(H["from"] || "");
  return { subject: word(H["subject"]), from: (fm ? fm[1] : (H["from"] || "")).trim(), messageId: H["message-id"] || null, text: out.text || "", html: out.html || "" };
}

function clean(text) {
  let t = String(text || "").replace(/\r\n/g, "\n");
  const cuts = [/\n+On .{0,250}?wrote:[\s\S]*$/i, /\n+-{2,}\s*Original Message\s*-{2,}[\s\S]*$/i, /\n+_{5,}[\s\S]*$/, /\n+From: .+\n(?:Sent|Date): [\s\S]*$/i, /\n+Sent from my [\s\S]*$/i, /\n+Get Outlook for [\s\S]*$/i];
  for (const c of cuts) t = t.replace(c, "");
  t = t.split("\n").filter((l) => !/^>/.test(l)).join("\n");
  return t.replace(/\n{3,}/g, "\n\n").trim();
}
function htmlToText(h) {
  return String(h || "").replace(/<(style|script)[\s\S]*?<\/\1>/gi, "").replace(/<br\s*\/?>/gi, "\n").replace(/<\/(p|div|li|tr)>/gi, "\n").replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&#39;/g, "'").replace(/&quot;/g, '"');
}

export default {
  async email(message, env, ctx) {
    let mail = null, rawBuf = null;
    try { rawBuf = await new Response(message.raw).arrayBuffer(); mail = parseMime(rawBuf); } catch (e) { console.error("parse failed", String(e)); }
    if (!mail) { try { await message.forward(HOST); } catch (e) {} return; }
    const from = String(mail.from || message.from || "").toLowerCase();
    const subject = String(mail.subject || "").slice(0, 300);
    const full = (mail.text && mail.text.trim()) ? mail.text : htmlToText(mail.html);
    let body = clean(full);
    if (!body) body = String(full).trim().slice(0, 2000) || "(no text)";
    body = body.slice(0, 8000);
    const mid = mail.messageId ? String(mail.messageId).slice(0, 300) : null;
    try {
      if (from && from !== OWN) {
        let bid = null;
        const refm = /\bCC\d+-[A-Z0-9]+\b/i.exec(subject + " " + String(full).slice(0, 4000));
        if (refm) { const r = await env.DB.prepare("SELECT id FROM bookings WHERE upper(ref) = ?").bind(refm[0].toUpperCase()).first(); if (r) bid = r.id; }
        if (!bid) {
          const r = await env.DB.prepare("SELECT id FROM bookings WHERE lower(email) = ? ORDER BY CASE WHEN status IN ('confirmed','awaiting_payment','request') THEN 0 ELSE 1 END, arrive DESC LIMIT 1").bind(from).first();
          if (r) bid = r.id;
        }
        await env.DB.prepare("INSERT OR IGNORE INTO messages (booking_id, direction, kind, from_addr, to_addr, subject, body, full_text, msg_id, read_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,NULL,?)")
          .bind(bid, "in", "msg", from, String(message.to || OWN), subject, body, String(full).slice(0, 20000), mid, new Date().toISOString()).run();
      }
    } catch (e) { console.error("inbox store failed", String(e)); }
    try {
      const fw = await env.DB.prepare("SELECT v FROM settings WHERE k = 'inbound_forward'").first();
      if (!fw || fw.v !== "0") await message.forward(HOST);
    } catch (e) { console.error("forward failed", String(e)); }
  },
};
