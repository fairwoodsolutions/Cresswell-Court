CREATE TABLE IF NOT EXISTS bookings (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ref           TEXT UNIQUE NOT NULL,
  status        TEXT NOT NULL DEFAULT 'request',   -- request | awaiting_payment | confirmed | cancelled | declined
  source        TEXT NOT NULL DEFAULT 'website',   -- website | phone | email | other
  name          TEXT,
  email         TEXT,
  phone         TEXT,
  guests        INTEGER,
  arrive        TEXT NOT NULL,                     -- first night, YYYY-MM-DD
  depart        TEXT NOT NULL,                     -- departure day, YYYY-MM-DD
  nights        INTEGER,
  total         INTEGER,                           -- pounds
  amount_paid   INTEGER NOT NULL DEFAULT 0,        -- pounds received so far
  deposit_state TEXT NOT NULL DEFAULT 'none',      -- none | requested | held | returned
  marketing     INTEGER NOT NULL DEFAULT 0,        -- 1 = agreed to availability emails
  heard_via     TEXT,
  guest_notes   TEXT,                              -- what the guest wrote
  admin_notes   TEXT,                              -- your private notes
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bookings_dates ON bookings (arrive, depart);
CREATE INDEX IF NOT EXISTS idx_bookings_status ON bookings (status);

-- Added for automated emails and Stripe payments (run once on an existing database):
-- ALTER TABLE bookings ADD COLUMN payment_link TEXT NOT NULL DEFAULT '';
-- ALTER TABLE bookings ADD COLUMN stripe_ref TEXT NOT NULL DEFAULT '';
-- ALTER TABLE bookings ADD COLUMN paid_at TEXT;
-- ALTER TABLE bookings ADD COLUMN ack_sent_at TEXT;
-- ALTER TABLE bookings ADD COLUMN link_sent_at TEXT;
-- ALTER TABLE bookings ADD COLUMN confirm_sent_at TEXT;
-- ALTER TABLE bookings ADD COLUMN prearrival_sent_at TEXT;
-- CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);

-- Reviews (run once in the D1 console)
CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, booking_id INTEGER, ref TEXT, name TEXT, rating INTEGER, body TEXT, stay TEXT, source TEXT DEFAULT 'direct', status TEXT DEFAULT 'pending', created_at TEXT);
CREATE TABLE IF NOT EXISTS review_invites (booking_id INTEGER PRIMARY KEY, sent_at TEXT);

-- Messages (run once in the D1 console)
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, booking_id INTEGER, direction TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'msg', from_addr TEXT, to_addr TEXT, subject TEXT, body TEXT, full_text TEXT, msg_id TEXT, read_at TEXT, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_messages_booking ON messages (booking_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_msgid ON messages (msg_id) WHERE msg_id IS NOT NULL;
