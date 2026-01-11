PRAGMA journal_mode=WAL;

-- Services offered
DROP TABLE IF EXISTS services;
CREATE TABLE services (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  duration_minutes INTEGER NOT NULL,
  price_cents INTEGER NOT NULL
);

-- Pre-generated time slots for the single barber (NOT per service)
DROP TABLE IF EXISTS time_slots;
CREATE TABLE time_slots (
  id INTEGER PRIMARY KEY,
  date TEXT NOT NULL,                 -- YYYY-MM-DD
  time TEXT NOT NULL,                 -- HH:mm (24h)
  is_available INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(date, time)                  -- one person, one slot globally
);

-- Bookings (tie a client + chosen service to a unique date/time)
DROP TABLE IF EXISTS bookings;
CREATE TABLE bookings (
  id INTEGER PRIMARY KEY,
  customer_name TEXT NOT NULL,
  customer_phone TEXT NOT NULL,
  customer_email TEXT,
  service_id INTEGER NOT NULL,
  date TEXT NOT NULL,                 -- YYYY-MM-DD
  time TEXT NOT NULL,                 -- HH:mm (24h)
  payment_method TEXT NOT NULL,       -- 'cash' | 'cashapp' | 'zelle' | 'venmo'
  status TEXT DEFAULT 'confirmed',    -- confirmed | cancelled | no_show | completed
  notes TEXT,
  policy_agreed_at TEXT,              -- ISO timestamp when policy was agreed
  phone_verified INTEGER DEFAULT 0,   -- 1 if phone was verified via SMS
  reminder_sent INTEGER DEFAULT 0,    -- 1 if 2-hour reminder was sent
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(date, time),                 -- single barber guard
  FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);
