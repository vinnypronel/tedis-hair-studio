-- Postgres (Neon) compatible schema

-- Core Services
DROP TABLE IF EXISTS services CASCADE;
CREATE TABLE services (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  duration_minutes INTEGER NOT NULL,
  price_cents INTEGER NOT NULL
);

-- Time Slots
DROP TABLE IF EXISTS time_slots CASCADE;
CREATE TABLE time_slots (
  id SERIAL PRIMARY KEY,
  date TEXT NOT NULL,                 -- YYYY-MM-DD
  time TEXT NOT NULL,                 -- HH:mm (24h)
  is_available INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(date, time)
);

-- Bookings
DROP TABLE IF EXISTS bookings CASCADE;
CREATE TABLE bookings (
  id SERIAL PRIMARY KEY,
  customer_name TEXT NOT NULL,
  customer_phone TEXT NOT NULL,
  customer_email TEXT,
  service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  date TEXT NOT NULL,                 -- YYYY-MM-DD
  time TEXT NOT NULL,                 -- HH:mm (24h)
  payment_method TEXT NOT NULL,       -- 'cash' | 'zelle'
  status TEXT DEFAULT 'confirmed',    -- confirmed | cancelled | no_show | completed
  notes TEXT,
  policy_agreed_at TEXT,
  phone_verified INTEGER DEFAULT 0,
  reminder_sent INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(date, time)
);

-- Users
DROP TABLE IF EXISTS users CASCADE;
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE,
  phone TEXT,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'user',
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Gallery
DROP TABLE IF EXISTS gallery_images CASCADE;
CREATE TABLE gallery_images (
  id SERIAL PRIMARY KEY,
  filename TEXT NOT NULL,
  caption TEXT,
  uploaded_by TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
