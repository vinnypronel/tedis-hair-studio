-- seed.sql
DELETE FROM services;

INSERT INTO services (id, name, duration_minutes, price_cents) VALUES
  (1, 'Basic Haircut',             30, 3500),
  (2, 'Haircut with Beard',        40, 4000),
  (3, 'Shape Up',                  20, 2500),
  (4, 'Beard Trim',                15, 2000),
  (5, 'Shape Up with Beard',       35, 3000);
