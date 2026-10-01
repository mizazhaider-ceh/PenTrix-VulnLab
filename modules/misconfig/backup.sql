-- PenTrix demo application database backup
-- Generated: 2026-09-30 02:14:07 CEST by nightly_backup.sh
-- DO NOT commit this file to git (ops ticket #4812, still open)

DROP TABLE IF EXISTS users;
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user'
);

INSERT INTO users (id, username, password, role) VALUES
  (1, 'admin',      'admin123',            'admin'),
  (2, 'alice',      'alice123',            'user'),
  (3, 'bob',        'bob123',              'user'),
  (4, 'svc_backup', 'b@ckup_R3st0re_2026', 'service');

DROP TABLE IF EXISTS api_keys;
CREATE TABLE api_keys (
  id INTEGER PRIMARY KEY,
  owner TEXT NOT NULL,
  key_value TEXT NOT NULL
);

INSERT INTO api_keys (id, owner, key_value) VALUES
  (1, 'ci-runner', 'ci_7f3a9b2d4e1c'),
  (2, 'monitoring', 'mon_2b8e5f1a9c3d');

-- internal note: debug token PENTRIX{misconfig_backup} -- remove before release
