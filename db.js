const path = require('path');
require('dotenv').config();

// Usamos el módulo "node:sqlite" incluido en Node.js (v22.5+) en vez de
// "better-sqlite3". Hace básicamente lo mismo, pero al venir integrado en
// Node no hace falta compilar nada con Visual Studio / build tools, que es
// lo que suele dar problemas en Windows.
const { DatabaseSync } = require('node:sqlite');

const dbPath = process.env.DB_PATH || path.join(__dirname, 'data.sqlite');
const db = new DatabaseSync(dbPath);

db.exec('PRAGMA journal_mode = WAL;');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  uuid TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  last_seen INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS modpacks (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  mc_version TEXT NOT NULL,
  owner_uuid TEXT NOT NULL,
  version_hash TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mods (
  id TEXT PRIMARY KEY,
  modpack_id TEXT NOT NULL,
  filename TEXT NOT NULL,
  filesize INTEGER NOT NULL,
  sha1 TEXT NOT NULL,
  added_at INTEGER NOT NULL,
  FOREIGN KEY (modpack_id) REFERENCES modpacks(id)
);

CREATE TABLE IF NOT EXISTS invites (
  token TEXT PRIMARY KEY,
  modpack_id TEXT NOT NULL,
  created_by TEXT NOT NULL,
  max_uses INTEGER,
  uses INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (modpack_id) REFERENCES modpacks(id)
);

CREATE TABLE IF NOT EXISTS access (
  modpack_id TEXT NOT NULL,
  user_uuid TEXT NOT NULL,
  granted_at INTEGER NOT NULL,
  PRIMARY KEY (modpack_id, user_uuid)
);
`);

module.exports = db;
