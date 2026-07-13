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

// Migración no destructiva: añade columnas nuevas a bases de datos que ya
// existían antes de introducir esa columna, sin tocar los datos existentes.
function ensureColumn(table, column, definitionSql) {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all();
    if (!cols.some((c) => c.name === column)) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definitionSql}`);
    }
}
ensureColumn('modpacks', 'loader', "TEXT NOT NULL DEFAULT 'vanilla'");
ensureColumn('modpacks', 'loader_version', "TEXT NOT NULL DEFAULT ''");
ensureColumn('modpacks', 'cover_image', "TEXT NOT NULL DEFAULT ''");
ensureColumn('mods', 'type', "TEXT NOT NULL DEFAULT 'mod'");
ensureColumn('mods', 'source', "TEXT NOT NULL DEFAULT 'upload'");
ensureColumn('mods', 'download_url', "TEXT NOT NULL DEFAULT ''");
ensureColumn('mods', 'external_project_id', "TEXT NOT NULL DEFAULT ''");
ensureColumn('mods', 'external_version_id', "TEXT NOT NULL DEFAULT ''");
ensureColumn('mods', 'optional', "INTEGER NOT NULL DEFAULT 0");
ensureColumn('mods', 'mod_identifier', "TEXT NOT NULL DEFAULT ''");

// mods.modpack_id se consulta en cada manifiesto/sincronización/lanzamiento
// (una por jugador conectado); access.user_uuid se consulta en /mine. Sin
// índice, ambas fuerzan un table scan que crece con cada modpack/usuario nuevo.
db.exec('CREATE INDEX IF NOT EXISTS idx_mods_modpack_id ON mods(modpack_id);');
db.exec('CREATE INDEX IF NOT EXISTS idx_access_user_uuid ON access(user_uuid);');
db.exec('CREATE INDEX IF NOT EXISTS idx_invites_modpack_id ON invites(modpack_id);');

module.exports = db;
