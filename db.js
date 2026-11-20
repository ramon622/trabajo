// Base de datos SQLite en un único fichero (data/app.db). Se crea sola al arrancar.
//
// Usa better-sqlite3 si está instalado. Si no (por ejemplo, porque en Windows no
// pudo compilarse), usa el módulo SQLite que trae Node 22.5 o superior.
// Los dos tienen la misma API para lo que usamos aquí: prepare().get/all/run().
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

let Database;
try {
  Database = require('better-sqlite3');
} catch (e) {
  try {
    ({ DatabaseSync: Database } = require('node:sqlite'));
  } catch (e2) {
    throw new Error(
      'No hay ningún motor SQLite disponible. Ejecuta "npm install" o usa Node 22.5 o superior.'
    );
  }
}

const FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'app.db');
fs.mkdirSync(path.dirname(FILE), { recursive: true });

const db = new Database(FILE);
db.exec('PRAGMA foreign_keys = ON'); // necesario en SQLite para que se respeten las claves ajenas
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA synchronous = NORMAL');
db.exec('PRAGMA busy_timeout = 5000');

db.exec(`
  CREATE TABLE IF NOT EXISTS groups (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE
  );

  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    group_id      INTEGER REFERENCES groups(id) ON DELETE RESTRICT, -- un usuario, un único grupo
    photo         TEXT
  );

  -- Mensajes del chat de grupo: pertenecen a un grupo, no a un destinatario.
  CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id   INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL, -- si se da de baja, el mensaje queda como "Usuario eliminado"
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_messages_group ON messages (group_id, id);
  CREATE INDEX IF NOT EXISTS idx_users_group ON users (group_id);
`);

// Administrador por defecto (solo si no existe ninguno)
const hasAdmin = db.prepare("SELECT 1 AS ok FROM users WHERE role = 'admin' LIMIT 1").get();
if (!hasAdmin) {
  db.prepare(
    "INSERT INTO users (username, name, email, password_hash, role) VALUES (?, ?, ?, ?, 'admin')"
  ).run(
    'admin',
    'Administrador',
    'admin@example.com',
    bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10)
  );
}

// Ayudas cortas para usar en las rutas
function get(sql, ...params) {
  return db.prepare(sql).get(...params);
}
function all(sql, ...params) {
  return db.prepare(sql).all(...params);
}
function run(sql, ...params) {
  const r = db.prepare(sql).run(...params);
  return { id: Number(r.lastInsertRowid), changes: Number(r.changes) };
}

module.exports = { get, all, run };
