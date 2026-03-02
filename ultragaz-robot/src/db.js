// db.js — Persistência SQLite local (idempotência + fila de retry)
import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.join(__dirname, '..', 'robot.db');

let db;

export function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    initSchema();
  }
  return db;
}

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS processed_orders (
      ultragaz_order_id TEXT PRIMARY KEY,
      moskogas_order_id  INTEGER,
      status             TEXT DEFAULT 'ok',
      created_at         INTEGER DEFAULT (unixepoch())
    );

    CREATE TABLE IF NOT EXISTS retry_queue (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      ultragaz_order_id TEXT NOT NULL,
      payload_json    TEXT NOT NULL,
      attempts        INTEGER DEFAULT 0,
      next_retry_at   INTEGER DEFAULT (unixepoch()),
      last_error      TEXT,
      created_at      INTEGER DEFAULT (unixepoch())
    );

    CREATE TABLE IF NOT EXISTS event_log (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type   TEXT,
      order_id     TEXT,
      payload_json TEXT,
      created_at   INTEGER DEFAULT (unixepoch())
    );
  `);
}

export function isProcessed(ultragazOrderId) {
  const row = getDb()
    .prepare('SELECT ultragaz_order_id FROM processed_orders WHERE ultragaz_order_id = ?')
    .get(String(ultragazOrderId));
  return !!row;
}

export function markProcessed(ultragazOrderId, moskogasOrderId = null, status = 'ok') {
  getDb()
    .prepare('INSERT OR IGNORE INTO processed_orders (ultragaz_order_id, moskogas_order_id, status) VALUES (?, ?, ?)')
    .run(String(ultragazOrderId), moskogasOrderId, status);
}

export function addToRetryQueue(ultragazOrderId, payload) {
  getDb()
    .prepare('INSERT INTO retry_queue (ultragaz_order_id, payload_json) VALUES (?, ?)')
    .run(String(ultragazOrderId), JSON.stringify(payload));
}

export function getPendingRetries() {
  return getDb()
    .prepare('SELECT * FROM retry_queue WHERE next_retry_at <= unixepoch() AND attempts < 5 ORDER BY created_at ASC LIMIT 10')
    .all();
}

export function updateRetry(id, success, error = null) {
  if (success) {
    getDb().prepare('DELETE FROM retry_queue WHERE id = ?').run(id);
  } else {
    // Backoff: 30s, 2min, 10min, 30min, 1h
    const backoffs = [30, 120, 600, 1800, 3600];
    const row = getDb().prepare('SELECT attempts FROM retry_queue WHERE id = ?').get(id);
    const attempts = (row?.attempts || 0) + 1;
    const delay = backoffs[Math.min(attempts - 1, backoffs.length - 1)];
    getDb()
      .prepare('UPDATE retry_queue SET attempts = ?, next_retry_at = unixepoch() + ?, last_error = ? WHERE id = ?')
      .run(attempts, delay, error, id);
  }
}

export function logEvent(eventType, orderId, payload) {
  try {
    getDb()
      .prepare('INSERT INTO event_log (event_type, order_id, payload_json) VALUES (?, ?, ?)')
      .run(eventType, String(orderId || ''), JSON.stringify(payload));
  } catch {}
}
