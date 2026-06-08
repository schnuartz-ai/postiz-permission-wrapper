'use strict';
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const { encrypt, decrypt } = require('./crypto');

const DB_PATH = path.join(__dirname, 'data', 'wrapper.db');
let _db = null;

function getDb() {
  if (_db) return _db;
  _db = new Database(DB_PATH);
  _db.pragma('journal_mode = WAL');
  _db.pragma('foreign_keys = ON');
  _initSchema();
  return _db;
}

function _initSchema() {
  _db.exec(`
    CREATE TABLE IF NOT EXISTS config (
      key   TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE TABLE IF NOT EXISTS channel_policies (
      channel_id   TEXT PRIMARY KEY,
      policy       TEXT NOT NULL DEFAULT 'draft',
      channel_name TEXT,
      updated_at   INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS activity_log (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp      INTEGER NOT NULL,
      channel_ids    TEXT    NOT NULL,
      requested_type TEXT    NOT NULL,
      effective_type TEXT    NOT NULL,
      policy_applied TEXT    NOT NULL,
      request_path   TEXT,
      key_id         TEXT
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      id         TEXT PRIMARY KEY,
      name       TEXT NOT NULL,
      key_value  TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS api_key_policies (
      key_id       TEXT NOT NULL,
      channel_id   TEXT NOT NULL,
      policy       TEXT NOT NULL DEFAULT 'draft',
      channel_name TEXT,
      updated_at   INTEGER NOT NULL,
      PRIMARY KEY (key_id, channel_id),
      FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE
    );
  `);

  // Add key_id column to activity_log if it doesn't exist yet (migration)
  try { _db.exec('ALTER TABLE activity_log ADD COLUMN key_id TEXT'); } catch (_) {}

  // Migrate old single wrapper_api_key → api_keys table
  _migrateWrapperKey();
}

function _migrateWrapperKey() {
  const count = _db.prepare('SELECT COUNT(*) as c FROM api_keys').get();
  if (count.c > 0) return; // Already migrated

  const oldKey = getConfig('wrapper_api_key');
  if (oldKey) {
    const id = 'key_' + crypto.randomBytes(12).toString('hex');
    _db.prepare('INSERT INTO api_keys (id, name, key_value, created_at) VALUES (?, ?, ?, ?)')
      .run(id, 'Default', oldKey, Date.now());
    console.log('[db] Migrated existing wrapper_api_key to api_keys table as "Default"');
  } else {
    // No old key → create first default key
    const id       = 'key_' + crypto.randomBytes(12).toString('hex');
    const keyValue = 'wk_' + crypto.randomBytes(32).toString('hex');
    _db.prepare('INSERT INTO api_keys (id, name, key_value, created_at) VALUES (?, ?, ?, ?)')
      .run(id, 'Default', keyValue, Date.now());
    console.log('[db] Created initial api_key "Default"');
  }
}

// ── generic config ────────────────────────────────────────────────────────────
function getConfig(key) {
  const row = getDb().prepare('SELECT value FROM config WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setConfig(key, value) {
  getDb().prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(key, value);
}

// ── Postiz API key (AES-256-GCM encrypted) ───────────────────────────────────
function getPostizApiKey() {
  const enc = getConfig('postiz_api_key_encrypted');
  const iv  = getConfig('postiz_api_key_iv');
  const tag = getConfig('postiz_api_key_auth_tag');
  if (!enc || !iv || !tag) return null;
  try {
    return decrypt(enc, iv, tag);
  } catch {
    console.error('[db] Failed to decrypt Postiz API key');
    return null;
  }
}

function setPostizApiKey(plaintext) {
  const { encrypted, iv, authTag } = encrypt(plaintext);
  const db = getDb();
  const insert = db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)');
  const tx = db.transaction(() => {
    insert.run('postiz_api_key_encrypted', encrypted);
    insert.run('postiz_api_key_iv',        iv);
    insert.run('postiz_api_key_auth_tag',  authTag);
  });
  tx();
}

// ── Wrapper API key (backward compat — returns first/default key) ─────────────
function getWrapperApiKey() {
  const row = getDb().prepare('SELECT key_value FROM api_keys ORDER BY created_at ASC LIMIT 1').get();
  return row ? row.key_value : null;
}

// Keep for backward compat (OAuth rotate, etc.)
function generateWrapperApiKey() {
  const db  = getDb();
  const row = db.prepare('SELECT id FROM api_keys ORDER BY created_at ASC LIMIT 1').get();
  if (row) {
    const newVal = 'wk_' + crypto.randomBytes(32).toString('hex');
    db.prepare('UPDATE api_keys SET key_value = ? WHERE id = ?').run(newVal, row.id);
    return newVal;
  }
  // Fallback: create one
  return createApiKey('Default').key_value;
}

// ── Multi API-Key management ──────────────────────────────────────────────────
function createApiKey(name) {
  const id       = 'key_' + crypto.randomBytes(12).toString('hex');
  const keyValue = 'wk_' + crypto.randomBytes(32).toString('hex');
  const now      = Date.now();
  getDb().prepare('INSERT INTO api_keys (id, name, key_value, created_at) VALUES (?, ?, ?, ?)')
    .run(id, name, keyValue, now);
  return { id, name, key_value: keyValue, created_at: now };
}

function listApiKeys() {
  return getDb().prepare('SELECT id, name, key_value, created_at FROM api_keys ORDER BY created_at ASC').all();
}

function getApiKeyById(id) {
  return getDb().prepare('SELECT id, name, key_value, created_at FROM api_keys WHERE id = ?').get(id) || null;
}

function getApiKeyByValue(value) {
  if (!value) return null;
  return getDb().prepare('SELECT id, name, key_value, created_at FROM api_keys WHERE key_value = ?').get(value) || null;
}

function renameApiKey(id, name) {
  getDb().prepare('UPDATE api_keys SET name = ? WHERE id = ?').run(name, id);
}

function rotateApiKey(id) {
  const newKey = 'wk_' + crypto.randomBytes(32).toString('hex');
  getDb().prepare('UPDATE api_keys SET key_value = ? WHERE id = ?').run(newKey, id);
  return newKey;
}

function deleteApiKey(id) {
  const count = getDb().prepare('SELECT COUNT(*) as c FROM api_keys').get();
  if (count.c <= 1) throw new Error('Der letzte API-Key kann nicht gelöscht werden.');
  getDb().prepare('DELETE FROM api_keys WHERE id = ?').run(id);
}

// ── Per-key channel policies ──────────────────────────────────────────────────
function getKeyChannelPolicy(keyId, channelId) {
  const row = getDb()
    .prepare('SELECT policy FROM api_key_policies WHERE key_id = ? AND channel_id = ?')
    .get(keyId, String(channelId));
  return row ? row.policy : 'draft';
}

function setKeyChannelPolicy(keyId, channelId, policy, channelName) {
  getDb().prepare(`
    INSERT OR REPLACE INTO api_key_policies (key_id, channel_id, policy, channel_name, updated_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(keyId, String(channelId), policy, channelName || null, Date.now());
}

function getKeyChannelPolicies(keyId) {
  return getDb().prepare('SELECT * FROM api_key_policies WHERE key_id = ?').all(keyId);
}

// ── Admin password ────────────────────────────────────────────────────────────
function getAdminPasswordHash() {
  return getConfig('admin_password_hash');
}

function setAdminPasswordHash(hash) {
  setConfig('admin_password_hash', hash);
}

// ── Channel policies (legacy — kept for compatibility) ────────────────────────
function getChannelPolicy(channelId) {
  const row = getDb()
    .prepare('SELECT policy FROM channel_policies WHERE channel_id = ?')
    .get(String(channelId));
  return row ? row.policy : 'draft';
}

function setChannelPolicy(channelId, policy, channelName) {
  getDb().prepare(`
    INSERT OR REPLACE INTO channel_policies (channel_id, policy, channel_name, updated_at)
    VALUES (?, ?, ?, ?)
  `).run(String(channelId), policy, channelName || null, Date.now());
}

function getAllChannelPolicies() {
  return getDb().prepare('SELECT * FROM channel_policies').all();
}

// ── Activity log ──────────────────────────────────────────────────────────────
function logActivity({ channelIds, requestedType, effectiveType, policyApplied, requestPath, keyId }) {
  getDb().prepare(`
    INSERT INTO activity_log
      (timestamp, channel_ids, requested_type, effective_type, policy_applied, request_path, key_id)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    Date.now(),
    JSON.stringify(channelIds),
    requestedType,
    effectiveType,
    policyApplied,
    requestPath || null,
    keyId || null,
  );
}

function getRecentActivity(limit = 50) {
  return getDb()
    .prepare('SELECT * FROM activity_log ORDER BY id DESC LIMIT ?')
    .all(limit);
}

// ── Session secret ────────────────────────────────────────────────────────────
function getSessionSecret() {
  let secret = getConfig('session_secret');
  if (!secret) {
    secret = crypto.randomBytes(64).toString('hex');
    setConfig('session_secret', secret);
  }
  return secret;
}

module.exports = {
  getDb,
  getPostizApiKey,
  setPostizApiKey,
  getWrapperApiKey,
  generateWrapperApiKey,
  // Multi-key management
  createApiKey,
  listApiKeys,
  getApiKeyById,
  getApiKeyByValue,
  renameApiKey,
  rotateApiKey,
  deleteApiKey,
  // Per-key channel policies
  getKeyChannelPolicy,
  setKeyChannelPolicy,
  getKeyChannelPolicies,
  // Legacy
  getAdminPasswordHash,
  setAdminPasswordHash,
  getChannelPolicy,
  setChannelPolicy,
  getAllChannelPolicies,
  logActivity,
  getRecentActivity,
  getSessionSecret,
};
