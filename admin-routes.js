'use strict';
const express  = require('express');
const bcrypt   = require('bcrypt');
const http     = require('http');
const path     = require('path');
const db       = require('./db');

const router = express.Router();

const POSTIZ_BASE_URL = process.env.POSTIZ_BASE_URL || 'http://localhost:4007';
const BASE_PATH       = process.env.WRAPPER_BASE_PATH || '';
const API_PREFIX      = process.env.POSTIZ_API_PREFIX || '/api';

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (req.session?.adminAuthenticated) return next();
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.redirect(`${BASE_PATH}/admin/login`);
}

// ── Pages ─────────────────────────────────────────────────────────────────────
router.get('/login', (req, res) => {
  if (req.session?.adminAuthenticated) return res.redirect(`${BASE_PATH}/admin`);
  res.sendFile('login.html', { root: path.join(__dirname, 'public') });
});

router.get('/', requireAdmin, (req, res) => {
  res.sendFile('index.html', { root: path.join(__dirname, 'public') });
});

// ── Auth actions ──────────────────────────────────────────────────────────────
router.post('/login', express.json(), express.urlencoded({ extended: false }), async (req, res) => {
  const password = (req.body.password || '').toString().trim();
  if (!password) return res.status(400).json({ error: 'Password required' });

  const hash = db.getAdminPasswordHash();
  if (!hash) return res.status(503).json({ error: 'Admin password not configured' });

  const valid = await bcrypt.compare(password, hash);
  if (!valid) return res.status(401).json({ error: 'Invalid password' });

  req.session.adminAuthenticated = true;
  res.json({ ok: true });
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ── API: Change password ──────────────────────────────────────────────────────
router.post('/api/change-password', requireAdmin, express.json(), async (req, res) => {
  const currentPassword = (req.body?.currentPassword || '').toString();
  const newPassword     = (req.body?.newPassword     || '').toString();
  const confirmPassword = (req.body?.confirmPassword || '').toString();

  if (!currentPassword || !newPassword || !confirmPassword)
    return res.status(400).json({ error: 'Alle drei Felder sind erforderlich.' });
  if (newPassword.length < 12)
    return res.status(400).json({ error: 'Neues Passwort muss mindestens 12 Zeichen haben.' });
  if (newPassword !== confirmPassword)
    return res.status(400).json({ error: 'Neues Passwort und Bestätigung stimmen nicht überein.' });

  const hash = db.getAdminPasswordHash();
  if (!hash) return res.status(503).json({ error: 'Kein Passwort konfiguriert.' });

  const valid = await bcrypt.compare(currentPassword, hash);
  if (!valid) return res.status(401).json({ error: 'Aktuelles Passwort ist falsch.' });

  const newHash = await bcrypt.hash(newPassword, 12);
  db.setAdminPasswordHash(newHash);

  req.session.destroy(() => {
    res.json({ ok: true, message: 'Passwort geändert. Bitte neu einloggen.' });
  });
});

// ── API: Postiz key ───────────────────────────────────────────────────────────
router.post('/api/postiz-key', requireAdmin, express.json(), (req, res) => {
  const key = (req.body?.key || '').toString().trim();
  if (!key) return res.status(400).json({ error: 'key is required' });
  db.setPostizApiKey(key);
  res.json({ ok: true });
});

// ── API: Test Postiz connection ───────────────────────────────────────────────
router.get('/api/test-postiz', requireAdmin, async (req, res) => {
  const postizKey = db.getPostizApiKey();
  if (!postizKey)
    return res.status(503).json({ ok: false, error: 'Kein Postiz API-Key gesetzt.' });
  try {
    await fetchFromPostiz(`${API_PREFIX}/public/v1/integrations`, postizKey);
    res.json({ ok: true, message: 'Verbindung erfolgreich.' });
  } catch (err) {
    res.status(502).json({ ok: false, error: err.message });
  }
});

// ── API: Wrapper key (legacy – returns first key for backward compat) ─────────
router.get('/api/wrapper-key', requireAdmin, (req, res) => {
  res.json({ key: db.getWrapperApiKey() });
});

router.post('/api/wrapper-key/rotate', requireAdmin, (req, res) => {
  const key = db.generateWrapperApiKey();
  res.json({ key });
});

// ── API: Multi-key management ─────────────────────────────────────────────────

// List all keys
router.get('/api/keys', requireAdmin, (req, res) => {
  const keys = db.listApiKeys();
  res.json({ keys });
});

// Create a new key
router.post('/api/keys', requireAdmin, express.json(), (req, res) => {
  const name = (req.body?.name || '').toString().trim();
  if (!name) return res.status(400).json({ error: 'name ist erforderlich.' });
  const apiKey = db.createApiKey(name);
  res.status(201).json({ key: apiKey });
});

// Rename a key
router.patch('/api/keys/:id', requireAdmin, express.json(), (req, res) => {
  const { id } = req.params;
  const name = (req.body?.name || '').toString().trim();
  if (!name) return res.status(400).json({ error: 'name ist erforderlich.' });
  const apiKey = db.getApiKeyById(id);
  if (!apiKey) return res.status(404).json({ error: 'Key nicht gefunden.' });
  db.renameApiKey(id, name);
  res.json({ ok: true, id, name });
});

// Rotate a key's value
router.post('/api/keys/:id/rotate', requireAdmin, (req, res) => {
  const { id } = req.params;
  const apiKey = db.getApiKeyById(id);
  if (!apiKey) return res.status(404).json({ error: 'Key nicht gefunden.' });
  const newKeyValue = db.rotateApiKey(id);
  res.json({ ok: true, id, key_value: newKeyValue });
});

// Delete a key
router.delete('/api/keys/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const apiKey = db.getApiKeyById(id);
  if (!apiKey) return res.status(404).json({ error: 'Key nicht gefunden.' });
  try {
    db.deleteApiKey(id);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── API: Per-key channels ─────────────────────────────────────────────────────

// Get channels with per-key policies
router.get('/api/keys/:keyId/channels', requireAdmin, async (req, res) => {
  const { keyId } = req.params;
  if (!db.getApiKeyById(keyId))
    return res.status(404).json({ error: 'Key nicht gefunden.' });

  const postizKey = db.getPostizApiKey();
  if (!postizKey) {
    return res.status(503).json({
      error: 'Postiz API-Key nicht gesetzt. Bitte zuerst in den Einstellungen eintragen.'
    });
  }

  try {
    const data    = await fetchFromPostiz(`${API_PREFIX}/public/v1/integrations`, postizKey);
    const rawList = Array.isArray(data) ? data : (data.integrations || data.items || []);

    const policies  = db.getKeyChannelPolicies(keyId);
    const policyMap = Object.fromEntries(policies.map(p => [p.channel_id, p.policy]));

    const channels = rawList.map(ch => ({
      id:       String(ch.id),
      name:     ch.name || ch.profile?.name || ch.identifier || String(ch.id),
      type:     ch.identifier || ch.type || '',
      picture:  ch.picture || ch.profile?.picture || null,
      username: ch.profile?.username || ch.profile?.handle || null,
      disabled: ch.disabled || false,
      policy:   policyMap[String(ch.id)] || 'draft',
    }));

    res.json({ channels });
  } catch (err) {
    console.error('[admin] /api/keys/:keyId/channels error:', err.message);
    res.status(502).json({ error: err.message });
  }
});

// Set per-key channel policy
router.post('/api/keys/:keyId/channels/:channelId/policy', requireAdmin, express.json(), (req, res) => {
  const { keyId, channelId } = req.params;
  const policy  = (req.body?.policy || '').toString();
  const name    = req.body?.name || null;

  if (!db.getApiKeyById(keyId))
    return res.status(404).json({ error: 'Key nicht gefunden.' });
  if (!['auto', 'draft', 'blocked'].includes(policy))
    return res.status(400).json({ error: 'policy muss "auto", "draft" oder "blocked" sein.' });

  db.setKeyChannelPolicy(keyId, channelId, policy, name);
  res.json({ ok: true, keyId, channelId, policy });
});

// ── API: Channels (legacy – global policies, kept for compatibility) ───────────
router.get('/api/channels', requireAdmin, async (req, res) => {
  const postizKey = db.getPostizApiKey();
  if (!postizKey) {
    return res.status(503).json({
      error: 'Postiz API-Key nicht gesetzt. Bitte zuerst in den Einstellungen eintragen.'
    });
  }

  try {
    const data    = await fetchFromPostiz(`${API_PREFIX}/public/v1/integrations`, postizKey);
    const rawList = Array.isArray(data) ? data : (data.integrations || data.items || []);

    const policies  = db.getAllChannelPolicies();
    const policyMap = Object.fromEntries(policies.map(p => [p.channel_id, p.policy]));

    const channels = rawList.map(ch => ({
      id:      String(ch.id),
      name:    ch.name || ch.profile?.name || ch.identifier || String(ch.id),
      type:    ch.identifier || ch.type || '',
      picture: ch.picture || ch.profile?.picture || null,
      username: ch.profile?.username || ch.profile?.handle || null,
      disabled: ch.disabled || false,
      policy:  policyMap[String(ch.id)] || 'draft',
    }));

    res.json({ channels });
  } catch (err) {
    console.error('[admin] /api/channels error:', err.message);
    res.status(502).json({ error: err.message });
  }
});

router.post('/api/channels/:id/policy', requireAdmin, express.json(), (req, res) => {
  const { id } = req.params;
  const policy  = (req.body?.policy || '').toString();
  const name    = req.body?.name || null;

  if (!['auto', 'draft', 'blocked'].includes(policy))
    return res.status(400).json({ error: 'policy must be "auto", "draft", or "blocked"' });

  db.setChannelPolicy(id, policy, name);
  res.json({ ok: true, id, policy });
});

// ── API: Activity log ─────────────────────────────────────────────────────────
router.get('/api/activity', requireAdmin, (req, res) => {
  const entries = db.getRecentActivity(50);
  res.json({ entries });
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function fetchFromPostiz(urlPath, apiKey) {
  const base = new URL(POSTIZ_BASE_URL);
  const options = {
    hostname: base.hostname,
    port:     base.port || (base.protocol === 'https:' ? 443 : 80),
    path:     urlPath,
    method:   'GET',
    headers:  {
      'Authorization': apiKey,
      'Accept':        'application/json',
    },
  };

  const lib = base.protocol === 'https:' ? require('https') : http;

  return new Promise((resolve, reject) => {
    const req = lib.request(options, (res) => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        if (res.statusCode >= 300 && res.statusCode < 400) {
          const location = res.headers['location'] || '?';
          return reject(new Error(
            `Postiz API-Key ungültig oder abgelaufen (HTTP ${res.statusCode} → ${location}). ` +
            `Bitte Key in den Einstellungen prüfen.`
          ));
        }
        if (res.statusCode >= 400) {
          return reject(new Error(
            `Postiz antwortete mit HTTP ${res.statusCode}: ${raw.slice(0, 200)}`
          ));
        }
        try {
          resolve(JSON.parse(raw));
        } catch {
          reject(new Error(
            `Postiz antwortete nicht mit JSON (HTTP ${res.statusCode}). ` +
            `Antwort: ${raw.slice(0, 100)}`
          ));
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

module.exports = router;
