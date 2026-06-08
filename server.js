'use strict';
const express      = require('express');
const session      = require('express-session');
const bcrypt       = require('bcrypt');
const http         = require('http');
const https        = require('https');
const path         = require('path');
const db           = require('./db');
const { applyPolicy }    = require('./policy');
const adminRoutes        = require('./admin-routes');
const { mountMcpRoutes } = require('./mcp-server');
const oauthRoutes       = require('./oauth-routes');

const PORT        = parseInt(process.env.PORT || '3001', 10);
const HOST        = process.env.HOST || '127.0.0.1';
const POSTIZ_BASE = process.env.POSTIZ_BASE_URL || 'http://localhost:4007';
const API_PREFIX  = process.env.POSTIZ_API_PREFIX || '/api';

function requireWrapperKey(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const raw  = auth.startsWith('Bearer ') ? auth.slice(7)
             : auth                        ? auth
             : (req.query.key || '');

  const apiKey = db.getApiKeyByValue(raw);
  if (!apiKey) {
    res.set('WWW-Authenticate',
      'Bearer resource_metadata="https://postiz.clavastack.com/wrapper/.well-known/oauth-authorization-server"');
    return res.status(401).json({ error: 'Invalid or missing Authorization header' });
  }
  req.apiKeyId   = apiKey.id;
  req.apiKeyName = apiKey.name;
  next();
}

function proxyToPostiz(method, urlPath, body, postizKey) {
  const base    = new URL(POSTIZ_BASE);
  const hasBody = body && method !== 'GET' && method !== 'HEAD' && Object.keys(body).length > 0;
  const bodyStr = hasBody ? JSON.stringify(body) : null;

  const options = {
    hostname: base.hostname,
    port:     base.port || (base.protocol === 'https:' ? 443 : 80),
    path:     urlPath,
    method,
    headers: {
      'Authorization': postizKey,
      'Content-Type':  'application/json',
      'Accept':        'application/json',
    },
  };
  if (bodyStr) options.headers['Content-Length'] = Buffer.byteLength(bodyStr);

  const lib = base.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const req = lib.request(options, (res) => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(raw); } catch { parsed = { raw }; }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('error', reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

async function bootstrap() {
  db.getDb();

  const initialPw = process.env.INITIAL_ADMIN_PASSWORD;
  if (initialPw) {
    if (!db.getAdminPasswordHash()) {
      const hash = await bcrypt.hash(initialPw, 12);
      db.setAdminPasswordHash(hash);
      console.log('[bootstrap] Initial admin password stored');
    }
    delete process.env.INITIAL_ADMIN_PASSWORD;
  }

  const SQLiteStore = require('connect-sqlite3')(session);
  const store = new SQLiteStore({
    db:  'sessions',
    dir: path.join(__dirname, 'data'),
  });

  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  app.use(session({
    store,
    secret:            db.getSessionSecret(),
    resave:            false,
    saveUninitialized: false,
    name:              'pwsid',
    cookie: {
      httpOnly:  true,
      secure:    true,
      sameSite:  'strict',
      maxAge:    24 * 60 * 60 * 1000,
    },
  }));

  app.use('/', oauthRoutes);
  app.use('/admin', adminRoutes);

  mountMcpRoutes(app, { requireWrapperKey, proxyToPostiz, applyPolicy, db, apiPrefix: API_PREFIX });

  app.post('/public/v1/posts', requireWrapperKey, async (req, res) => {
    const postizKey = db.getPostizApiKey();
    if (!postizKey)
      return res.status(503).json({ error: 'Postiz API key not configured. Set it in the admin UI.' });

    try {
      const result = applyPolicy(req.body, req.path, req.apiKeyId);
      if (result.blocked) {
        return res.status(403).json({
          error: 'Post blocked by permission policy.',
          blockedChannels: result.blockedChannels || [],
        });
      }
      const upstream = await proxyToPostiz('POST', API_PREFIX + '/public/v1/posts', result.body, postizKey);
      res.status(upstream.status).json(upstream.body);
    } catch (err) {
      console.error('[proxy] POST /public/v1/posts error:', err.message);
      res.status(502).json({ error: 'Upstream error' });
    }
  });

  app.all('/public/v1/*', requireWrapperKey, async (req, res) => {
    const postizKey = db.getPostizApiKey();
    if (!postizKey)
      return res.status(503).json({ error: 'Postiz API key not configured. Set it in the admin UI.' });

    try {
      const upstream = await proxyToPostiz(req.method, API_PREFIX + req.url, req.body, postizKey);
      res.status(upstream.status).json(upstream.body);
    } catch (err) {
      console.error('[proxy] ' + req.method + ' ' + req.path + ' error:', err.message);
      res.status(502).json({ error: 'Upstream error' });
    }
  });

  app.use((req, res) => res.status(404).json({ error: 'Not found' }));

  app.listen(PORT, HOST, () => {
    console.log('[server] Postiz Permission Wrapper listening on ' + HOST + ':' + PORT);
  });
}

bootstrap().catch(err => {
  console.error('[bootstrap] Fatal:', err);
  process.exit(1);
});
