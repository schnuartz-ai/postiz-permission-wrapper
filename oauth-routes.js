'use strict';
const express = require('express');
const crypto  = require('crypto');
const bcrypt  = require('bcrypt');
const db      = require('./db');

const router = express.Router();
const BASE   = 'https://postiz.clavastack.com/wrapper';

// In-memory auth-code store: code → { clientId, redirectUri, codeChallenge, method, expiresAt }
const authCodes = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [code, data] of authCodes)
    if (data.expiresAt < now) authCodes.delete(code);
}, 60_000).unref();

// ── OAuth Server Metadata ─────────────────────────────────────────────────────
router.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json({
    issuer:                               BASE,
    authorization_endpoint:              BASE + '/oauth/authorize',
    token_endpoint:                      BASE + '/oauth/token',
    response_types_supported:            ['code'],
    grant_types_supported:               ['authorization_code'],
    code_challenge_methods_supported:    ['S256', 'plain'],
    token_endpoint_auth_methods_supported: ['none'],
    scopes_supported:                    ['mcp'],
  });
});

// ── Authorization Page ────────────────────────────────────────────────────────
function authPage(query, errorMsg = '') {
  const qs = new URLSearchParams(query).toString();
  return `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Postiz Wrapper – Zugriff erlauben</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-950 min-h-screen flex items-center justify-center p-4">
  <div class="w-full max-w-sm bg-gray-900 border border-gray-800 rounded-2xl p-8 shadow-2xl">
    <div class="flex items-center gap-3 mb-6">
      <div class="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center text-white text-sm font-bold">P</div>
      <span class="font-semibold text-white">Postiz Wrapper</span>
    </div>
    <h1 class="text-lg font-semibold text-white mb-1">Zugriff erlauben</h1>
    <p class="text-sm text-gray-400 mb-6">
      Ein MCP-Client möchte auf deinen Postiz-Wrapper zugreifen.<br>
      Gib dein Admin-Passwort ein, um den Zugriff zu genehmigen.
    </p>
    ${errorMsg ? `<p class="text-sm text-red-400 bg-red-950 border border-red-900 rounded-lg px-3 py-2 mb-4">${errorMsg}</p>` : ''}
    <form method="POST" action="/oauth/authorize?${qs}">
      <input type="password" name="password" placeholder="Admin-Passwort"
        autofocus
        class="w-full bg-gray-800 border border-gray-700 text-white rounded-lg px-4 py-2.5 text-sm mb-4
               focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
      <button type="submit"
        class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-medium py-2.5 rounded-lg text-sm transition-colors">
        Zugriff genehmigen
      </button>
    </form>
  </div>
</body>
</html>`;
}

router.get('/oauth/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope } = req.query;
  if (response_type !== 'code' || !redirect_uri) {
    return res.status(400).send('Ungültige Anfrage: response_type=code und redirect_uri sind erforderlich.');
  }
  res.send(authPage(req.query));
});

router.post('/oauth/authorize', express.urlencoded({ extended: false }), async (req, res) => {
  const { password, response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.body;

  if (!redirect_uri) return res.status(400).send('redirect_uri fehlt.');

  // Passwort prüfen
  const hash  = db.getAdminPasswordHash();
  const valid = hash && password && await bcrypt.compare(password, hash);
  if (!valid) {
    return res.status(401).send(authPage(req.body, 'Falsches Passwort. Bitte erneut versuchen.'));
  }

  // Auth-Code ausstellen
  const code = crypto.randomBytes(32).toString('hex');
  authCodes.set(code, {
    clientId:            client_id || '',
    redirectUri:         redirect_uri,
    codeChallenge:       code_challenge || null,
    codeChallengeMethod: code_challenge_method || 'S256',
    expiresAt:           Date.now() + 5 * 60_000,
  });

  const dest = new URL(redirect_uri);
  dest.searchParams.set('code', code);
  if (state) dest.searchParams.set('state', state);
  res.redirect(dest.toString());
});

// ── Token Endpoint ────────────────────────────────────────────────────────────
router.post('/oauth/token', express.urlencoded({ extended: false }), express.json(), async (req, res) => {
  const { grant_type, code, redirect_uri, code_verifier } = req.body;

  if (grant_type !== 'authorization_code')
    return res.status(400).json({ error: 'unsupported_grant_type' });

  const stored = authCodes.get(code);
  if (!stored || stored.expiresAt < Date.now()) {
    authCodes.delete(code);
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Code ungültig oder abgelaufen.' });
  }

  // PKCE prüfen
  if (stored.codeChallenge) {
    if (!code_verifier)
      return res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier fehlt.' });

    const challenge = stored.codeChallengeMethod === 'S256'
      ? crypto.createHash('sha256').update(code_verifier).digest('base64url')
      : code_verifier;

    if (challenge !== stored.codeChallenge)
      return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE-Prüfung fehlgeschlagen.' });
  }

  authCodes.delete(code);

  res.json({
    access_token: db.getWrapperApiKey(),
    token_type:   'Bearer',
    expires_in:   365 * 24 * 3600,
    scope:        'mcp',
  });
});

module.exports = router;
