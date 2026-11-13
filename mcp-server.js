'use strict';
const { McpServer }                     = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { z }                             = require('zod');
const path                              = require('path');
const db                                = require('./db');
const fs                                = require('fs');
const http                              = require('http');
const https                             = require('https');
const crypto                            = require('crypto');

const UPLOAD_DIR    = path.join(__dirname, 'public', 'uploads');
const PUBLIC_BASE   = 'https://postiz.clavastack.com/wrapper/uploads';
const ALLOWED_TYPES = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/gif': '.gif', 'image/webp': '.webp' };
// Local paths the wrapper is allowed to read from
const ALLOWED_DIRS  = ['/home/', '/tmp/', '/mnt/', '/opt/postiz-wrapper/public/'];

// ---------------------------------------------------------------------------
// Media helpers
// ---------------------------------------------------------------------------

function extFromMime(mime) {
  return ALLOWED_TYPES[mime] || null;
}

function extFromPath(filePath) {
  const map = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp' };
  const e = path.extname(filePath).toLowerCase();
  return { mime: map[e] || null, ext: ALLOWED_TYPES[map[e]] || null };
}

function saveBuffer(buf, ext, hint) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  const uid  = crypto.randomBytes(8).toString('hex');
  const base = hint ? path.basename(hint).replace(/[^a-zA-Z0-9._-]/g, '_').replace(/\.[^.]+$/, '') : 'media';
  const name = `${base}_${uid}${ext}`;
  fs.writeFileSync(path.join(UPLOAD_DIR, name), buf);
  return `${PUBLIC_BASE}/${name}`;
}

async function downloadUrl(srcUrl) {
  return new Promise((resolve, reject) => {
    const lib = srcUrl.startsWith('https') ? https : http;
    const req = lib.get(srcUrl, { headers: { 'User-Agent': 'PostizWrapper/1.0' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return downloadUrl(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ buf: Buffer.concat(chunks), ct: (res.headers['content-type'] || '').split(';')[0].trim() }));
      res.on('error', reject);
    });
    req.on('error', reject);
  });
}

/**
 * Resolves a single media item to a public wrapper URL.
 * Accepts:
 *   - data:image/...;base64,...   (base64 data URL — recommended for ChatGPT)
 *   - https?://...                (remote URL — downloaded and re-hosted)
 *   - /absolute/path              (local server file — must be in ALLOWED_DIRS)
 *
 * Returns { url: string, size_bytes: number, source: string }
 * Throws on error.
 */
async function resolveMediaItem(item) {
  // ── 1. Base64 data URL ────────────────────────────────────────────────────
  if (item.startsWith('data:')) {
    const m = item.match(/^data:([^;]+);base64,(.+)$/s);
    if (!m) throw new Error(`Ungültiges data-URL-Format`);
    const mime   = m[1];
    const ext    = extFromMime(mime);
    if (!ext) throw new Error(`Nicht unterstützter MIME-Typ in data-URL: ${mime}`);
    const buf = Buffer.from(m[2], 'base64');
    if (buf.length === 0)              throw new Error('data-URL enthält leere Daten');
    if (buf.length > 20 * 1024 * 1024) throw new Error('Datei zu groß (max. 20 MB)');
    const url = saveBuffer(buf, ext, 'upload');
    return { url, size_bytes: buf.length, source: 'base64' };
  }

  // ── 2. Remote URL ─────────────────────────────────────────────────────────
  if (/^https?:\/\//.test(item)) {
    const { buf, ct } = await downloadUrl(item);
    const ext = extFromMime(ct)
      || (item.match(/\.(png|jpe?g|gif|webp)(\?|$)/i)
          ? extFromMime({ png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', gif:'image/gif', webp:'image/webp' }[item.match(/\.(png|jpe?g|gif|webp)/i)[1].toLowerCase()] )
          : null);
    if (!ext) throw new Error(`Nicht unterstützter Typ: ${ct || 'unbekannt'}`);
    if (buf.length === 0)              throw new Error('Remote-Datei ist leer');
    if (buf.length > 20 * 1024 * 1024) throw new Error('Remote-Datei zu groß (max. 20 MB)');
    const url = saveBuffer(buf, ext, path.basename(item.split('?')[0]) || 'remote');
    return { url, size_bytes: buf.length, source: 'url' };
  }

  // ── 3. Local file path ────────────────────────────────────────────────────
  const normalized = path.resolve(item);
  if (!ALLOWED_DIRS.some(d => normalized.startsWith(d))) {
    throw new Error(`Pfad nicht erlaubt: ${normalized}. Erlaubt: ${ALLOWED_DIRS.join(', ')}`);
  }
  const { mime, ext } = extFromPath(normalized);
  if (!ext) throw new Error(`Nicht unterstütztes Format: ${path.extname(normalized)}`);
  let buf;
  try { buf = fs.readFileSync(normalized); }
  catch (e) { throw new Error(`Datei nicht lesbar: ${e.message}`); }
  if (buf.length === 0)              throw new Error('Datei ist leer');
  if (buf.length > 20 * 1024 * 1024) throw new Error('Datei zu groß (max. 20 MB)');
  const url = saveBuffer(buf, ext, path.basename(normalized));
  return { url, size_bytes: buf.length, source: normalized };
}

/**
 * Resolves an array of media items. Returns { urls: string[], errors: string[] }.
 * Never throws — errors are collected per item.
 */
async function resolveMediaItems(items) {
  const urls   = [];
  const errors = [];
  for (const item of items) {
    try {
      const r = await resolveMediaItem(item);
      urls.push(r.url);
    } catch (e) {
      errors.push(`[${item.slice(0, 60)}]: ${e.message}`);
    }
  }
  return { urls, errors };
}

/**
 * Uploads a buffer to Postiz media library.
 * Returns { id, url } — both required by Postiz post creation API.
 */
async function uploadToPostiz(buf, filename, mimeType) {
  const postizKey = db.getPostizApiKey();
  if (!postizKey) throw new Error('Postiz API key nicht konfiguriert.');

  const boundary = '----FormBoundary' + crypto.randomBytes(8).toString('hex');
  const body = Buffer.concat([
    Buffer.from('--' + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="' + filename + '"\r\nContent-Type: ' + mimeType + '\r\n\r\n'),
    buf,
    Buffer.from('\r\n--' + boundary + '--\r\n'),
  ]);

  return new Promise((resolve, reject) => {
    const urlObj = new URL(process.env.POSTIZ_BASE_URL || 'http://localhost:4007');
    const lib = urlObj.protocol === 'https:' ? require('https') : require('http');
    const req = lib.request({
      hostname: urlObj.hostname,
      port:     urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path:     (process.env.POSTIZ_API_PREFIX || '/api') + '/public/v1/upload',
      method:   'POST',
      headers: {
        'Authorization': postizKey,
        'Content-Type':  'multipart/form-data; boundary=' + boundary,
        'Content-Length': body.length,
      },
    }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        try {
          const d = JSON.parse(raw);
          if (!d.id) throw new Error('Kein id in Postiz-Antwort: ' + raw.slice(0, 200));
          resolve({ id: d.id, url: d.path });
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/**
 * Resolves a media item (data URL / https URL / local path) to a Postiz media object { id, url }.
 * Uploads to Postiz so the returned id is valid for post creation.
 */
async function resolveAndUploadMedia(item) {
  // Own wrapper uploads: Postiz accepts any non-null UUID as id,
  // so we skip the round-trip download+upload and reference directly.
  if (item.startsWith(PUBLIC_BASE + '/')) {
    const uuid = require('crypto').randomBytes(16).toString('hex')
      .replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
    return { id: uuid, url: item };
  }

  let buf, mimeType;

  if (item.startsWith('data:')) {
    const m = item.match(/^data:([^;]+);base64,(.+)$/s);
    if (!m) throw new Error('Ungültiges data-URL-Format');
    mimeType = m[1];
    if (!extFromMime(mimeType)) throw new Error('Nicht unterstützter MIME-Typ: ' + mimeType);
    buf = Buffer.from(m[2], 'base64');
  } else if (/^https?:\/\//.test(item)) {
    const r = await downloadUrl(item);
    mimeType = r.ct || 'image/png';
    buf = r.buf;
  } else {
    const normalized = path.resolve(item);
    if (!ALLOWED_DIRS.some(d => normalized.startsWith(d)))
      throw new Error('Pfad nicht erlaubt: ' + normalized);
    const { mime } = extFromPath(normalized);
    mimeType = mime || 'image/png';
    buf = fs.readFileSync(normalized);
  }

  if (!buf || buf.length === 0) throw new Error('Datei ist leer');
  if (buf.length > 20 * 1024 * 1024) throw new Error('Datei zu groß (max. 20 MB)');

  const ext = extFromMime(mimeType) || '.png';
  const filename = crypto.randomBytes(8).toString('hex') + ext;
  return uploadToPostiz(buf, filename, mimeType);
}

/**
 * Formats the Postiz API response into the clean success structure.
 * Postiz v1 returns: [{postId, integration}]
 */
function formatScheduleResponse(postizBody, scheduledAt, integrationMap) {
  // Postiz public v1 returns array of {postId, integration (id string)}
  const items = Array.isArray(postizBody) ? postizBody : (postizBody?.posts || []);
  const scheduled_posts = items.map(p => {
    const integId = p.integration || p.integrationId || null;
    const info    = integrationMap?.[integId] || {};
    return {
      platform:     info.platform || 'unknown',
      profile:      info.name || integId || 'unknown',
      post_id:      p.postId || p.id || null,
      scheduled_at: scheduledAt || null,
      media_count:  info.media_count || 0,
    };
  });
  return { success: true, scheduled_posts };
}

// ---------------------------------------------------------------------------

function mountMcpRoutes(app, { requireWrapperKey, proxyToPostiz, applyPolicy, db, apiPrefix }) {

  app.use('/uploads', require('express').static(UPLOAD_DIR, { maxAge: '7d' }));

  function createServer(keyId) {
    const server = new McpServer({
      name: 'Postiz Wrapper',
      version: '2.0.0',
      instructions: [
        'Tools zum Planen und Verwalten von Social-Media-Posts via Postiz.',
        'Für Medien-Uploads: media_paths akzeptiert lokale Pfade (/mnt/data/...), base64-Data-URLs (data:image/png;base64,...) und https-URLs.',
        'Für X/Twitter-Threads: create_thread verwenden. Für alle anderen Plattformen: create_post.',
      ].join(' '),
    });

    async function proxy(method, urlPath, body) {
      const postizKey = db.getPostizApiKey();
      if (!postizKey) throw new Error('Postiz API key nicht konfiguriert.');
      return proxyToPostiz(method, apiPrefix + urlPath, body || {}, postizKey);
    }

    // Das Postiz-Backend hat keine GET-Route für einzelne Posts, und DELETE
    // erwartet die `group`-ID statt der Post-`id`. Beides lässt sich nur über
    // die Listen-Route auflösen, daher hier: Post per `id` über /public/v1/posts
    // suchen (über einen weiten Datumsbereich paginiert) und das volle Objekt
    // (inkl. `group`) zurückgeben.
    async function findPostById(post_id) {
      const wideStart = new Date(Date.now() - 3 * 365 * 24 * 60 * 60 * 1000).toISOString();
      const wideEnd   = new Date(Date.now() + 3 * 365 * 24 * 60 * 60 * 1000).toISOString();
      for (let page = 1; page <= 50; page++) {
        const qs = new URLSearchParams({ page: String(page), limit: '50', startDate: wideStart, endDate: wideEnd });
        const r  = await proxy('GET', `/public/v1/posts?${qs}`, {});
        const posts = r.body?.posts || [];
        const found = posts.find((p) => p.id === post_id);
        if (found) return found;
        if (posts.length < 50) break;
      }
      return null;
    }

    // ── list_integrations ──────────────────────────────────────────────────
    server.tool(
      'list_integrations',
      'Listet alle verbundenen Social-Media-Konten auf. Gibt ID, Name und Plattform zurück. Die integrationId wird beim Erstellen von Posts benötigt.',
      {},
      async () => {
        const r = await proxy('GET', '/public/v1/integrations', {});
        return { content: [{ type: 'text', text: JSON.stringify(r.body, null, 2) }] };
      }
    );

    // ── upload_media ────────────────────────────────────────────────────────
    server.tool(
      'upload_media',
      [
        'Lädt eine oder mehrere Mediendateien hoch und gibt öffentliche URLs zurück.',
        'Jeder Eintrag in file_paths kann sein:',
        '(1) base64 data-URL: "data:image/png;base64,..." — empfohlen wenn ChatGPT Bilder generiert hat,',
        '(2) https-URL: wird heruntergeladen und re-gehostet,',
        '(3) lokaler Serverpfad: /home/..., /tmp/..., /mnt/... — nur wenn die Datei auf dem Wrapper-Server liegt.',
        'Rückgabe: { media_urls: ["https://..."], errors: [...] }',
      ].join(' '),
      {
        file_paths: z.array(z.string()).min(1).max(10)
          .describe('Liste von Medienpfaden/-quellen. Max. 10 Einträge.'),
      },
      async ({ file_paths }) => {
        const { urls, errors } = await resolveMediaItems(file_paths);
        const result = { media_urls: urls };
        if (errors.length > 0) result.errors = errors;
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      }
    );

    // ── create_post ─────────────────────────────────────────────────────────
    server.tool(
      'create_post',
      [
        'Erstellt oder plant einen Social-Media-Post auf einer oder mehreren Plattformen.',
        'Für X/Twitter-Threads stattdessen create_thread verwenden.',
        'Medien via media_paths übergeben (base64, https-URL oder Serverpfad) — der Wrapper hostet sie automatisch.',
        'Policy-Regeln gelten: gesperrte Kanäle → 403, draft-Kanäle → Entwurfsmodus.',
      ].join(' '),
      {
        integration_ids: z.array(z.string()).min(1)
          .describe('Konto-IDs aus list_integrations. Pro ID wird ein Post erstellt.'),
        content: z.string()
          .describe('Posttext.'),
        type: z.enum(['now', 'schedule', 'draft']).default('now')
          .describe('"now" = sofort, "schedule" = geplant (date erforderlich), "draft" = Entwurf.'),
        post_type: z.enum(['post', 'story']).default('post')
          .describe('Nur für Instagram: "post" oder "story" (Standard: "post"). Stories unterstützen nur ein Bild.'),
        date: z.string().optional()
          .describe('ISO-8601 Datum, z.B. "2026-06-19T16:00:00.000Z". Nur bei type="schedule".'),
        media_paths: z.array(z.string()).optional()
          .describe([
            'Mediendateien für den Post. Akzeptiert:',
            '• base64 data-URL: "data:image/png;base64,..." (von ChatGPT generierte Bilder so übergeben)',
            '• https-URL: wird heruntergeladen',
            '• Serverpfad: /mnt/data/bild.png, /home/finn/bild.png usw.',
          ].join(' ')),
        image_urls: z.array(z.string()).optional()
          .describe('Bereits öffentliche Bild-URLs (Legacy-Feld). Alternativ media_paths verwenden.'),
        short_link: z.boolean().default(false).optional()
          .describe('URLs im Post als Kurzlink.'),
        tags: z.array(z.string()).default([]).optional()
          .describe('Optionale Tags.'),
      },
      async ({ integration_ids, content, type = 'now', post_type = 'post', date, media_paths, image_urls, short_link = false, tags = [] }) => {

        // The public integrations endpoint returns the provider as `identifier`.
        // Resolve every requested account before uploading media or creating posts.
        let integrations;
        try {
          integrations = await proxy('GET', '/public/v1/integrations', {});
        } catch (e) {
          return { isError: true, content: [{ type: 'text', text: JSON.stringify({
            error: 'Plattformen konnten nicht ermittelt werden: Integrationen sind nicht erreichbar.',
          }) }] };
        }
        if (!Number.isInteger(integrations?.status) || integrations.status < 200 ||
            integrations.status >= 300 || !Array.isArray(integrations.body)) {
          return { isError: true, content: [{ type: 'text', text: JSON.stringify({
            error: 'Plattformen konnten nicht ermittelt werden: Ungültige Antwort der Integrationen.',
          }) }] };
        }
        const providers = new Map(integrations.body
          .filter(integration => typeof integration?.id === 'string' &&
            typeof integration.identifier === 'string' && integration.identifier.length > 0)
          .map(integration => [integration.id, integration.identifier]));
        const missingIds = integration_ids.filter(id => !providers.has(id));
        if (missingIds.length > 0) {
          return { isError: true, content: [{ type: 'text', text: JSON.stringify({
            error: 'Plattform für mindestens eine Integration nicht gefunden.',
            integration_ids: missingIds,
          }) }] };
        }

        // Resolve media_paths → Postiz media objects {id, url}
        let resolvedMedia = [];
        let mediaErrors   = [];
        const allSources  = [...(media_paths || []), ...(image_urls || [])];
        for (const src of allSources) {
          try {
            const m = await resolveAndUploadMedia(src);
            resolvedMedia.push(m);
          } catch (e) {
            mediaErrors.push('[' + src.slice(0, 60) + ']: ' + e.message);
          }
        }

        const allUrls = resolvedMedia.map(m => m.url);
        const image   = resolvedMedia.map(m => ({ id: m.id, url: m.url, path: m.url }));

        const value = [{ content, image }];

        // Postiz always requires a date field
        const effectiveDate = date || new Date().toISOString();

        const body = {
          type,
          date: effectiveDate,
          shortLink: short_link,
          tags,
          posts: integration_ids.map(id => {
            const provider = providers.get(id);
            const settings = provider === 'instagram' || provider === 'instagram-standalone'
              ? { __type: provider, post_type }
              : { who_can_reply_post: 'everyone' };
            return { integration: { id }, value, settings };
          }),
        };

        const policyResult = applyPolicy(body, '/public/v1/posts', keyId);
        if (policyResult.blocked) {
          return {
            isError: true,
            content: [{ type: 'text', text: JSON.stringify({
              error: 'Post durch Policy blockiert',
              blockedChannels: policyResult.blockedChannels,
            }, null, 2) }],
          };
        }

        const r      = await proxy('POST', '/public/v1/posts', policyResult.body);

        // Non-2xx → report the actual Postiz error
        if (r.status < 200 || r.status >= 300) {
          const errResult = {
            success: false,
            error: 'Postiz returned HTTP ' + r.status,
            postiz_response: r.body,
          };
          if (mediaErrors.length > 0) errResult.media_warnings = mediaErrors;
          return { isError: true, content: [{ type: 'text', text: JSON.stringify(errResult, null, 2) }] };
        }

        // Build integration map for response enrichment
        const integMap = {};
        integration_ids.forEach(id => {
          integMap[id] = { media_count: allUrls.length };
        });
        const result = formatScheduleResponse(r.body, effectiveDate, integMap);
        if (mediaErrors.length > 0) result.media_warnings = mediaErrors;

        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      }
    );

    // ── create_thread ────────────────────────────────────────────────────────
    server.tool(
      'create_thread',
      [
        'Erstellt einen X/Twitter-Thread: mehrere Tweets in Folge, jeder mit eigenem Text und eigenen Bildern.',
        'Für Nostr, LinkedIn, etc. stattdessen create_post verwenden (unterstützt mehrere Bilder in einem Post).',
        'Medien pro Tweet via media_paths (base64, https-URL, Serverpfad) ODER image_urls (bereits gehostete URLs vom upload_media-Tool — kein Re-Hosting).',
      ].join(' '),
      {
        integration_id: z.string()
          .describe('ID des X/Twitter-Kontos aus list_integrations.'),
        type: z.enum(['now', 'schedule', 'draft']).default('now')
          .describe('"now" = sofort, "schedule" = geplant, "draft" = Entwurf.'),
        date: z.string().optional()
          .describe('ISO-8601 Datum für den Thread. Nur bei type="schedule".'),
        posts: z.array(z.object({
          content: z.string()
            .describe('Text dieses Tweets.'),
          media_paths: z.array(z.string()).optional()
            .describe('Medien für diesen Tweet (base64, https-URL oder Serverpfad). Max. 4 Bilder pro Tweet.'),
          image_urls: z.array(z.string()).optional()
            .describe('Bereits öffentliche Bild-URLs (z. B. vom upload_media-Tool). Werden ohne Re-Hosting direkt referenziert.'),
        })).min(1).max(25)
          .describe('Die einzelnen Tweets des Threads. Reihenfolge = Reihenfolge im Thread.'),
        short_link: z.boolean().default(false).optional()
          .describe('URLs als Kurzlink.'),
        tags: z.array(z.string()).default([]).optional()
          .describe('Optionale Tags.'),
      },
      async ({ integration_id, type = 'now', date, posts, short_link = false, tags = [] }) => {

        // Resolve all media for all thread posts
        const value = [];
        const allMediaErrors = [];

        for (const post of posts) {
          let image = [];
          const sources = [...(post.media_paths || []), ...(post.image_urls || [])].slice(0, 4);
          for (const src of sources) {
            try {
              const m = await resolveAndUploadMedia(src);
              image.push({ id: m.id, url: m.url, path: m.url });
            } catch (e) {
              allMediaErrors.push('[' + src.slice(0, 60) + ']: ' + e.message);
            }
          }
          value.push({ content: post.content, image });
        }

        const effectiveDate = date || new Date().toISOString();

        const body = {
          type,
          date: effectiveDate,
          shortLink: short_link,
          tags,
          posts: [{
            integration: { id: integration_id },
            value,
            settings: { who_can_reply_post: 'everyone' },
          }],
        };

        const policyResult = applyPolicy(body, '/public/v1/posts', keyId);
        if (policyResult.blocked) {
          return {
            isError: true,
            content: [{ type: 'text', text: JSON.stringify({
              error: 'Thread durch Policy blockiert',
              blockedChannels: policyResult.blockedChannels,
            }, null, 2) }],
          };
        }

        const r = await proxy('POST', '/public/v1/posts', policyResult.body);

        // Non-2xx → report the actual Postiz error
        if (r.status < 200 || r.status >= 300) {
          const errResult = {
            success: false,
            error: 'Postiz returned HTTP ' + r.status,
            postiz_response: r.body,
          };
          if (allMediaErrors.length > 0) errResult.media_warnings = allMediaErrors;
          return { isError: true, content: [{ type: 'text', text: JSON.stringify(errResult, null, 2) }] };
        }

        const created = Array.isArray(r.body) ? r.body : (r.body?.posts || []);
        const firstPost = created[0] || {};
        const result = {
          success: true,
          thread: {
            integration_id,
            tweet_count: posts.length,
            scheduled_at: effectiveDate,
            post_id: firstPost.postId || firstPost.id || null,
          },
        };
        if (allMediaErrors.length > 0) result.media_warnings = allMediaErrors;

        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      }
    );


    // ── get_channel_policies ─────────────────────────────────────────────────
    server.tool(
      'get_channel_policies',
      'Zeigt für jeden verbundenen Account, ob Postings direkt veröffentlicht werden (auto), als Entwurf gespeichert werden (draft) oder blockiert sind (blocked). Vor dem Schedulen aufrufen um sicherzustellen dass der Channel auf auto steht.',
      {},
      async () => {
        const r = await proxy('GET', '/public/v1/integrations', {});
        const integrations = Array.isArray(r.body) ? r.body : [];
        const result = integrations.map(i => ({
          id:       i.id,
          name:     i.name,
          platform: i.identifier,
          policy:   db.getKeyChannelPolicy(keyId, i.id),
        }));
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      }
    );

    // ── list_posts ───────────────────────────────────────────────────────────
    server.tool(
      'list_posts',
      'Listet geplante und veröffentlichte Posts im angegebenen Zeitraum auf. Standard: heute bis +60 Tage.',
      {
        page: z.number().int().min(1).default(1).optional(),
        limit: z.number().int().min(1).max(50).default(20).optional(),
        start_date: z.string().optional()
          .describe('ISO-8601 Startdatum. Standard: heute 00:00 UTC.'),
        end_date: z.string().optional()
          .describe('ISO-8601 Enddatum. Standard: heute +60 Tage.'),
      },
      async ({ page = 1, limit = 20, start_date, end_date }) => {
        const now = new Date();
        const sd  = start_date || new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())).toISOString();
        const ed  = end_date   || new Date(now.getTime() + 60 * 24 * 60 * 60 * 1000).toISOString();
        const qs  = new URLSearchParams({ page: String(page), limit: String(limit), startDate: sd, endDate: ed });
        const r   = await proxy('GET', `/public/v1/posts?${qs}`, {});
        return { content: [{ type: 'text', text: JSON.stringify(r.body, null, 2) }] };
      }
    );

    // ── get_post ─────────────────────────────────────────────────────────────
    server.tool(
      'get_post',
      'Ruft Details zu einem einzelnen Post ab.',
      { post_id: z.string() },
      async ({ post_id }) => {
        const post = await findPostById(post_id);
        if (!post) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: 'Post nicht gefunden', post_id }, null, 2) }] };
        }
        return { content: [{ type: 'text', text: JSON.stringify(post, null, 2) }] };
      }
    );

    // ── delete_post ──────────────────────────────────────────────────────────
    server.tool(
      'delete_post',
      'Löscht einen geplanten Post.',
      { post_id: z.string() },
      async ({ post_id }) => {
        const post = await findPostById(post_id);
        if (!post) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: 'Post nicht gefunden, kann nicht gelöscht werden', post_id }, null, 2) }] };
        }
        const r = await proxy('DELETE', `/public/v1/posts/group/${encodeURIComponent(post.group)}`, {});
        return { content: [{ type: 'text', text: JSON.stringify(r.body, null, 2) }] };
      }
    );

    // ── get_analytics_summary ─────────────────────────────────────────────────
    server.tool(
      'get_analytics_summary',
      'Liefert eine aggregierte Übersicht über Posts im Zeitraum: Gesamt, nach Status, Plattform, Account, Tag. Standard: letzte 30 Tage.',
      {
        start_date: z.string().optional().describe('ISO-8601 Startdatum. Standard: -30 Tage.'),
        end_date:   z.string().optional().describe('ISO-8601 Enddatum. Standard: morgen.'),
      },
      async ({ start_date, end_date }) => {
        const now = new Date();
        const sd  = start_date || new Date(now.getTime() - 30 * 86400 * 1000).toISOString();
        const ed  = end_date   || new Date(now.getTime() +      86400 * 1000).toISOString();

        const allPosts = [];
        let page = 1;
        while (true) {
          const qs = new URLSearchParams({ page: String(page), limit: '100', startDate: sd, endDate: ed });
          const r  = await proxy('GET', `/public/v1/posts?${qs}`, {});
          const posts = r.body?.posts || [];
          allPosts.push(...posts);
          if (posts.length < 100 || page >= 10) break;
          page++;
        }

        const byState = {}, byPlatform = {}, byAccount = {}, byDay = {};
        for (const post of allPosts) {
          const state    = post.state || 'UNKNOWN';
          const platform = post.integration?.providerIdentifier || 'unknown';
          const accId    = post.integration?.id;
          const accName  = post.integration?.name || accId || 'Unknown';

          byState[state] = (byState[state] || 0) + 1;

          if (!byPlatform[platform]) byPlatform[platform] = { platform, total: 0, published: 0, errors: 0, draft: 0, queue: 0 };
          byPlatform[platform].total++;
          if      (state === 'PUBLISHED') byPlatform[platform].published++;
          else if (state === 'ERROR')     byPlatform[platform].errors++;
          else if (state === 'DRAFT')     byPlatform[platform].draft++;
          else if (state === 'QUEUE')     byPlatform[platform].queue++;

          if (accId) {
            if (!byAccount[accId]) byAccount[accId] = { id: accId, name: accName, platform, total: 0, published: 0, errors: 0 };
            byAccount[accId].total++;
            if      (state === 'PUBLISHED') byAccount[accId].published++;
            else if (state === 'ERROR')     byAccount[accId].errors++;
          }

          const day = (post.publishDate || '').slice(0, 10);
          if (day) byDay[day] = (byDay[day] || 0) + 1;
        }

        return { content: [{ type: 'text', text: JSON.stringify({
          period:      { start: sd, end: ed },
          total:       allPosts.length,
          by_state:    byState,
          by_platform: Object.values(byPlatform).sort((a, b) => b.total - a.total),
          by_account:  Object.values(byAccount).sort((a, b) => b.total - a.total),
          by_day:      Object.entries(byDay).sort(([a], [b]) => a.localeCompare(b)).map(([date, count]) => ({ date, count })),
        }, null, 2) }] };
      }
    );

    // ── get_channel_analytics ─────────────────────────────────────────────────
    server.tool(
      'get_channel_analytics',
      'Zeigt detaillierte Statistiken pro Kanal: Posts, Erfolgsrate, letzte Aktivität. Standard: letzte 90 Tage.',
      {
        start_date:     z.string().optional().describe('ISO-8601 Startdatum. Standard: -90 Tage.'),
        end_date:       z.string().optional().describe('ISO-8601 Enddatum. Standard: morgen.'),
        integration_id: z.string().optional().describe('Nur diesen Account anzeigen.'),
      },
      async ({ start_date, end_date, integration_id }) => {
        const now = new Date();
        const sd  = start_date || new Date(now.getTime() - 90 * 86400 * 1000).toISOString();
        const ed  = end_date   || new Date(now.getTime() +      86400 * 1000).toISOString();

        const allPosts = [];
        let page = 1;
        while (true) {
          const qs = new URLSearchParams({ page: String(page), limit: '100', startDate: sd, endDate: ed });
          const r  = await proxy('GET', `/public/v1/posts?${qs}`, {});
          const posts = r.body?.posts || [];
          allPosts.push(...posts);
          if (posts.length < 100 || page >= 10) break;
          page++;
        }

        const accounts = {};
        for (const post of allPosts) {
          const accId = post.integration?.id;
          if (!accId || (integration_id && accId !== integration_id)) continue;
          if (!accounts[accId]) {
            accounts[accId] = {
              id: accId, name: post.integration?.name || accId,
              platform: post.integration?.providerIdentifier || 'unknown',
              total: 0, published: 0, errors: 0, draft: 0, queue: 0,
              last_post: null, published_urls: [],
            };
          }
          const acc = accounts[accId], state = post.state || 'UNKNOWN';
          acc.total++;
          if      (state === 'PUBLISHED') { acc.published++; if (post.publishDate && (!acc.last_post || post.publishDate > acc.last_post)) acc.last_post = post.publishDate; if (post.releaseURL) acc.published_urls.push(post.releaseURL); }
          else if (state === 'ERROR')     acc.errors++;
          else if (state === 'DRAFT')     acc.draft++;
          else if (state === 'QUEUE')     acc.queue++;
        }

        return { content: [{ type: 'text', text: JSON.stringify({
          period: { start: sd, end: ed },
          channels: Object.values(accounts).sort((a, b) => b.total - a.total).map(acc => ({
            ...acc,
            success_rate:   acc.total > 0 ? Math.round(acc.published / acc.total * 100) + '%' : 'n/a',
            published_urls: acc.published_urls.slice(-5),
          })),
        }, null, 2) }] };
      }
    );

    return server;
  }

  app.all('/mcp', requireWrapperKey, async (req, res) => {
    const server    = createServer(req.apiKeyId || null);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => { transport.close(); server.close(); });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error('[mcp] Fehler:', err.message);
      if (!res.headersSent) res.status(500).json({ error: 'Interner MCP-Fehler' });
    }
  });

  console.log('[mcp] Endpoint bereit: /mcp');
}

module.exports = { mountMcpRoutes };
