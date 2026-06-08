'use strict';
const { McpServer }                     = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { z }                             = require('zod');
const path                              = require('path');
const fs                                = require('fs');
const crypto                            = require('crypto');

const UPLOAD_DIR     = path.join(__dirname, 'public', 'uploads');
const PUBLIC_BASE    = 'https://postiz.clavastack.com/wrapper/uploads';
const ALLOWED_TYPES  = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/gif': '.gif', 'image/webp': '.webp' };

function mountMcpRoutes(app, { requireWrapperKey, proxyToPostiz, applyPolicy, db, apiPrefix }) {

  // Serve uploaded images publicly (no auth — Postiz needs to fetch them)
  app.use('/uploads', require('express').static(UPLOAD_DIR, { maxAge: '7d' }));

  function createServer() {
    const server = new McpServer({
      name: 'Postiz Wrapper',
      version: '1.0.0',
      instructions: 'Tools zum Planen und Verwalten von Social-Media-Posts via Postiz.',
    });

    async function proxy(method, urlPath, body) {
      const postizKey = db.getPostizApiKey();
      if (!postizKey) throw new Error('Postiz API key nicht konfiguriert.');
      return proxyToPostiz(method, apiPrefix + urlPath, body || {}, postizKey);
    }

    // ── list_integrations ───────────────────────────────────────────────────
    server.tool(
      'list_integrations',
      'Listet alle verbundenen Social-Media-Konten auf. Gibt ID, Name und Plattform zurück. Die integrationId wird beim Erstellen von Posts benötigt.',
      {},
      async () => {
        const r = await proxy('GET', '/public/v1/integrations', {});
        return { content: [{ type: 'text', text: JSON.stringify(r.body, null, 2) }] };
      }
    );

    // ── create_post ─────────────────────────────────────────────────────────
    server.tool(
      'create_post',
      'Erstellt oder plant einen Social-Media-Post. Policy-Regeln gelten: gesperrte Kanäle → 403, draft-Kanäle → Entwurfsmodus.',
      {
        integration_ids: z.array(z.string())
          .describe('Liste der Konto-IDs aus list_integrations. Pro Konto wird ein Post erstellt.'),
        content: z.string()
          .describe('Text des Posts.'),
        type: z.enum(['now', 'schedule', 'draft']).default('now')
          .describe('"now" = sofort posten, "schedule" = zum angegebenen Datum planen, "draft" = Entwurf speichern.'),
        date: z.string().optional()
          .describe('ISO-8601-Datum für geplante Posts, z.B. "2026-06-09T10:00:00.000Z". Nur bei type="schedule" erforderlich.'),
        short_link: z.boolean().default(false).optional()
          .describe('URLs im Post als Kurzlink darstellen.'),
        tags: z.array(z.string()).default([]).optional()
          .describe('Optionale Tags/Labels für den Post.'),
        image_urls: z.array(z.string()).optional()
          .describe('Öffentlich erreichbare Bild-URLs. Lokale Dateien zuerst mit upload_image hochladen.'),
      },
      async ({ integration_ids, content, type = 'now', date, short_link = false, tags = [], image_urls }, extra) => {
        const keyId = extra?._req?.apiKeyId || null;

        const value = [{
          content,
          image: (image_urls && image_urls.length > 0)
            ? image_urls.map(url => ({ url, path: url }))
            : [],
        }];

        const body = {
          type,
          shortLink: short_link,
          tags,
          ...(date ? { date } : {}),
          posts: integration_ids.map(id => ({
            integration: { id },
            value,
            settings: { who_can_reply_post: 'everyone' },
          })),
        };

        const result = applyPolicy(body, '/public/v1/posts', keyId);
        if (result.blocked) {
          return {
            isError: true,
            content: [{ type: 'text', text: JSON.stringify({
              error: 'Post durch Policy blockiert',
              blockedChannels: result.blockedChannels,
            }, null, 2) }],
          };
        }

        const r = await proxy('POST', '/public/v1/posts', result.body);
        return { content: [{ type: 'text', text: JSON.stringify(r.body, null, 2) }] };
      }
    );

    // ── list_posts ──────────────────────────────────────────────────────────
    server.tool(
      'list_posts',
      'Listet geplante und veröffentlichte Posts im angegebenen Zeitraum auf. Standard: heute bis +60 Tage.',
      {
        page: z.number().int().min(1).default(1).optional()
          .describe('Seitennummer (Standard: 1)'),
        limit: z.number().int().min(1).max(50).default(20).optional()
          .describe('Posts pro Seite (Standard: 20, max 50)'),
        start_date: z.string().optional()
          .describe('ISO-8601 Startdatum, z.B. "2026-06-01T00:00:00.000Z". Standard: heute 00:00 UTC.'),
        end_date: z.string().optional()
          .describe('ISO-8601 Enddatum, z.B. "2026-07-01T00:00:00.000Z". Standard: heute +60 Tage.'),
      },
      async ({ page = 1, limit = 20, start_date, end_date }) => {
        const now = new Date();
        // Default startDate: start of today UTC
        const sd = start_date || new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())).toISOString();
        // Default endDate: +60 days
        const ed = end_date || new Date(now.getTime() + 60 * 24 * 60 * 60 * 1000).toISOString();

        const qs = new URLSearchParams({ page: String(page), limit: String(limit), startDate: sd, endDate: ed });
        const r  = await proxy('GET', `/public/v1/posts?${qs}`, {});
        return { content: [{ type: 'text', text: JSON.stringify(r.body, null, 2) }] };
      }
    );

    // ── get_post ────────────────────────────────────────────────────────────
    server.tool(
      'get_post',
      'Ruft Details zu einem einzelnen Post ab.',
      { post_id: z.string().describe('Die Post-ID') },
      async ({ post_id }) => {
        const r = await proxy('GET', `/public/v1/posts/${encodeURIComponent(post_id)}`, {});
        return { content: [{ type: 'text', text: JSON.stringify(r.body, null, 2) }] };
      }
    );

    // ── delete_post ─────────────────────────────────────────────────────────
    server.tool(
      'delete_post',
      'Löscht einen geplanten Post.',
      { post_id: z.string().describe('Die Post-ID') },
      async ({ post_id }) => {
        const r = await proxy('DELETE', `/public/v1/posts/${encodeURIComponent(post_id)}`, {});
        return { content: [{ type: 'text', text: JSON.stringify(r.body, null, 2) }] };
      }
    );

    // ── upload_image ────────────────────────────────────────────────────────
    server.tool(
      'upload_image',
      [
        'Lädt ein Bild auf den Wrapper-Server hoch und gibt eine öffentlich erreichbare URL zurück.',
        'Diese URL kann direkt als image_urls-Eintrag in create_post verwendet werden — Postiz kann sie fetchen.',
        'Akzeptiert Base64-codierte Bilddaten (ohne Data-URL-Prefix wie "data:image/png;base64,").',
        'Erlaubte Formate: PNG, JPEG, GIF, WebP.',
      ].join(' '),
      {
        image_data: z.string()
          .describe('Base64-codiertes Bild. Ohne Prefix — also nur der reine Base64-String.'),
        filename: z.string().optional()
          .describe('Gewünschter Dateiname (optional). Die Endung bestimmt das Format, z.B. "banner.png".'),
        mime_type: z.string().default('image/png').optional()
          .describe('MIME-Typ: "image/png", "image/jpeg", "image/gif" oder "image/webp". Standard: image/png.'),
      },
      async ({ image_data, filename, mime_type = 'image/png' }) => {
        const ext = ALLOWED_TYPES[mime_type];
        if (!ext) {
          return {
            isError: true,
            content: [{ type: 'text', text: `Nicht unterstützter MIME-Typ: ${mime_type}. Erlaubt: ${Object.keys(ALLOWED_TYPES).join(', ')}` }],
          };
        }

        // Strip optional Data-URL prefix if the client included it
        const base64 = image_data.replace(/^data:[^;]+;base64,/, '');

        let buf;
        try {
          buf = Buffer.from(base64, 'base64');
        } catch {
          return { isError: true, content: [{ type: 'text', text: 'Ungültige Base64-Daten.' }] };
        }

        if (buf.length === 0) {
          return { isError: true, content: [{ type: 'text', text: 'Bild ist leer (0 Bytes).' }] };
        }
        if (buf.length > 20 * 1024 * 1024) {
          return { isError: true, content: [{ type: 'text', text: 'Bild zu groß (max. 20 MB).' }] };
        }

        // Generate unique filename
        const uid  = crypto.randomBytes(16).toString('hex');
        const name = filename
          ? path.basename(filename).replace(/[^a-zA-Z0-9._-]/g, '_').replace(/\.[^.]+$/, '') + '_' + uid.slice(0, 8) + ext
          : uid + ext;

        const dest = path.join(UPLOAD_DIR, name);
        try {
          fs.mkdirSync(UPLOAD_DIR, { recursive: true });
          fs.writeFileSync(dest, buf);
        } catch (err) {
          return { isError: true, content: [{ type: 'text', text: `Fehler beim Speichern: ${err.message}` }] };
        }

        const publicUrl = `${PUBLIC_BASE}/${name}`;
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ok: true,
              url: publicUrl,
              filename: name,
              size_bytes: buf.length,
              mime_type,
              hint: 'Diese URL direkt als image_urls-Eintrag in create_post verwenden.',
            }, null, 2),
          }],
        };
      }
    );

    return server;
  }

  app.all('/mcp', requireWrapperKey, async (req, res) => {
    const server    = createServer();
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
