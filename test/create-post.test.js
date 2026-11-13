'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');

const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'mcp-server.js'), 'utf8');
const wrapperUploads = 'https://postiz.clavastack.com/wrapper/uploads';
const accountList = [
  { id: 'ig-facebook', identifier: 'instagram', name: 'Instagram' },
  { id: 'ig-direct', identifier: 'instagram-standalone', name: 'Instagram direct' },
  { id: 'x-account', identifier: 'x', name: 'X' },
  { id: 'linkedin-account', identifier: 'linkedin', name: 'LinkedIn' },
];

// Exercise the actual MCP tool and schema. All Postiz and media traffic is mocked.
async function setup(t, options = {}) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  serverTransport.handleRequest = async () => {};
  const calls = [];
  const uploads = [];
  const db = { getPostizApiKey: () => 'test-key' };
  const network = {
    get() { throw new Error('Unexpected remote download in test'); },
    request(requestOptions, callback) {
      const request = new EventEmitter();
      request.write = () => {};
      request.end = () => {
        uploads.push(requestOptions);
        const response = new EventEmitter();
        callback(response);
        queueMicrotask(() => {
          response.emit('data', JSON.stringify({
            id: `upload-${uploads.length}`,
            path: `https://postiz.test/media/${uploads.length}.png`,
          }));
          response.emit('end');
        });
      };
      return request;
    },
  };
  const testRequire = (name) => {
    if (name === './db') return db;
    if (name === 'http' || name === 'https') return network;
    if (name === 'express') return { static: () => () => {} };
    if (name === '@modelcontextprotocol/sdk/server/streamableHttp.js') {
      return { StreamableHTTPServerTransport: class { constructor() { return serverTransport; } } };
    }
    return require(name);
  };
  const sandbox = {
    module: { exports: {} }, require: testRequire, __dirname: root,
    Buffer, URL, URLSearchParams, process: { env: {} },
    console: { log() {}, error() {} },
  };
  vm.runInNewContext(source, sandbox, { filename: 'mcp-server.js' });

  const app = {
    use() {},
    all(_path, _auth, handler) { this.handler = handler; },
  };
  sandbox.module.exports.mountMcpRoutes(app, {
    db,
    apiPrefix: '/api',
    requireWrapperKey() {},
    applyPolicy: options.applyPolicy || ((body) => ({ blocked: false, body })),
    async proxyToPostiz(method, url, body, key) {
      assert.equal(key, 'test-key');
      calls.push({ method, url, body: JSON.parse(JSON.stringify(body)) });
      if (method === 'GET' && url === '/api/public/v1/integrations') {
        if (options.lookupError) throw new Error('simulated lookup failure');
        return Object.hasOwn(options, 'lookupResponse')
          ? options.lookupResponse
          : { status: 200, body: accountList };
      }
      if (method === 'POST' && url === '/api/public/v1/posts') {
        return { status: 200, body: body.posts.map(post => ({ postId: 'post-id', integration: post.integration.id })) };
      }
      throw new Error(`Unexpected Postiz request: ${method} ${url}`);
    },
  });
  await app.handler({ apiKeyId: 'test-wrapper-key', body: {} }, { on() {} });
  const client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: {} });
  await client.connect(clientTransport);
  t.after(() => client.close());
  return {
    calls, uploads, client,
    create: (args) => client.callTool({ name: 'create_post', arguments: args }),
    posted: () => calls.find(call => call.method === 'POST')?.body,
  };
}

test('defaults to an Instagram post and preserves four images across both media inputs', async (t) => {
  const h = await setup(t);
  const result = await h.create({
    integration_ids: ['ig-facebook', 'ig-direct', 'x-account'],
    content: 'Carousel',
    type: 'draft',
    media_paths: ['data:image/png;base64,YQ==', 'data:image/png;base64,Yg=='],
    image_urls: [`${wrapperUploads}/three.png`, `${wrapperUploads}/four.png`],
  });
  assert.notEqual(result.isError, true);
  assert.equal(h.uploads.length, 2);
  const body = h.posted();
  assert.equal(body.type, 'draft');
  assert.deepEqual(body.posts.map(post => post.settings), [
    { __type: 'instagram', post_type: 'post' },
    { __type: 'instagram-standalone', post_type: 'post' },
    { who_can_reply_post: 'everyone' },
  ]);
  for (const post of body.posts) {
    assert.equal(post.value.length, 1);
    assert.equal(post.value[0].content, 'Carousel');
    assert.deepEqual(post.value[0].image.map(image => image.url), [
      'https://postiz.test/media/1.png', 'https://postiz.test/media/2.png',
      `${wrapperUploads}/three.png`, `${wrapperUploads}/four.png`,
    ]);
    for (const image of post.value[0].image) {
      assert.ok(image.id);
      assert.equal(image.path, image.url);
    }
  }
});

test('sends explicit Instagram post and story types for both provider variants', async (t) => {
  for (const postType of ['post', 'story']) {
    const h = await setup(t);
    const result = await h.create({
      integration_ids: ['ig-facebook', 'ig-direct'],
      content: 'Example', type: 'draft', post_type: postType,
      image_urls: [`${wrapperUploads}/one.png`],
    });
    assert.notEqual(result.isError, true);
    assert.deepEqual(h.posted().posts.map(post => post.settings), [
      { __type: 'instagram', post_type: postType },
      { __type: 'instagram-standalone', post_type: postType },
    ]);
  }
});

test('keeps the settings for non-Instagram platforms unchanged', async (t) => {
  const h = await setup(t);
  await h.create({ integration_ids: ['x-account', 'linkedin-account'], content: 'Example', type: 'draft', post_type: 'story' });
  assert.deepEqual(h.posted().posts.map(post => post.settings), [
    { who_can_reply_post: 'everyone' }, { who_can_reply_post: 'everyone' },
  ]);
});

test('rejects an invalid post_type before looking up integrations', async (t) => {
  const h = await setup(t);
  const result = await h.create({ integration_ids: ['ig-facebook'], content: 'Example', type: 'draft', post_type: 'reel' });
  assert.equal(result.isError, true);
  assert.equal(h.calls.length, 0);
});

test('does not upload or create a post when integration lookup fails or is malformed', async (t) => {
  const cases = [
    { lookupError: true },
    { lookupResponse: null },
    { lookupResponse: { body: accountList } },
    { lookupResponse: { status: 503, body: accountList } },
    { lookupResponse: { status: 200, body: {} } },
    { lookupResponse: { status: 200, body: [{ id: 'ig-facebook' }] } },
    { lookupResponse: { status: 200, body: [] } },
  ];
  for (const options of cases) {
    const h = await setup(t, options);
    const result = await h.create({
      integration_ids: ['ig-facebook'], content: 'Example', type: 'draft',
      media_paths: ['data:image/png;base64,YQ=='],
    });
    assert.equal(result.isError, true);
    assert.equal(h.uploads.length, 0);
    assert.equal(h.posted(), undefined);
  }
});

test('keeps policy blocking and draft conversion in effect', async (t) => {
  const blocked = await setup(t, { applyPolicy: () => ({ blocked: true, blockedChannels: ['ig-facebook'] }) });
  const result = await blocked.create({ integration_ids: ['ig-facebook'], content: 'Example', type: 'now' });
  assert.equal(result.isError, true);
  assert.equal(blocked.posted(), undefined);

  const draft = await setup(t, { applyPolicy: (body) => ({ blocked: false, body: { ...body, type: 'draft' } }) });
  await draft.create({ integration_ids: ['ig-facebook'], content: 'Example', type: 'now' });
  assert.equal(draft.posted().type, 'draft');
  assert.deepEqual(draft.posted().posts[0].settings, { __type: 'instagram', post_type: 'post' });
});
