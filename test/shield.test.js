import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { once } from 'node:events';
import { test } from 'node:test';
import { mkdtemp, writeFile, symlink, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createShield } from '../src/index.js';
import { createStaticHandler } from '../src/static.js';

async function fixture(t, options = {}, handler = (_req, res) => res.end('ok')) {
  const events = [];
  const shield = createShield(options, { log: event => events.push(event) });
  const server = createServer((req, res) => shield(req, res, () => handler(req, res)));
  server.listen(0, '127.0.0.1');
  t.after(() => new Promise(resolve => server.close(resolve)));
  await once(server, 'listening');
  const send = (path, method = 'GET', headers = {}) => new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port: server.address().port, path, method, headers }, res => {
      let body = '';
      res.setEncoding('utf8').on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end();
  });
  return { send, events };
}

test('normal traffic, security headers and feature controls', async t => {
  const { send } = await fixture(t, { inspect: false, securityHeaders: false, csrf: false });
  const result = await send('/?q=union+select', 'POST');
  assert.equal(result.status, 200);
  assert.equal(result.headers['x-content-type-options'], undefined);
});

test('rejects suspicious targets and logs only fixed fields', async t => {
  const { send, events } = await fixture(t);
  assert.equal((await send('/')).headers['x-content-type-options'], 'nosniff');
  for (const target of ['/x/%252e%252e/y', '/?q=%3Cscript%3E', '/?q=union+select', '/?file=https://example.org', '/?file=file:///tmp/example']) {
    assert.equal((await send(target)).status, 403);
  }
  assert.equal((await send('/%ZZ')).status, 400);
  assert.equal((await send('/?secret=private', 'GET', { 'User-Agent': 'nikto' })).status, 403);
  assert.equal(JSON.stringify(events).includes('private'), false);
  assert.deepEqual(Object.keys(events[0]), ['time', 'action', 'status', 'reason']);
});

test('enforces exact write origins, upload defaults and declared size', async t => {
  const { send } = await fixture(t, { allowedOrigins: ['https://example.org'], maxDeclaredBodyBytes: 2 });
  const origin = 'https://example.org';
  assert.equal((await send('/', 'POST')).status, 403);
  assert.equal((await send('/', 'POST', { Origin: `${origin}.invalid` })).status, 403);
  assert.equal((await send('/', 'POST', { Origin: origin })).status, 200);
  assert.equal((await send('/', 'POST', { Origin: origin, 'Content-Type': 'multipart/form-data' })).status, 415);
  assert.equal((await send('/', 'POST', { Origin: origin, 'Content-Length': '3' })).status, 413);
});

test('login and peer limits ignore spoofed forwarding headers', async t => {
  const { send } = await fixture(t, { csrf: false, loginPerMinute: 1, requestsPerMinute: 3 });
  assert.equal((await send('/login', 'POST')).status, 200);
  assert.equal((await send('/LOGIN/', 'POST', { 'X-Forwarded-For': '192.0.2.1' })).status, 429);
  assert.equal((await send('/')).status, 200);
  const denied = await send('/');
  assert.equal(denied.status, 429);
  assert.ok(Number(denied.headers['retry-after']) >= 1);
});

test('rejects invalid startup settings', () => {
  for (const options of [{ unknown: true }, { maxTrackedPeers: 0 }, { allowedOrigins: ['https://example.org/'] }]) {
    assert.throws(() => createShield(options), TypeError);
  }
});

test('website serves only allowed public files and supports HEAD', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'shield-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const root = join(dir, 'public');
  await mkdir(root);
  await writeFile(join(root, 'index.html'), 'hello');
  await writeFile(join(root, '.hidden.txt'), 'hidden');
  await writeFile(join(dir, 'private.txt'), 'private');
  await symlink(join(dir, 'private.txt'), join(root, 'escape.txt'));
  const { send } = await fixture(t, {}, await createStaticHandler(root));
  assert.equal((await send('/')).body, 'hello');
  const head = await send('/', 'HEAD');
  assert.equal(head.headers['content-length'], '5');
  assert.equal(head.body, '');
  for (const path of ['/.hidden.txt', '/escape.txt', '/config.js', '/missing.txt']) assert.equal((await send(path)).status, 404);
});
