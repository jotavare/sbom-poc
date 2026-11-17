'use strict';

const assert = require('node:assert/strict');
const { after, before, test } = require('node:test');
const app = require('../app');

let server;
let base;

before(async () => {
  server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

test('GET /health', async () => {
  const res = await fetch(`${base}/health`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { status: 'ok' });
});

test('GET /calc evaluates user input (planted code injection)', async () => {
  const res = await fetch(`${base}/calc?expr=6*7`);
  assert.deepEqual(await res.json(), { result: '42' });
});

test('token round-trip', async () => {
  const { token } = await (await fetch(`${base}/token?user=alice`)).json();
  const body = await (await fetch(`${base}/whoami?token=${token}`)).json();
  assert.equal(body.user, 'alice');
});
