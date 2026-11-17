// Deliberately vulnerable Express API for the DevSecOps PoC.
//
// WARNING: this app contains intentional security flaws so that scanners have
// something to find. Never expose it to a network you don't control.
// Each planted flaw is tagged with `VULN:`.
'use strict';

const { exec } = require('node:child_process');
const axios = require('axios');
const express = require('express');
const jwt = require('jsonwebtoken');
const _ = require('lodash');

// VULN: hardcoded signing secret
const JWT_SECRET = 'super-secret-poc-key';

const app = express();
app.use(express.json());

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

app.get('/ping', (req, res) => {
  const host = req.query.host || '127.0.0.1';
  // VULN: OS command injection (user input in a shell string). Try ?host=127.0.0.1;id
  exec(`ping -c 1 ${host}`, { timeout: 5000 }, (err, stdout, stderr) => {
    res.json({ stdout, stderr, error: err ? err.message : null });
  });
});

app.get('/calc', (req, res) => {
  // VULN: code injection via eval of user input. Try ?expr=process.version
  // eslint-disable-next-line no-eval
  res.json({ result: String(eval(req.query.expr || '1+1')) });
});

app.post('/settings', (req, res) => {
  const defaults = { theme: 'light' };
  // VULN: prototype pollution (deep merge of untrusted JSON, old lodash)
  res.json(_.merge(defaults, req.body));
});

app.get('/fetch', async (req, res) => {
  // VULN: SSRF (server fetches any user-supplied URL)
  try {
    const resp = await axios.get(req.query.url || 'https://example.com', { timeout: 5000 });
    res.json({ status: resp.status, length: String(resp.data).length });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get('/token', (req, res) => {
  const user = req.query.user || 'guest';
  res.json({ token: jwt.sign({ user }, JWT_SECRET) });
});

app.get('/whoami', (req, res) => {
  try {
    // VULN: no `algorithms` allow-list when verifying JWTs
    res.json(jwt.verify(req.query.token || '', JWT_SECRET));
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

module.exports = app;

if (require.main === module) {
  const port = Number(process.env.PORT || 8080);
  app.listen(port, '0.0.0.0', () => console.log(`listening on :${port}`));
}
