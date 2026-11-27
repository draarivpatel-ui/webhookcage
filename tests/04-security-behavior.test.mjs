import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MemoryReplayStore,
  constantTimeEqual,
  createVerifier,
  normalizeHeaders,
  redactInput,
  signGitHub,
  validateDeliveryUrl,
  verifyWebhook,
} from '../src/index.mjs';
import { FIXED_NOW, expectCode } from './helpers.mjs';

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('prototype pollution cannot inject a secret', () => {
  const body = 'pollution-body';
  const signature = signGitHub(body, 'polluted-prototype-secret');
  Object.prototype.secret = 'polluted-prototype-secret';
  try {
    expectCode(() => verifyWebhook('github', body, { 'x-hub-signature-256': signature }, {}), 'INVALID_SECRET');
  } finally {
    delete Object.prototype.secret;
  }
});

test('prototype pollution cannot inject key rotation', () => {
  const body = 'pollution-body';
  const signature = signGitHub(body, 'polluted-prototype-secret');
  Object.prototype.secrets = ['polluted-prototype-secret'];
  try {
    expectCode(() => verifyWebhook('github', body, { 'x-hub-signature-256': signature }, {}), 'INVALID_SECRET');
  } finally {
    delete Object.prototype.secrets;
  }
});

test('prototype pollution cannot inject a replay store', () => {
  const body = 'pollution-body';
  const secret = 'real-secret';
  const signature = signGitHub(body, secret);
  Object.prototype.replayStore = { checkAndRecord: () => true };
  try {
    const result = verifyWebhook('github', body, { 'x-hub-signature-256': signature }, { secret });
    assert.equal(result.replayProtected, false);
  } finally {
    delete Object.prototype.replayStore;
  }
});

test('prototype pollution cannot relax outbound port policy', () => {
  Object.prototype.allowedPorts = 'any';
  try {
    const result = validateDeliveryUrl('https://example.com:8443/');
    assert.equal(result.code, 'PORT_FORBIDDEN');
  } finally {
    delete Object.prototype.allowedPorts;
  }
});

test('prototype pollution cannot relax outbound host policy', () => {
  Object.prototype.hostPolicy = { allow: ['.example.com'] };
  try {
    assert.equal(validateDeliveryUrl('https://evil.example.net/').ok, true);
    assert.equal(validateDeliveryUrl('https://localhost/').ok, false);
  } finally {
    delete Object.prototype.hostPolicy;
  }
});

test('header normalization folds ASCII case without object keys', () => {
  const headers = normalizeHeaders({ 'X-Hub-Signature-256': 'sha256=abc' });
  assert.equal(headers instanceof Map, true);
  assert.equal(headers.get('x-hub-signature-256')[0], 'sha256=abc');
});

test('header normalization accepts immutable header-like objects', () => {
  const headers = normalizeHeaders(new Headers({ 'x-test': 'yes' }));
  assert.equal(headers.get('x-test')[0], 'yes');
});

test('header normalization rejects invalid names and nonstring values', () => {
  expectCode(() => normalizeHeaders({ 'bad name': 'x' }), 'INVALID_HEADER');
  expectCode(() => normalizeHeaders({ 'x-test': 1 }), 'INVALID_HEADER');
  expectCode(() => normalizeHeaders(null), 'INVALID_ARGUMENT');
});

test('header arrays preserve multiplicity for duplicate detection', () => {
  const headers = normalizeHeaders({ 'x-test': ['one', 'two'] });
  assert.deepEqual(headers.get('x-test'), ['one', 'two']);
});

test('redactInput limits and hides untrusted strings', () => {
  const text = `prefix-${'x'.repeat(500)}`;
  const redacted = redactInput(text);
  assert.equal(redacted.includes('x'.repeat(500)), false);
  assert.equal(redacted.length <= 260, true);
});

test('constantTimeEqual rejects polluted prototype byte shapes', () => {
  Object.prototype.length = 32;
  try {
    expectCode(() => constantTimeEqual('abc', 'abc'), 'INVALID_ARGUMENT');
  } finally {
    delete Object.prototype.length;
  }
});

test('MemoryReplayStore expires keys after the TTL', () => {
  let now = 1000;
  const store = new MemoryReplayStore({ ttlMs: 1000, now: () => now });
  assert.equal(store.checkAndRecord('key'), true);
  assert.equal(store.checkAndRecord('key'), false);
  now = 2001;
  assert.equal(store.checkAndRecord('key'), true);
});

test('MemoryReplayStore enforces its bound', () => {
  const store = new MemoryReplayStore({ maxEntries: 2, now: () => FIXED_NOW });
  store.checkAndRecord('one');
  store.checkAndRecord('two');
  store.checkAndRecord('three');
  assert.equal(store.size(), 2);
});

test('MemoryReplayStore rejects malformed configuration', () => {
  expectCode(() => new MemoryReplayStore({ ttlMs: 0 }), 'INVALID_ARGUMENT');
  expectCode(() => new MemoryReplayStore({ maxEntries: 0 }), 'INVALID_ARGUMENT');
});

test('unknown provider fails closed', () => {
  expectCode(() => verifyWebhook('unknown', 'body', {}, { secret: 'secret' }), 'UNKNOWN_PROVIDER');
});

test('provider verifier objects are frozen', () => {
  const verifier = createVerifier('github', { secret: 'secret' });
  assert.equal(Object.isFrozen(verifier), true);
  assert.equal(typeof verifier.verify, 'function');
});

test('verifier merges own overrides without mutating defaults', () => {
  const defaults = { secret: 'old-secret', now: FIXED_NOW };
  const verifier = createVerifier('github', defaults);
  const body = 'override-body';
  const signature = signGitHub(body, 'new-secret');
  const result = verifier.verify(body, { 'x-hub-signature-256': signature }, { secret: 'new-secret' });
  assert.equal(result.valid, true);
  assert.equal(defaults.secret, 'old-secret');
});

const cjsModules = ['errors', 'ip', 'ssrf', 'headers', 'crypto', 'replay', 'providers', 'verify', 'index'];
for (const name of cjsModules) {
  test(`CommonJS module ${name} loads`, () => {
    const loaded = require(`../cjs/${name}.cjs`);
    assert.equal(typeof loaded, 'object');
  });
}

test('CommonJS and ESM export the same surface', async () => {
  const esm = await import('../src/index.mjs');
  const cjs = require('../cjs/index.cjs');
  assert.deepEqual(Object.keys(cjs).sort(), Object.keys(esm).sort());
});

test('CommonJS HMAC parity', () => {
  const cjs = require('../cjs/index.cjs');
  const signature = cjs.signGitHub('body', 'secret');
  const result = cjs.verifyWebhook('github', 'body', { 'x-hub-signature-256': signature }, { secret: 'secret' });
  assert.equal(result.valid, true);
});

test('CommonJS SSRF parity', () => {
  const cjs = require('../cjs/index.cjs');
  assert.equal(cjs.validateDeliveryUrl('https://example.com/').ok, true);
  assert.equal(cjs.validateDeliveryUrl('https://127.0.0.1/').code, 'PRIVATE_IP');
});

test('generated CommonJS is LF normalized', () => {
  for (const name of cjsModules) {
    const text = fs.readFileSync(path.join(root, 'cjs', `${name}.cjs`), 'utf8');
    assert.equal(text.includes('\r'), false, `${name}.cjs contains CR`);
  }
});
