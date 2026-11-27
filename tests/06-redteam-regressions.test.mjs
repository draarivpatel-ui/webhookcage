import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  WebhookCageError,
  normalizeHeaders,
  parseIpv4,
  signHmac,
  validateDeliveryUrl,
  verifyWebhook,
} from '../src/index.mjs';

const FIXED_SECONDS = 1700000000;
const FIXED_NOW = FIXED_SECONDS * 1000;

function codeOf(fn) {
  try {
    fn();
  } catch (error) {
    assert.equal(error instanceof WebhookCageError, true);
    return error.code;
  }
  throw new Error('expected rejection');
}

test('leading zero IPv4 pieces containing 8 or 9 are invalid', () => {
  for (const host of ['1.2.3.08', '1.2.3.09', '010.0.0.08']) {
    assert.equal(parseIpv4(host), null);
  }
});

test('host policy exact entries do not include subdomains', () => {
  const hostPolicy = { allow: ['api.example.com'] };
  assert.equal(validateDeliveryUrl('https://api.example.com/', { hostPolicy }).ok, true);
  assert.equal(validateDeliveryUrl('https://evil.api.example.com/', { hostPolicy }).code, 'HOST_NOT_ALLOWED');
});

test('dot and star host policy forms keep distinct meanings', () => {
  assert.equal(validateDeliveryUrl('https://example.com/', { hostPolicy: { allow: ['.example.com'] } }).ok, true);
  assert.equal(validateDeliveryUrl('https://x.example.com/', { hostPolicy: { allow: ['.example.com'] } }).ok, true);
  assert.equal(validateDeliveryUrl('https://example.com/', { hostPolicy: { allow: ['*.example.com'] } }).code, 'HOST_NOT_ALLOWED');
  assert.equal(validateDeliveryUrl('https://x.example.com/', { hostPolicy: { allow: ['*.example.com'] } }).ok, true);
});

test('standard webhooks rejects a correctly signed empty message id', () => {
  const body = 'body';
  const secret = 'standard-secret';
  const payload = Buffer.concat([Buffer.from(`.${FIXED_SECONDS}.`), Buffer.from(body)]);
  const signature = signHmac(secret, payload, { algorithm: 'sha256', encoding: 'base64' });
  const headers = {
    'webhook-id': '',
    'webhook-timestamp': String(FIXED_SECONDS),
    'webhook-signature': `v1,${signature}`,
  };
  assert.equal(codeOf(() => verifyWebhook('standard-webhooks', body, headers, { secret, now: FIXED_NOW })), 'INVALID_HEADER');
});

test('header accessors are rejected without invocation', () => {
  let invoked = false;
  const headers = {};
  Object.defineProperty(headers, 'x-test', {
    enumerable: true,
    get() {
      invoked = true;
      return 'value';
    },
  });
  assert.equal(codeOf(() => normalizeHeaders(headers)), 'INVALID_HEADER');
  assert.equal(invoked, false);
});
