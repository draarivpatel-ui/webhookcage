import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import {
  WebhookCageError,
  signHmac,
  validateDeliveryUrl,
  verifyHmacSignatures,
} from '../src/index.mjs';

const propertyOptions = { seed: 20261127, numRuns: 120 };
const secretArbitrary = fc.stringMatching(/^[A-Za-z0-9][A-Za-z0-9._-]{7,39}$/);
const payloadUnit = fc.constantFrom(...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}[],: ".-_'.split(''));
const payloadArbitrary = fc.string({ unit: payloadUnit, minLength: 0, maxLength: 70 });
const algorithmArbitrary = fc.constantFrom('sha256', 'sha512');
const encodingArbitrary = fc.constantFrom('hex', 'base64');

function expectWebhookError(fn, code) {
  assert.throws(
    fn,
    (error) => error instanceof WebhookCageError && error.code === code,
  );
}

test('generated correct signatures verify across algorithms encodings and rotation order', () => {
  fc.assert(
    fc.property(secretArbitrary, secretArbitrary, payloadArbitrary, algorithmArbitrary, encodingArbitrary, (oldSecret, newSecret, payload, algorithm, encoding) => {
      fc.pre(oldSecret !== newSecret);
      const signature = signHmac(oldSecret, payload, { algorithm, encoding });
      const result = verifyHmacSignatures([signature], [newSecret, oldSecret], payload, { algorithm, encoding });
      assert.equal(result.secretIndex, 1);
      assert.equal(result.matchedSignatures.length, 1);
    }),
    propertyOptions,
  );
});

test('generated tampered payloads never verify with the original signature', () => {
  fc.assert(
    fc.property(secretArbitrary, payloadArbitrary, algorithmArbitrary, encodingArbitrary, (secret, payload, algorithm, encoding) => {
      const signature = signHmac(secret, payload, { algorithm, encoding });
      expectWebhookError(
        () => verifyHmacSignatures([signature], [secret], `${payload}-tampered`, { algorithm, encoding }),
        'SIGNATURE_MISMATCH',
      );
    }),
    propertyOptions,
  );
});

test('generated public webhook hostnames pass static delivery validation', () => {
  const label = fc.stringMatching(/^[a-z][a-z0-9]{0,12}$/);
  fc.assert(
    fc.property(label, (subdomain) => {
      const result = validateDeliveryUrl(`https://${subdomain}.example.com/webhook`);
      assert.equal(result.ok, true, result.detail);
      assert.equal(result.port, 443);
    }),
    propertyOptions,
  );
});

test('generated private and cloud-adjacent IP literals are rejected', () => {
  const octet = fc.integer({ min: 0, max: 255 });
  const privateIp = fc.oneof(
    fc.tuple(octet, octet, octet).map(([a, b, c]) => `10.${a}.${b}.${c}`),
    fc.tuple(octet, octet, octet).map(([a, b, c]) => `127.${a}.${b}.${c}`),
    fc.tuple(octet, octet).map(([b, c]) => `192.168.${b}.${c}`),
    fc.tuple(fc.integer({ min: 16, max: 31 }), octet, octet).map(([b, c, d]) => `172.${b}.${c}.${d}`),
    fc.tuple(octet, octet).map(([b, c]) => `169.254.${b}.${c}`),
  );
  fc.assert(
    fc.property(privateIp, (ip) => {
      const result = validateDeliveryUrl(`https://${ip}/webhook`);
      assert.equal(result.ok, false, ip);
      assert.equal(result.code, 'PRIVATE_IP');
    }),
    propertyOptions,
  );
});
