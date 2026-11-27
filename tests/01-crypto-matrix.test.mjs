import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  constantTimeEqual,
  decodeSignature,
  hmacDigest,
  normalizeAlgorithm,
  normalizeBody,
  normalizeSecrets,
  signHmac,
  verifyHmacSignatures,
} from '../src/index.mjs';
import { expectCode, rotationSecrets } from './helpers.mjs';

const payloads = [
  '',
  'a',
  '{}',
  '{"a":1}',
  '{"unicode":"café"}',
  'line one\nline two',
  'space suffix ',
  ' prefix space',
  '0',
  'false',
  'null',
  '[]',
  'x'.repeat(64),
  'x'.repeat(257),
  '符号',
  'a,b=c&d=e',
  '<script>alert(1)</script>',
  '\u0001control',
  'emoji-test',
  'final-payload',
];

const algorithms = ['sha256', 'sha512'];
const encodings = ['hex', 'base64'];

for (const algorithm of algorithms) {
  for (const encoding of encodings) {
    for (let index = 0; index < payloads.length; index += 1) {
      test(`valid ${algorithm} ${encoding} payload ${index}`, () => {
        const payload = payloads[index];
        const secret = `secret-${algorithm}-${encoding}-${index}`;
        const signature = signHmac(secret, payload, { algorithm, encoding });
        const result = verifyHmacSignatures([signature], [secret], payload, { algorithm, encoding });
        assert.equal(result.secretIndex, 0);
        assert.equal(result.matchedSignatures.length, 1);
      });

      test(`wrong payload fails ${algorithm} ${encoding} payload ${index}`, () => {
        const payload = payloads[index];
        const secret = `secret-${algorithm}-${encoding}-${index}`;
        const signature = signHmac(secret, payload, { algorithm, encoding });
        expectCode(() => verifyHmacSignatures([signature], [secret], `${payload}x`, { algorithm, encoding }), 'SIGNATURE_MISMATCH');
      });
    }
  }
}

for (const algorithm of algorithms) {
  for (let index = 0; index < 16; index += 1) {
    test(`rotation key ${index} verifies for ${algorithm}`, () => {
      const secrets = rotationSecrets(16);
      const encoding = algorithm === 'sha256' ? 'hex' : 'base64';
      const signature = signHmac(secrets[index], 'rotation-body', { algorithm, encoding });
      const result = verifyHmacSignatures([signature], secrets, 'rotation-body', { algorithm, encoding });
      assert.equal(result.secretIndex, index);
      assert.equal(result.matchedSignatures.length, 1);
    });
  }
}

const badHex = ['', '0', 'zz', '0x00', '00 11', '00\n', 'abcd'];
for (const value of badHex) {
  test(`strict hex rejects case ${JSON.stringify(value)}`, () => {
    expectCode(() => decodeSignature(value, 'hex', 'sha256'), 'INVALID_SIGNATURE');
  });
}

const badBase64 = ['', 'YQ', 'YQ===', 'YWI', 'YWJjZA=', 'YW Jj', 'YWJj\n', '_-__', 'Zh=='];
for (const value of badBase64) {
  test(`strict base64 rejects case ${JSON.stringify(value)}`, () => {
    expectCode(() => decodeSignature(value, 'base64', 'sha256'), 'INVALID_SIGNATURE');
  });
}

test('hex uppercase input is canonicalized before comparison', () => {
  const lower = signHmac('secret', 'body', { algorithm: 'sha256', encoding: 'hex' });
  const result = verifyHmacSignatures([lower.toUpperCase()], ['secret'], 'body', { algorithm: 'sha256', encoding: 'hex' });
  assert.equal(result.secretIndex, 0);
});

test('base64 correct digest verifies', () => {
  const signature = signHmac('secret', 'body', { algorithm: 'sha256', encoding: 'base64' });
  const result = verifyHmacSignatures([signature], ['secret'], 'body', { algorithm: 'sha256', encoding: 'base64' });
  assert.equal(result.secretIndex, 0);
});

test('sha256 digest length is enforced', () => {
  expectCode(() => decodeSignature('00'.repeat(31), 'hex', 'sha256'), 'INVALID_SIGNATURE');
  expectCode(() => decodeSignature('00'.repeat(33), 'hex', 'sha256'), 'INVALID_SIGNATURE');
});

test('sha512 digest length is enforced', () => {
  expectCode(() => decodeSignature('00'.repeat(63), 'hex', 'sha512'), 'INVALID_SIGNATURE');
  expectCode(() => decodeSignature('00'.repeat(65), 'hex', 'sha512'), 'INVALID_SIGNATURE');
});

test('normalizeBody accepts Buffer and Uint8Array views', () => {
  assert.equal(normalizeBody('abc').toString(), 'abc');
  assert.equal(normalizeBody(Buffer.from('abc')).toString(), 'abc');
  const view = new Uint8Array([97, 98, 99, 100]).subarray(1, 3);
  assert.equal(normalizeBody(view).toString(), 'bc');
});

test('normalizeBody rejects parsed objects and scalars', () => {
  for (const bad of [{ a: 1 }, [1], 1, true, null, undefined]) {
    expectCode(() => normalizeBody(bad), 'INVALID_BODY');
  }
});

test('normalizeSecrets rejects bad secret shapes', () => {
  expectCode(() => normalizeSecrets('', undefined), 'INVALID_SECRET');
  expectCode(() => normalizeSecrets('   ', undefined), 'INVALID_SECRET');
  expectCode(() => normalizeSecrets(undefined, []), 'INVALID_SECRET');
  expectCode(() => normalizeSecrets(undefined, 'secret'), 'INVALID_ARGUMENT');
  expectCode(() => normalizeSecrets('a', ['a']), 'INVALID_ARGUMENT');
});

test('normalizeSecrets accepts byte keys and rotation arrays', () => {
  assert.equal(normalizeSecrets(new Uint8Array([1, 2, 3]), undefined).length, 1);
  assert.equal(normalizeSecrets(undefined, ['one', 'two']).length, 2);
});

test('normalizeAlgorithm accepts exact and hmac-prefixed names', () => {
  assert.equal(normalizeAlgorithm('sha256'), 'sha256');
  assert.equal(normalizeAlgorithm('hmac-sha512'), 'sha512');
  expectCode(() => normalizeAlgorithm('sha1'), 'INVALID_ARGUMENT');
});

test('constantTimeEqual compares bytes', () => {
  const a = Buffer.from('0011aa', 'hex');
  assert.equal(constantTimeEqual(a, Buffer.from('0011aa', 'hex')), true);
  assert.equal(constantTimeEqual(a, Buffer.from('0011ab', 'hex')), false);
  assert.equal(constantTimeEqual(a, Buffer.from('0011aabb', 'hex')), false);
  expectCode(() => constantTimeEqual('a', 'a'), 'INVALID_ARGUMENT');
});

test('hmacDigest returns raw bytes of the right length', () => {
  assert.equal(hmacDigest('secret', 'body', 'sha256').length, 32);
  assert.equal(hmacDigest('secret', 'body', 'sha512').length, 64);
});

test('presented signature count is bounded', () => {
  expectCode(() => verifyHmacSignatures([], ['secret'], 'body', { algorithm: 'sha256', encoding: 'hex' }), 'INVALID_SIGNATURE');
  const many = Array.from({ length: 33 }, () => signHmac('secret', 'body', { algorithm: 'sha256', encoding: 'hex' }));
  expectCode(() => verifyHmacSignatures(many, ['secret'], 'body', { algorithm: 'sha256', encoding: 'hex' }), 'INVALID_SIGNATURE');
});
