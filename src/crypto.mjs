// HMAC signing, strict encodings, secret rotation, and constant-time compare.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { WebhookCageError } from './errors.mjs';

const MAX_BODY_BYTES = 1024 * 1024;
const MAX_SECRETS = 32;
const ALGORITHMS = new Set(['sha256', 'sha512']);
const DIGEST_BYTES = Object.freeze({ sha256: 32, sha512: 64 });

export function normalizeBody(body) {
  if (typeof body === 'string') {
    const out = Buffer.from(body, 'utf8');
    if (out.length > MAX_BODY_BYTES) throw new WebhookCageError('INVALID_BODY', 'body exceeds the one megabyte limit');
    return out;
  }
  if (Buffer.isBuffer(body)) {
    if (body.length > MAX_BODY_BYTES) throw new WebhookCageError('INVALID_BODY', 'body exceeds the one megabyte limit');
    return Buffer.from(body);
  }
  if (body instanceof Uint8Array) {
    if (body.byteLength > MAX_BODY_BYTES) throw new WebhookCageError('INVALID_BODY', 'body exceeds the one megabyte limit');
    return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  }
  throw new WebhookCageError('INVALID_BODY', 'body must be a string, Buffer, or Uint8Array');
}

function normalizeOneSecret(secret) {
  if (typeof secret === 'string') {
    if (secret.length === 0 || secret.trim().length === 0) throw new WebhookCageError('INVALID_SECRET', 'secret must not be empty or whitespace');
    return Buffer.from(secret, 'utf8');
  }
  if (secret instanceof Uint8Array) {
    if (secret.byteLength === 0) throw new WebhookCageError('INVALID_SECRET', 'secret must not be empty');
    return Buffer.from(secret.buffer, secret.byteOffset, secret.byteLength);
  }
  throw new WebhookCageError('INVALID_SECRET', 'secret must be a nonempty string or byte array');
}

export function normalizeSecrets(secret, secrets) {
  if (secret !== undefined && secrets !== undefined) throw new WebhookCageError('INVALID_ARGUMENT', 'pass either secret or secrets, not both');
  const input = secrets !== undefined ? secrets : [secret];
  if (!Array.isArray(input)) throw new WebhookCageError('INVALID_ARGUMENT', 'secrets must be an array');
  if (input.length === 0 || input.length > MAX_SECRETS) throw new WebhookCageError('INVALID_SECRET', `secret rotation requires 1 to ${MAX_SECRETS} keys`);
  return Object.freeze(input.map(normalizeOneSecret));
}

export function normalizeAlgorithm(algorithm) {
  const normalized = typeof algorithm === 'string' ? algorithm.toLowerCase().replace(/^hmac-/, '') : '';
  if (!ALGORITHMS.has(normalized)) throw new WebhookCageError('INVALID_ARGUMENT', 'algorithm must be sha256 or sha512');
  return normalized;
}

export function constantTimeEqual(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)) throw new WebhookCageError('INVALID_ARGUMENT', 'constantTimeEqual compares byte arrays');
  const a = Buffer.from(left.buffer, left.byteOffset, left.byteLength);
  const b = Buffer.from(right.buffer, right.byteOffset, right.byteLength);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export function decodeSignature(text, encoding, algorithm) {
  if (typeof text !== 'string' || text.length === 0) throw new WebhookCageError('INVALID_SIGNATURE', 'signature must be a nonempty string');
  const alg = normalizeAlgorithm(algorithm);
  let decoded;
  if (encoding === 'hex') {
    const lower = text.toLowerCase();
    if (!/^[0-9a-f]+$/.test(lower) || lower.length % 2 !== 0) throw new WebhookCageError('INVALID_SIGNATURE', 'hex signature is not canonical');
    decoded = Buffer.from(lower, 'hex');
  } else if (encoding === 'base64') {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text) || text.length % 4 !== 0) throw new WebhookCageError('INVALID_SIGNATURE', 'base64 signature is not canonical');
    decoded = Buffer.from(text, 'base64');
    if (decoded.length === 0 || decoded.toString('base64') !== text) throw new WebhookCageError('INVALID_SIGNATURE', 'base64 signature is not canonical');
  } else {
    throw new WebhookCageError('INVALID_ARGUMENT', 'signature encoding must be hex or base64');
  }
  if (decoded.length !== DIGEST_BYTES[alg]) throw new WebhookCageError('INVALID_SIGNATURE', `signature length is not correct for ${alg}`);
  return decoded;
}

export function hmacDigest(secret, payload, algorithm) {
  const alg = normalizeAlgorithm(algorithm);
  const key = normalizeOneSecret(secret);
  const data = normalizeBody(payload);
  return createHmac(alg, key).update(data).digest();
}

export function signHmac(secret, payload, options) {
  const opts = options && typeof options === 'object' ? options : {};
  const algorithm = normalizeAlgorithm(Object.hasOwn(opts, 'algorithm') ? opts.algorithm : 'sha256');
  const encoding = Object.hasOwn(opts, 'encoding') ? opts.encoding : 'hex';
  const digest = hmacDigest(secret, payload, algorithm);
  if (encoding === 'hex') return digest.toString('hex');
  if (encoding === 'base64') return digest.toString('base64');
  throw new WebhookCageError('INVALID_ARGUMENT', 'signature encoding must be hex or base64');
}

export function verifyHmacSignatures(presentedSignatures, secrets, payload, options) {
  const opts = options && typeof options === 'object' ? options : {};
  const algorithm = normalizeAlgorithm(Object.hasOwn(opts, 'algorithm') ? opts.algorithm : 'sha256');
  const encoding = Object.hasOwn(opts, 'encoding') ? opts.encoding : 'hex';
  if (!Array.isArray(presentedSignatures) || presentedSignatures.length === 0 || presentedSignatures.length > 32) {
    throw new WebhookCageError('INVALID_SIGNATURE', 'expected 1 to 32 presented signatures');
  }
  const secretList = normalizeSecrets(undefined, secrets);
  const data = normalizeBody(payload);
  const presented = presentedSignatures.map((text) => decodeSignature(text, encoding, algorithm));
  const expected = secretList.map((secret) => createHmac(algorithm, secret).update(data).digest());
  const matches = [];
  for (let secretIndex = 0; secretIndex < expected.length; secretIndex += 1) {
    for (let signatureIndex = 0; signatureIndex < presented.length; signatureIndex += 1) {
      if (constantTimeEqual(expected[secretIndex], presented[signatureIndex])) {
        matches.push(Object.freeze({ secretIndex, signatureIndex, algorithm }));
      }
    }
  }
  if (matches.length === 0) throw new WebhookCageError('SIGNATURE_MISMATCH', 'no presented signature matches a configured secret');
  return Object.freeze({ secretIndex: matches[0].secretIndex, matchedSignatures: Object.freeze(matches) });
}

export function sha256Hex(text) {
  const data = text instanceof Uint8Array ? Buffer.from(text.buffer, text.byteOffset, text.byteLength) : String(text);
  return createHash('sha256').update(data).digest('hex');
}
