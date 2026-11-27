// Provider-specific webhook signature schemes and timestamp windows.
import { WebhookCageError } from './errors.mjs';
import { normalizeHeaders, optionalSingleHeader, requireSingleHeader } from './headers.mjs';
import { normalizeBody, normalizeSecrets, sha256Hex, signHmac, verifyHmacSignatures } from './crypto.mjs';
import { assertTimestampFresh, deliveryKey } from './replay.mjs';

function own(source, key) {
  return source && typeof source === 'object' && Object.hasOwn(source, key) ? source[key] : undefined;
}

function secretsFrom(options) {
  const opts = options && typeof options === 'object' ? options : {};
  return normalizeSecrets(own(opts, 'secret'), own(opts, 'secrets'));
}

function rawSecretsFrom(options) {
  const opts = options && typeof options === 'object' ? options : {};
  const secret = own(opts, 'secret');
  const secrets = own(opts, 'secrets');
  if (secret !== undefined && secrets !== undefined) throw new WebhookCageError('INVALID_ARGUMENT', 'pass either secret or secrets, not both');
  const input = secrets !== undefined ? secrets : [secret];
  if (!Array.isArray(input)) throw new WebhookCageError('INVALID_ARGUMENT', 'secrets must be an array');
  return input;
}

function decodeStandardSecret(secret) {
  if (typeof secret !== 'string' || !secret.startsWith('whsec_')) return secret;
  const encoded = secret.slice(6);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 !== 0) {
    throw new WebhookCageError('INVALID_SECRET', 'Standard Webhooks whsec secret is not canonical base64');
  }
  const decoded = Buffer.from(encoded, 'base64');
  if (decoded.length === 0 || decoded.toString('base64') !== encoded) {
    throw new WebhookCageError('INVALID_SECRET', 'Standard Webhooks whsec secret is not canonical base64');
  }
  return decoded;
}

function timingFrom(options) {
  const opts = options && typeof options === 'object' ? options : {};
  const out = {};
  if (Object.hasOwn(opts, 'now')) out.now = opts.now;
  if (Object.hasOwn(opts, 'toleranceSeconds')) out.toleranceSeconds = opts.toleranceSeconds;
  if (Object.hasOwn(opts, 'futureSkewSeconds')) out.futureSkewSeconds = opts.futureSkewSeconds;
  return out;
}

function freezeResult(result) {
  return Object.freeze(result);
}

function textPayload(prefix, body) {
  return Buffer.concat([Buffer.from(prefix, 'utf8'), normalizeBody(body)]);
}

export function signGitHub(body, secret) {
  return `sha256=${signHmac(secret, body, { algorithm: 'sha256', encoding: 'hex' })}`;
}

export function verifyGitHub(body, headers, options) {
  const map = normalizeHeaders(headers);
  const secrets = secretsFrom(options);
  const header = requireSingleHeader(map, 'x-hub-signature-256');
  if (!header.startsWith('sha256=')) throw new WebhookCageError('INVALID_SIGNATURE', 'GitHub signature must use the sha256= prefix');
  const signature = header.slice('sha256='.length);
  const match = verifyHmacSignatures([signature], secrets, normalizeBody(body), { algorithm: 'sha256', encoding: 'hex' });
  const delivery = optionalSingleHeader(map, 'x-github-delivery');
  return freezeResult({
    valid: true,
    provider: 'github',
    algorithm: 'sha256',
    timestamp: null,
    deliveryId: delivery,
    replayKey: deliveryKey('github', delivery),
    secretIndex: match.secretIndex,
    matchedSignatures: match.matchedSignatures,
  });
}

export function signStripe(body, secret, timestamp) {
  const seconds = timestamp === undefined ? Math.floor(Date.now() / 1000) : timestamp;
  if (!Number.isSafeInteger(seconds) || seconds <= 0) throw new WebhookCageError('INVALID_ARGUMENT', 'Stripe timestamp must be positive integer seconds');
  const payload = textPayload(`${seconds}.`, body);
  const signature = signHmac(secret, payload, { algorithm: 'sha256', encoding: 'hex' });
  return `t=${seconds},v1=${signature}`;
}

export function parseStripeSignature(header) {
  if (typeof header !== 'string' || header.length === 0 || header.length > 4096) throw new WebhookCageError('INVALID_HEADER', 'Stripe-Signature header is missing or too long');
  const parts = header.split(',');
  if (parts.length > 100) throw new WebhookCageError('INVALID_HEADER', 'Stripe-Signature has too many fields');
  let timestamp = null;
  const signatures = [];
  for (const part of parts) {
    const equals = part.indexOf('=');
    if (equals < 1) throw new WebhookCageError('INVALID_HEADER', 'Stripe-Signature field is malformed');
    const key = part.slice(0, equals);
    const value = part.slice(equals + 1);
    if (key === 't') {
      if (timestamp !== null) throw new WebhookCageError('INVALID_HEADER', 'Stripe-Signature contains duplicate timestamps');
      timestamp = value;
    } else if (key === 'v1') {
      if (value.length === 0) throw new WebhookCageError('INVALID_SIGNATURE', 'Stripe v1 signature is empty');
      signatures.push(value);
    }
  }
  if (timestamp === null) throw new WebhookCageError('TIMESTAMP_MISSING', 'Stripe-Signature is missing t');
  if (signatures.length === 0) throw new WebhookCageError('INVALID_SIGNATURE', 'Stripe-Signature is missing v1');
  return Object.freeze({ timestamp, signatures });
}

export function verifyStripe(body, headers, options) {
  const map = normalizeHeaders(headers);
  const secrets = secretsFrom(options);
  const parsed = parseStripeSignature(requireSingleHeader(map, 'stripe-signature'));
  const freshness = assertTimestampFresh(parsed.timestamp, timingFrom(options));
  const payload = textPayload(`${parsed.timestamp}.`, body);
  const match = verifyHmacSignatures(parsed.signatures, secrets, payload, { algorithm: 'sha256', encoding: 'hex' });
  const replayId = `stripe:${parsed.timestamp}:${sha256Hex(normalizeBody(body))}`;
  return freezeResult({
    valid: true,
    provider: 'stripe',
    algorithm: 'sha256',
    timestamp: freshness.timestampMs,
    deliveryId: null,
    replayKey: deliveryKey('stripe', replayId),
    secretIndex: match.secretIndex,
    matchedSignatures: match.matchedSignatures,
  });
}

export function signSlack(body, secret, timestamp) {
  const seconds = timestamp === undefined ? Math.floor(Date.now() / 1000) : timestamp;
  if (!Number.isSafeInteger(seconds) || seconds <= 0) throw new WebhookCageError('INVALID_ARGUMENT', 'Slack timestamp must be positive integer seconds');
  const payload = textPayload(`v0:${seconds}:`, body);
  return `v0=${signHmac(secret, payload, { algorithm: 'sha256', encoding: 'hex' })}`;
}

export function verifySlack(body, headers, options) {
  const map = normalizeHeaders(headers);
  const secrets = secretsFrom(options);
  const timestamp = requireSingleHeader(map, 'x-slack-request-timestamp');
  const header = requireSingleHeader(map, 'x-slack-signature');
  if (!header.startsWith('v0=')) throw new WebhookCageError('INVALID_SIGNATURE', 'Slack signature must use the v0= prefix');
  const signature = header.slice(3);
  const freshness = assertTimestampFresh(timestamp, timingFrom(options));
  const payload = textPayload(`v0:${timestamp}:`, body);
  const match = verifyHmacSignatures([signature], secrets, payload, { algorithm: 'sha256', encoding: 'hex' });
  const replayId = `slack:${timestamp}:${sha256Hex(normalizeBody(body))}`;
  return freezeResult({
    valid: true,
    provider: 'slack',
    algorithm: 'sha256',
    timestamp: freshness.timestampMs,
    deliveryId: null,
    replayKey: deliveryKey('slack', replayId),
    secretIndex: match.secretIndex,
    matchedSignatures: match.matchedSignatures,
  });
}

export function signStandardWebhooks(body, secret, messageId, timestamp) {
  if (typeof messageId !== 'string' || messageId.length === 0 || messageId.length > 256) throw new WebhookCageError('INVALID_ARGUMENT', 'Standard Webhooks message id must be a bounded string');
  const seconds = timestamp === undefined ? Math.floor(Date.now() / 1000) : timestamp;
  if (!Number.isSafeInteger(seconds) || seconds <= 0) throw new WebhookCageError('INVALID_ARGUMENT', 'Standard Webhooks timestamp must be positive integer seconds');
  const payload = textPayload(`${messageId}.${seconds}.`, body);
  return {
    'webhook-id': messageId,
    'webhook-timestamp': String(seconds),
    'webhook-signature': `v1,${signHmac(decodeStandardSecret(secret), payload, { algorithm: 'sha256', encoding: 'base64' })}`,
  };
}

export function parseStandardWebhookSignatures(header) {
  if (typeof header !== 'string' || header.length === 0 || header.length > 4096) throw new WebhookCageError('INVALID_HEADER', 'webhook-signature header is missing or too long');
  const tokens = header.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0 || tokens.length > 32) throw new WebhookCageError('INVALID_HEADER', 'webhook-signature must contain 1 to 32 tokens');
  const signatures = [];
  for (const token of tokens) {
    const comma = token.indexOf(',');
    if (comma < 1) throw new WebhookCageError('INVALID_SIGNATURE', 'Standard Webhooks signature token is malformed');
    const version = token.slice(0, comma);
    const signature = token.slice(comma + 1);
    if (version !== 'v1') continue;
    if (signature.length === 0) throw new WebhookCageError('INVALID_SIGNATURE', 'Standard Webhooks v1 signature is empty');
    signatures.push(signature);
  }
  if (signatures.length === 0) throw new WebhookCageError('INVALID_SIGNATURE', 'no v1 Standard Webhooks signature is present');
  return Object.freeze(signatures.slice());
}

export function verifyStandardWebhooks(body, headers, options) {
  const map = normalizeHeaders(headers);
  const secrets = rawSecretsFrom(options).map(decodeStandardSecret);
  const messageId = requireSingleHeader(map, 'webhook-id');
  const timestamp = requireSingleHeader(map, 'webhook-timestamp');
  const signatures = parseStandardWebhookSignatures(requireSingleHeader(map, 'webhook-signature'));
  if (messageId.length === 0 || messageId.length > 256) throw new WebhookCageError('INVALID_HEADER', 'webhook-id must be a nonempty bounded string');
  const freshness = assertTimestampFresh(timestamp, timingFrom(options));
  const payload = textPayload(`${messageId}.${timestamp}.`, body);
  const match = verifyHmacSignatures(signatures, secrets, payload, { algorithm: 'sha256', encoding: 'base64' });
  return freezeResult({
    valid: true,
    provider: 'standard-webhooks',
    algorithm: 'sha256',
    timestamp: freshness.timestampMs,
    deliveryId: messageId,
    replayKey: deliveryKey('standard-webhooks', messageId),
    secretIndex: match.secretIndex,
    matchedSignatures: match.matchedSignatures,
  });
}

export const providerVerifiers = Object.freeze({
  github: verifyGitHub,
  stripe: verifyStripe,
  slack: verifySlack,
  'standard-webhooks': verifyStandardWebhooks,
});

export const providerSigners = Object.freeze({
  github: signGitHub,
  stripe: signStripe,
  slack: signSlack,
  'standard-webhooks': signStandardWebhooks,
});
