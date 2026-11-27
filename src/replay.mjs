// Timestamp windows, clock-skew guards, replay keys, and an in-memory store.
import { WebhookCageError } from './errors.mjs';
import { sha256Hex } from './crypto.mjs';

const MAX_TIMESTAMP_DIGITS = 13;

export function resolveNow(now) {
  const value = typeof now === 'function' ? now() : now === undefined ? Date.now() : now;
  if (!Number.isFinite(value) || value < 0 || value > 8.64e15) throw new WebhookCageError('INVALID_ARGUMENT', 'now must be a finite millisecond timestamp');
  return value;
}

export function parseTimestampSeconds(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value) || value.length > MAX_TIMESTAMP_DIGITS) {
    throw new WebhookCageError('TIMESTAMP_INVALID', 'timestamp must be a canonical positive integer of seconds');
  }
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds) || seconds <= 0 || seconds > 4102444800) {
    throw new WebhookCageError('TIMESTAMP_INVALID', 'timestamp is outside the supported range');
  }
  return seconds * 1000;
}

export function assertTimestampFresh(timestampText, options) {
  const opts = options && typeof options === 'object' ? options : {};
  const timestampMs = parseTimestampSeconds(timestampText);
  const nowMs = resolveNow(Object.hasOwn(opts, 'now') ? opts.now : undefined);
  const toleranceSeconds = Object.hasOwn(opts, 'toleranceSeconds') ? opts.toleranceSeconds : 300;
  const futureSkewSeconds = Object.hasOwn(opts, 'futureSkewSeconds') ? opts.futureSkewSeconds : 60;
  if (!Number.isFinite(toleranceSeconds) || toleranceSeconds < 0 || toleranceSeconds > 86400) throw new WebhookCageError('INVALID_ARGUMENT', 'toleranceSeconds must be between 0 and 86400');
  if (!Number.isFinite(futureSkewSeconds) || futureSkewSeconds < 0 || futureSkewSeconds > 86400) throw new WebhookCageError('INVALID_ARGUMENT', 'futureSkewSeconds must be between 0 and 86400');
  const ageMs = nowMs - timestampMs;
  if (ageMs > toleranceSeconds * 1000) {
    throw new WebhookCageError('TIMESTAMP_OUT_OF_TOLERANCE', 'webhook timestamp is older than the replay window');
  }
  if (ageMs < -futureSkewSeconds * 1000) {
    throw new WebhookCageError('TIMESTAMP_OUT_OF_TOLERANCE', 'webhook timestamp is beyond the permitted clock skew');
  }
  return Object.freeze({ timestampMs, ageMs, toleranceSeconds, futureSkewSeconds });
}

export function deliveryKey(provider, identifier) {
  if (typeof identifier !== 'string' || identifier.length === 0 || identifier.length > 512) return null;
  return `${provider}:${sha256Hex(identifier)}`;
}

export class MemoryReplayStore {
  constructor(options) {
    const opts = options && typeof options === 'object' ? options : {};
    this.ttlMs = Object.hasOwn(opts, 'ttlMs') ? opts.ttlMs : 300000;
    this.maxEntries = Object.hasOwn(opts, 'maxEntries') ? opts.maxEntries : 10000;
    this.now = Object.hasOwn(opts, 'now') ? opts.now : Date.now;
    if (!Number.isFinite(this.ttlMs) || this.ttlMs < 1000) throw new WebhookCageError('INVALID_ARGUMENT', 'ttlMs must be at least 1000');
    if (!Number.isInteger(this.maxEntries) || this.maxEntries < 1) throw new WebhookCageError('INVALID_ARGUMENT', 'maxEntries must be a positive integer');
    this.entries = new Map();
  }

  prune() {
    const nowMs = resolveNow(this.now);
    for (const [key, expires] of this.entries.entries()) {
      if (expires <= nowMs) this.entries.delete(key);
    }
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
  }

  checkAndRecord(key) {
    if (typeof key !== 'string' || key.length === 0 || key.length > 600) throw new WebhookCageError('INVALID_ARGUMENT', 'replay key must be a nonempty bounded string');
    this.prune();
    if (this.entries.has(key)) return false;
    this.entries.set(key, resolveNow(this.now) + this.ttlMs);
    return true;
  }

  size() {
    this.prune();
    return this.entries.size;
  }
}

export function recordDelivery(store, key) {
  if (!store || key === null) return;
  if (typeof store.checkAndRecord !== 'function') throw new WebhookCageError('INVALID_ARGUMENT', 'replayStore must expose checkAndRecord');
  if (!store.checkAndRecord(key)) throw new WebhookCageError('REPLAYED_DELIVERY', 'webhook delivery was already accepted');
}
