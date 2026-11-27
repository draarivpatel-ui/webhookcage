// Structured, stable errors. No internal frames or credentials are exposed.
const MAX_INPUT_DISPLAY = 240;
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/g;

function safeString(value) {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return '';
  try {
    return String(value);
  } catch {
    return '<unprintable>';
  }
}

export function redactInput(value) {
  let text = safeString(value).replace(CONTROL_RE, '?');
  text = text.replace(/([a-z][a-z\d+.-]*:\/\/)([^/?#]*)@/i, '$1[redacted]@');
  if (text.length > MAX_INPUT_DISPLAY) text = `${text.slice(0, MAX_INPUT_DISPLAY)}...[truncated]`;
  return text;
}

export const ERROR_CODES = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  INVALID_BODY: 'INVALID_BODY',
  INVALID_SECRET: 'INVALID_SECRET',
  MISSING_HEADER: 'MISSING_HEADER',
  INVALID_HEADER: 'INVALID_HEADER',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  SIGNATURE_MISMATCH: 'SIGNATURE_MISMATCH',
  TIMESTAMP_MISSING: 'TIMESTAMP_MISSING',
  TIMESTAMP_INVALID: 'TIMESTAMP_INVALID',
  TIMESTAMP_OUT_OF_TOLERANCE: 'TIMESTAMP_OUT_OF_TOLERANCE',
  REPLAYED_DELIVERY: 'REPLAYED_DELIVERY',
  UNKNOWN_PROVIDER: 'UNKNOWN_PROVIDER',
  SSRF_REJECTED: 'SSRF_REJECTED',
});

export class WebhookCageError extends Error {
  constructor(code, reason, details) {
    const message = safeString(reason) || 'webhook rejected';
    super(message);
    this.name = 'WebhookCageError';
    this.code = safeString(code) || 'INVALID_ARGUMENT';
    this.reason = message;
    this.details = details && typeof details === 'object' ? Object.freeze({ ...details }) : undefined;
    this.stack = `WebhookCageError [${this.code}]: ${this.reason}`;
  }

  toJSON() {
    return { name: this.name, code: this.code, message: this.reason, details: this.details };
  }
}

export function fail(code, reason, input) {
  return { ok: false, code, detail: reason, input: redactInput(input) };
}

export function guardError(code, reason, input) {
  return new WebhookCageError(code, reason, { input: redactInput(input) });
}

export function invariant(condition, code, reason) {
  if (!condition) throw new WebhookCageError(code, reason);
}
