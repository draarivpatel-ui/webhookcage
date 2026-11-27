// Safe header normalization. Plain objects are converted to Maps and never
// copied into a fresh object, so prototype keys cannot alter later lookups.
import { WebhookCageError } from './errors.mjs';

const MAX_HEADERS = 100;
const MAX_VALUE_LENGTH = 16384;
const HEADER_NAME_RE = /^[!#$%&'*+.^_`|~0-9a-z-]+$/;

function badHeader(reason) {
  throw new WebhookCageError('INVALID_HEADER', reason);
}

function checkName(name) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 128) badHeader('header name must be a nonempty ASCII token');
  const lower = name.toLowerCase();
  if (!HEADER_NAME_RE.test(lower)) badHeader('header name is not a valid HTTP token');
  return lower;
}

function checkValue(value) {
  if (typeof value !== 'string') badHeader('header value must be a string');
  if (value.length > MAX_VALUE_LENGTH) badHeader('header value is too long');
  if (/[\r\n\u0000]/.test(value)) badHeader('header value contains a forbidden control character');
  return value;
}

function addValue(output, name, value) {
  const lower = checkName(name);
  if (Array.isArray(value)) {
    if (value.length === 0 || value.length > 16) badHeader('header array must contain 1 to 16 values');
    for (const item of value) addValue(output, lower, item);
    return;
  }
  const text = checkValue(value);
  const existing = output.get(lower) || [];
  if (existing.length >= 16) badHeader('too many values for one header');
  existing.push(text);
  output.set(lower, existing);
}

export function normalizeHeaders(headers) {
  const output = new Map();
  if (headers === undefined || headers === null) throw new WebhookCageError('INVALID_ARGUMENT', 'headers must be an object, Map, or Headers-like value');
  if (output.size > MAX_HEADERS) badHeader('too many headers');

  if (headers instanceof Map) {
    for (const [name, value] of headers.entries()) {
      addValue(output, name, value);
      if (output.size > MAX_HEADERS) badHeader('too many headers');
    }
    return output;
  }

  if (typeof headers === 'object' && typeof headers.forEach === 'function' && typeof headers.get === 'function') {
    headers.forEach((value, name) => {
      addValue(output, name, value);
      if (output.size > MAX_HEADERS) badHeader('too many headers');
    });
    return output;
  }

  if (typeof headers === 'object' && !Array.isArray(headers)) {
    for (const name of Object.getOwnPropertyNames(headers)) {
      const descriptor = Object.getOwnPropertyDescriptor(headers, name);
      if (!descriptor || !descriptor.enumerable) continue;
      if (Object.hasOwn(descriptor, 'get') || Object.hasOwn(descriptor, 'set')) badHeader('accessor header properties are not allowed');
      addValue(output, name, descriptor.value);
      if (output.size > MAX_HEADERS) badHeader('too many headers');
    }
    return output;
  }

  throw new WebhookCageError('INVALID_ARGUMENT', 'headers must be an object, Map, or Headers-like value');
}

export function requireSingleHeader(headers, name) {
  const values = headers.get(name.toLowerCase());
  if (!values || values.length === 0) {
    throw new WebhookCageError('MISSING_HEADER', `required header ${name} is missing`, { header: name });
  }
  if (values.length !== 1) {
    throw new WebhookCageError('INVALID_HEADER', `required header ${name} must occur once`, { header: name });
  }
  return values[0];
}

export function optionalSingleHeader(headers, name) {
  const values = headers.get(name.toLowerCase());
  if (!values || values.length === 0) return null;
  if (values.length !== 1) {
    throw new WebhookCageError('INVALID_HEADER', `optional header ${name} must occur once`, { header: name });
  }
  return values[0];
}
