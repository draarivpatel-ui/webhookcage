import assert from 'node:assert/strict';
import { WebhookCageError } from '../src/index.mjs';

export const FIXED_SECONDS = 1700000000;
export const FIXED_NOW = FIXED_SECONDS * 1000;
export const SECRET = 'correct-test-secret';

export function expectCode(fn, code) {
  try {
    fn();
  } catch (error) {
    assert.ok(error instanceof WebhookCageError, `expected WebhookCageError, got ${error}`);
    assert.equal(error.code, code, error.stack);
    return error;
  }
  assert.fail(`expected ${code}`);
}

export function rotationSecrets(count) {
  return Array.from({ length: count }, (_, index) => `rotation-secret-${index}`);
}
