// Cross-platform CLI smoke test. Uses spawnSync with shell disabled.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(root, 'bin', 'webhookcage.mjs');

function run(args, expectedStatus, env) {
  const result = spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
    env: { ...process.env, ...(env || {}) },
  });
  assert.equal(result.error, undefined, result.error && result.error.message);
  assert.equal(result.status, expectedStatus, `webhookcage ${args.join(' ')} exited ${result.status}: ${result.stderr || result.stdout}`);
  assert.equal(result.stderr.includes('/' + 'Users/'), false);
  return result.stdout;
}

assert.match(run(['--version'], 0), /^webhookcage 1\.0\.0\n?$/);
const signed = JSON.parse(run(['sign', 'github', '--secret', 'smoke-secret', '--body', 'smoke-body'], 0));
assert.equal(typeof signed.signature, 'string');
assert.ok(signed.signature.startsWith('sha256='));
const verified = JSON.parse(run([
  'verify', 'github', '--secret', 'smoke-secret', '--body', 'smoke-body',
  '--header', `x-hub-signature-256: ${signed.signature}`,
], 0));
assert.equal(verified.ok, true);
assert.match(run(['check-url', 'https://example.com/'], 0), /"ok": true/);
assert.match(run(['check-url', 'https://127.0.0.1/'], 1), /"code": "PRIVATE_IP"/);
assert.match(run([], 2), /^$/);

console.log('cli smoke tests passed');
