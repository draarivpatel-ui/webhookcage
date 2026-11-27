import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const declaration = fs.readFileSync(path.join(root, 'types', 'index.d.ts'), 'utf8');
if (/(:|=>)\s*any\b|\bas\s+any\b|\bArray<\s*any\s*>|\bany\s*\[\s*\]/u.test(declaration)) {
  console.error('types/index.d.ts must not use an explicit any type');
  process.exit(1);
}
for (const required of ['verifyWebhook', 'signHmac', 'verifyHmacSignatures', 'MemoryReplayStore', 'validateDeliveryUrl', 'auditResolvedDeliveryTarget', 'createDeliveryGuard']) {
  if (!declaration.includes(required)) {
    console.error('types/index.d.ts does not declare ' + required);
    process.exit(1);
  }
}

const command = process.platform === 'win32' ? 'tsc.cmd' : 'tsc';
const probe = spawnSync(command, ['--version'], { encoding: 'utf8', shell: false });
if (probe.error || probe.status !== 0) {
  console.log('strict type check skipped: tsc is not installed');
  process.exitCode = 0;
} else {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'webhookcage-types-'));
  try {
    fs.copyFileSync(path.join(root, 'types', 'index.d.ts'), path.join(scratch, 'index.d.ts'));
    fs.writeFileSync(path.join(scratch, 'check.ts'), [
      'import {',
      '  MemoryReplayStore,',
      '  auditResolvedDeliveryTarget,',
      '  constantTimeEqual,',
      '  createDeliveryGuard,',
      '  signHmac,',
      '  validateDeliveryUrl,',
      '  verifyHmacSignatures,',
      '  verifyWebhook,',
      '  VERSION,',
      '} from "./index";',
      'const version: "1.0.0" = VERSION;',
      'const signature = signHmac("secret", "body", { algorithm: "sha512", encoding: "hex" });',
      'const hmac = verifyHmacSignatures([signature], ["secret"], "body", { algorithm: "sha512", encoding: "hex" });',
      'const store = new MemoryReplayStore({ ttlMs: 300000 });',
      'const url = validateDeliveryUrl("https://example.com/");',
      'const resolved = auditResolvedDeliveryTarget("https://example.com/", ["93.184.216.34"]);',
      'const guard = createDeliveryGuard({ allowedPorts: "default-only" });',
      'const bytes = new Uint8Array([1]);',
      'const same: boolean = constantTimeEqual(bytes, bytes);',
      'if (url.ok && resolved.ok && same) {',
      '  console.log(version, hmac.secretIndex, store.size(), guard.validate("https://example.com/").ok);',
      '}',
    ].join('\n'), 'utf8');
    const result = spawnSync(command, ['--noEmit', '--strict', '--target', 'es2022', '--module', 'nodenext', '--moduleResolution', 'nodenext', 'check.ts'], { cwd: scratch, encoding: 'utf8', shell: false });
    if (result.status !== 0) {
      process.stderr.write(result.stderr + result.stdout);
      process.exitCode = 1;
    } else {
      console.log('strict type check ok');
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}
