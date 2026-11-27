import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cliArgs = process.argv.slice(2);
const nodeArgs = [];
const fileArgs = [];

for (const arg of cliArgs) {
  if (arg.startsWith('--')) nodeArgs.push(arg);
  else fileArgs.push(arg);
}

function expandDefaultGlob() {
  return readdirSync(join(root, 'tests'))
    .filter((name) => name.endsWith('.test.mjs'))
    .sort()
    .map((name) => join('tests', name));
}

let files = fileArgs;
if (files.length === 0 || (files.length === 1 && files[0] === 'tests/*.test.mjs')) {
  files = expandDefaultGlob();
} else if (files.some((name) => name.includes('*'))) {
  process.stderr.write(`Unsupported test file pattern: ${files.find((name) => name.includes('*'))}\n`);
  process.exit(2);
}

if (files.length === 0) {
  process.stderr.write('No test files matched tests/*.test.mjs\n');
  process.exit(1);
}

const resolved = files.map((name) => (isAbsolute(name) ? name : join(root, name)));
const result = spawnSync(process.execPath, ['--test', ...nodeArgs, ...resolved], { stdio: 'inherit' });
if (result.error) throw result.error;
process.exit(result.status === null ? 1 : result.status);
