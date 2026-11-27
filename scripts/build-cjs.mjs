// Generate CommonJS modules from src/*.mjs with a small, dependency-free
// transform. The library only uses static import/export syntax that this
// transform supports. Run: node scripts/build-cjs.mjs
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const srcDir = join(root, 'src');
const cjsDir = join(root, 'cjs');
mkdirSync(cjsDir, { recursive: true });

const MODULES = ['errors', 'ip', 'ssrf', 'headers', 'crypto', 'replay', 'providers', 'verify', 'index'];

function transform(source) {
  const exportAssignments = [];
  let out = source;

  out = out.replace(/import\s*\{([^}]*)\}\s*from\s*'(\.\/[^']+\.mjs)';/g, (full, names, spec) => {
    const bindings = names.split(',').map((s) => s.trim()).filter(Boolean).map((s) => {
      const parts = s.split(/\s+as\s+/);
      return parts.length === 2 ? `${parts[1]}: ${parts[0]}` : s;
    });
    return `const { ${bindings.join(', ')} } = require('${spec.replace(/\.mjs$/, '.cjs')}');`;
  });
  out = out.replace(/import\s+(\w+)\s+from\s*'(\.\/[^']+\.mjs)';/g, (full, name, spec) =>
    `const ${name} = require('${spec.replace(/\.mjs$/, '.cjs')}').default;`);
  out = out.replace(/import\s*\{([^}]*)\}\s*from\s*'(node:[^']+)';/g, (full, names, spec) =>
    `const { ${names.trim()} } = require('${spec}');`);
  out = out.replace(/await import\('\.\/errors\.mjs'\)/g, "Promise.resolve(require('./errors.cjs'))");

  // Re-exports: export { a, b as c } from './x.mjs';
  out = out.replace(/export\s*\{([^}]*)\}\s*from\s*'(\.\/[^']+\.mjs)';/g, (full, names, spec) => {
    const local = `__reexport_${spec.replace(/[^\w]/g, '_')}`;
    const lines = [`const ${local} = require('${spec.replace(/\.mjs$/, '.cjs')}');`];
    for (const raw of names.split(',').map((s) => s.trim()).filter(Boolean)) {
      const parts = raw.split(/\s+as\s+/);
      const source = parts[0];
      const exported = parts[1] || source;
      lines.push(`Object.defineProperty(exports, ${JSON.stringify(exported)}, { enumerable: true, get: () => ${local}.${source} });`);
    }
    return lines.join('\n');
  });
  out = out.replace(/export\s*\{([^}]*)\};/g, (full, names) => {
    const lines = [];
    for (const raw of names.split(',').map((s) => s.trim()).filter(Boolean)) {
      const parts = raw.split(/\s+as\s+/);
      const local = parts[0];
      const exported = parts[1] || local;
      exportAssignments.push([exported, local]);
      if (exported !== local) lines.push(`Object.defineProperty(exports, ${JSON.stringify(exported)}, { enumerable: true, get: () => ${local} });`);
    }
    return lines.join('\n');
  });

  out = out.replace(/export\s+(const|let|function|async\s+function|class)\s+([A-Za-z_$][\w$]*)/g, (full, kind, name) => {
    exportAssignments.push([name, name]);
    return `${kind} ${name}`;
  });
  out = out.replace(/export\s+default\s+([A-Za-z_$][\w$]*);/g, (full, name) => {
    exportAssignments.push(['default', name]);
    return '';
  });

  const seen = new Set();
  for (const [exported, local] of exportAssignments) {
    if (seen.has(exported)) continue;
    seen.add(exported);
    if (exported !== 'default') out += `\nexports.${exported} = ${local};`;
  }
  if (exportAssignments.some(([name]) => name === 'default')) {
    const local = exportAssignments.find(([name]) => name === 'default')[1];
    out += `\nexports.default = ${local};`;
  }
  return `${out}\n`;
}

function normalizeLf(text) {
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

function outputFor(name) {
  const source = normalizeLf(readFileSync(join(srcDir, `${name}.mjs`), 'utf8'));
  return normalizeLf(transform(source));
}

const check = process.argv.includes('--check');
const outdated = [];

for (const name of MODULES) {
  const target = join(cjsDir, `${name}.cjs`);
  const output = outputFor(name);
  if (!check) {
    writeFileSync(target, output);
  } else if (!existsSync(target) || readFileSync(target, 'utf8') !== output) {
    outdated.push(`cjs/${name}.cjs`);
  }
}

if (check) {
  if (outdated.length > 0) {
    console.error(`CommonJS artifacts are out of date: ${outdated.join(', ')}`);
    process.exit(1);
  }
  console.log(`Verified ${MODULES.length} CommonJS modules in cjs/`);
} else {
  console.log(`Generated ${MODULES.length} CommonJS modules in cjs/`);
}
