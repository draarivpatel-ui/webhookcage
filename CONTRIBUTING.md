# Contributing

## Ground rules

- Keep runtime dependencies empty. `fast-check` is the only development dependency and is used only for property-based fuzz tests.
- Keep support for Node.js 18 and newer.
- Add deterministic offline tests for every security behavior.
- Do not weaken an existing rejection to make a new feature pass.
- Do not commit secrets, live webhook payloads, or personal data.
- Update ESM source first, then regenerate CommonJS with `node scripts/build-cjs.mjs`.

## Verification

```
npm test
node scripts/build-cjs.mjs --check
node scripts/check-types.mjs
node scripts/cli-smoke.mjs
node scripts/check-pack.mjs
```

Tests use `node:test` only. Windows and Ubuntu must both pass before a change
is released.
