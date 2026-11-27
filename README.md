# webhookcage

`webhookcage` is a zero-dependency webhook security firewall for Node.js 18
and newer. It verifies inbound webhook signatures with constant-time HMAC
comparison, enforces timestamp replay windows and clock-skew limits, supports
zero-downtime key rotation, records replayed deliveries, and validates outbound
webhook delivery URLs against SSRF and cloud metadata attacks.

The package has no runtime dependencies. `fast-check` is a development-only
fuzzing dependency. It ships native ESM, generated CommonJS, and TypeScript
declarations.

## Inbound verification

```js
import { MemoryReplayStore, verifyWebhook } from 'webhookcage';

const replayStore = new MemoryReplayStore();

const result = verifyWebhook('github', rawBody, requestHeaders, {
  secrets: [newSecret, oldSecret],
  replayStore,
  requireReplay: true,
});

console.log(result.valid, result.secretIndex);
```

Supported provider schemes:

- GitHub `x-hub-signature-256` with HMAC-SHA256 hex.
- Stripe `Stripe-Signature` with `t` plus one or more `v1` HMAC-SHA256 hex
  signatures over `timestamp.body`.
- Slack `x-slack-signature` and `x-slack-request-timestamp` with HMAC-SHA256
  hex over `v0:timestamp:body`.
- Standard Webhooks `webhook-id`, `webhook-timestamp`, and `webhook-signature`
  with base64 HMAC-SHA256 over `id.timestamp.body`. Real `whsec_...`
  secrets are base64 decoded before use; raw byte keys remain supported.

GitHub does not include a signed timestamp in its native scheme. The library
verifies the exact HMAC and uses the delivery identifier for replay protection
when GitHub supplies one. Stripe, Slack, and Standard Webhooks enforce a
300-second replay window and a 60-second future clock-skew allowance by
default. Both values are configurable.

Raw bodies are byte-exact strings, `Buffer` values, or `Uint8Array` values.
Parsed JSON objects are rejected because reserializing JSON changes bytes and
breaks signatures.

## Signing and generic HMAC

```js
import { signHmac, verifyHmacSignatures } from 'webhookcage';

const signature = signHmac('secret', 'payload', {
  algorithm: 'sha512',
  encoding: 'hex',
});

const match = verifyHmacSignatures([signature], ['new-secret', 'secret'], 'payload', {
  algorithm: 'sha512',
  encoding: 'hex',
});

console.log(match.secretIndex);
```

Both HMAC-SHA256 and HMAC-SHA512 are supported. Hex and canonical base64 are
decoded strictly. Byte comparison uses `crypto.timingSafeEqual`. Rotation
accepts up to 32 keys and checks every candidate without object mutation.

## Replay protection

`MemoryReplayStore` is a bounded in-memory store suitable for tests and small
single-process receivers. Production systems can provide any object exposing
`checkAndRecord(key)`.

```js
const store = new MemoryReplayStore({ ttlMs: 300000, maxEntries: 10000 });
verifyWebhook('stripe', body, headers, { secret, replayStore: store });
```

A second accepted delivery with the same provider-scoped replay key throws
`REPLAYED_DELIVERY`. Replay recording happens only after signature and
timestamp verification succeed.

## Outbound SSRF firewall

```js
import { auditResolvedDeliveryTarget, validateDeliveryUrl } from 'webhookcage';

const staticResult = validateDeliveryUrl('https://hooks.example.com/inbound');
if (!staticResult.ok) throw new Error(staticResult.code);

const resolved = auditResolvedDeliveryTarget(
  'https://hooks.example.com/inbound',
  ['93.184.216.34'],
  { pinnedIp: '93.184.216.34' },
);
```

The outbound validator rejects unsafe schemes, embedded credentials, nondefault
ports, loopback and private ranges, cloud metadata endpoints, obfuscated IPv4
forms, IPv6 transition tunnels, local hostnames, CIDR matches, Unicode hostnames
in the default ASCII-only mode, and long or malformed input. Resolution checks
validate every A or AAAA answer and can compare a previous answer set to catch
DNS rebinding.

## Prototype-pollution resistance

Security options are read only as own properties. Headers normalize into a
`Map`, never into a plain object. Policy objects are copied or frozen at
boundaries documented by the API. A polluted `Object.prototype` cannot inject
a secret, resolver, URL policy, replay store, or provider behavior.

## CLI

```
webhookcage sign github --secret-env WEBHOOK_SECRET --body '{}'
webhookcage verify github --secret-env WEBHOOK_SECRET --body '{}' --header 'x-hub-signature-256: sha256=...'
webhookcage check-url https://hooks.example.com/inbound
```

The CLI exits `0` for success, `1` for a security rejection, and `2` for usage
errors. Prefer `--secret-env` so secrets do not appear in shell history.

## Examples

```
node examples/inbound-github.mjs
node examples/key-rotation.mjs
node examples/outbound-delivery.mjs
```

## Security contract

- Verify the exact raw body bytes before JSON parsing.
- Use TLS and validate the inbound source at the infrastructure layer too.
- Persist replay keys for at least the timestamp tolerance window.
- Rotate secrets by configuring the new key first and removing the old key
  after senders are updated.
- Validate outbound webhook URLs before queueing and again before delivery.
- Validate every resolved IP and pin the connection to the verified address
  when the HTTP client supports it.
- Keep network egress controls in place as an independent layer.

## Development

```
npm test
node scripts/build-cjs.mjs --check
node scripts/check-types.mjs
node scripts/cli-smoke.mjs
node scripts/check-pack.mjs
```

The test suite is deterministic and offline. CI runs eight jobs across Ubuntu
and Windows on Node.js 18, 20, 22, and 24.
