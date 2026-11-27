import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  auditIp,
  auditResolvedDeliveryTarget,
  createDeliveryGuard,
  normalizeDeliveryHost,
  validateDeliveryUrl,
} from '../src/index.mjs';

const validCases = [
  'https://example.com/',
  'https://hooks.example.com/inbound',
  'https://1.1.1.1/',
  'https://8.8.8.8/',
  'https://[2606:4700:4700::1111]/',
  'https://example.com/path?x=1',
  'https://example.com./',
  'https://EXAMPLE.com/',
  'https://93.184.216.34/',
  'https://139.130.4.5/',
];

for (const [index, url] of validCases.entries()) {
  test(`outbound valid case ${index}`, () => {
    const result = validateDeliveryUrl(url);
    assert.equal(result.ok, true, result.detail);
    assert.equal(typeof result.hostname, 'string');
  });
}

const blockedIps = [
  '127.0.0.1', '127.1', '2130706433', '0x7f000001', '017700000001',
  '10.0.0.1', '172.16.0.1', '192.168.1.1', '169.254.1.1', '169.254.169.254',
  '169.254.170.2', '100.100.100.200', '192.0.0.192', '100.64.0.1',
  '0.0.0.0', '224.0.0.1', '240.0.0.1', '192.0.2.1', '198.51.100.1',
  '203.0.113.1', '198.18.0.1', '192.88.99.1',
];

for (const [index, ip] of blockedIps.entries()) {
  test(`outbound blocked ipv4 matrix ${index}`, () => {
    const result = validateDeliveryUrl(`https://${ip}/`);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'PRIVATE_IP');
  });
}

const blockedIpv6 = [
  '::1', '::', 'fe80::1', 'fc00::1', 'fd00::1', 'ff02::1', '2001:db8::1',
  '100::1', 'fd00:ec2::254', '::ffff:127.0.0.1', '2002:7f00:1::',
  '64:ff9b::127.0.0.1', '64:ff9b:1::127.0.0.1', '2001:0:4136:e378:8000:63bf:3fff:fdd2',
];

for (const [index, ip] of blockedIpv6.entries()) {
  test(`outbound blocked ipv6 matrix ${index}`, () => {
    const result = validateDeliveryUrl(`https://[${ip}]/`);
    assert.equal(result.ok, false, ip);
    assert.equal(result.code, 'PRIVATE_IP');
  });
}

const badHosts = [
  'localhost', 'localhost.localdomain', 'metadata', 'metadata.google.internal',
  'metadata.goog', 'instance-data', 'instance-data.ec2.internal', 'x.internal',
  'x.local', 'x.home.arpa', 'x.onion',
];

for (const [index, host] of badHosts.entries()) {
  test(`outbound blocked hostname matrix ${index}`, () => {
    const result = validateDeliveryUrl(`https://${host}/`);
    assert.equal(result.ok, false, host);
    assert.equal(result.code, 'HOST_DENIED');
  });
}

const structuralCases = [
  ['http://example.com/', 'UNSAFE_SCHEME'],
  ['ftp://example.com/', 'UNSAFE_SCHEME'],
  ['https://user:pass@example.com/', 'USERINFO_FORBIDDEN'],
  ['https://example.com:8443/', 'PORT_FORBIDDEN'],
  ['https://example.com:0/', 'PORT_FORBIDDEN'],
  ['//example.com/', 'INVALID_URL'],
  ['https:\\example.com/', 'INVALID_URL'],
  ['https://example.com:/', 'PORT_FORBIDDEN'],
  ['https://example.com:0443/', 'PORT_FORBIDDEN'],
  ['https:///path', 'INVALID_URL'],
];

for (const [index, [url, code]] of structuralCases.entries()) {
  test(`outbound structural rejection matrix ${index}`, () => {
    const result = validateDeliveryUrl(url);
    assert.equal(result.ok, false);
    assert.equal(result.code, code);
  });
}

test('allow-http option permits plain http on port 80', () => {
  const result = validateDeliveryUrl('http://example.com/', { allowedSchemes: ['https:', 'http:'] });
  assert.equal(result.ok, true);
});

test('allowedPorts any permits a high port', () => {
  const result = validateDeliveryUrl('https://example.com:8443/', { allowedPorts: 'any' });
  assert.equal(result.ok, true);
});

test('host allowlist permits only the named suffix', () => {
  const hostPolicy = { allow: ['.example.com'] };
  assert.equal(validateDeliveryUrl('https://hooks.example.com/', { hostPolicy }).ok, true);
  assert.equal(validateDeliveryUrl('https://evil.net/', { hostPolicy }).code, 'HOST_NOT_ALLOWED');
});

test('host denylist blocks exact host', () => {
  const hostPolicy = { deny: ['bad.example.com'] };
  assert.equal(validateDeliveryUrl('https://bad.example.com/', { hostPolicy }).code, 'HOST_DENIED');
});

test('denyCidrs blocks a public literal', () => {
  const result = validateDeliveryUrl('https://8.8.8.8/', { denyCidrs: ['8.8.8.0/24'] });
  assert.equal(result.code, 'HOST_DENIED');
});

test('normalizeDeliveryHost folds case and trailing dot', () => {
  assert.equal(normalizeDeliveryHost('EXAMPLE.com.'), 'example.com');
  assert.equal(normalizeDeliveryHost('0x01010101'), '1.1.1.1');
});

test('auditIp exposes structured public and private outcomes', () => {
  assert.equal(auditIp('8.8.8.8').ok, true);
  assert.equal(auditIp('127.0.0.1').ok, false);
  assert.equal(auditIp('not-an-ip').classification, 'invalid');
});

for (const [index, resolved] of [
  ['93.184.216.34'],
  ['1.1.1.1', '8.8.8.8'],
  ['2606:4700:4700::1111'],
].entries()) {
  test(`resolved target valid matrix ${index}`, () => {
    const result = auditResolvedDeliveryTarget('https://example.com/', resolved);
    assert.equal(result.ok, true, result.detail);
    assert.equal(result.pinned, true);
    assert.deepEqual(result.resolvedIps, [...resolved].sort());
  });
}

const badResolved = ['127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', 'fc00::1', 'not-an-ip'];
for (const [index, ip] of badResolved.entries()) {
  test(`resolved target rejects bad answer matrix ${index}`, () => {
    const result = auditResolvedDeliveryTarget('https://example.com/', [ip]);
    assert.equal(result.ok, false);
  });
}

test('resolved target accepts correct pinned IP', () => {
  const result = auditResolvedDeliveryTarget('https://example.com/', ['93.184.216.34'], { pinnedIp: '93.184.216.34' });
  assert.equal(result.ok, true);
  assert.equal(result.pinnedIp, '93.184.216.34');
});

test('resolved target rejects a mismatched pin', () => {
  const result = auditResolvedDeliveryTarget('https://example.com/', ['93.184.216.34'], { pinnedIp: '1.1.1.1' });
  assert.equal(result.code, 'PIN_MISMATCH');
});

test('resolved target detects changed answer sets', () => {
  const result = auditResolvedDeliveryTarget('https://example.com/', ['1.1.1.1'], { previousIps: ['8.8.8.8'] });
  assert.equal(result.code, 'DNS_REBIND');
});

test('resolved target accepts reordered identical answer sets', () => {
  const result = auditResolvedDeliveryTarget('https://example.com/', ['1.1.1.1', '8.8.8.8'], { previousIps: ['8.8.8.8', '1.1.1.1'] });
  assert.equal(result.ok, true);
});

test('createDeliveryGuard freezes a reusable policy', () => {
  const guard = createDeliveryGuard({ allowedPorts: 'any' });
  assert.equal(guard.validate('https://example.com:8443/').ok, true);
  assert.equal(Object.isFrozen(guard.options), true);
});
