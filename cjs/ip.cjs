// IPv4/IPv6 parsing, normalization, CIDR matching and risk classification.
// Zero dependencies. All parsers are strict and reject ambiguous/oversized input.

const DEC = /^\d+$/;
const HEX = /^0[xX][0-9a-fA-F]+$/;
const OCT = /^0[oO][0-7]+$/;
const LEGACY_OCT = /^0[0-7]+$/;
const BIN = /^0[bB][01]+$/;
const HEX_GROUP = /^[0-9a-fA-F]{1,4}$/;

/** Parse one IPv4 octet accepting decimal, 0x hex, 0o/leading-0 octal and 0b binary. */
function parseOctet(token) {
  if (!token || token.length > 16) return null;
  let base = 10;
  let body = token;
  if (HEX.test(token)) { base = 16; body = token.slice(2); }
  else if (OCT.test(token)) { base = 8; body = token.slice(2); }
  else if (LEGACY_OCT.test(token)) { base = 8; body = token.slice(1); }
  else if (/^0\d+$/.test(token)) return null;
  else if (BIN.test(token)) { base = 2; body = token.slice(2); }
  else if (!DEC.test(token)) return null;
  if (body.length === 0 || body.length > 16) return null;
  let value = 0;
  for (const ch of body) {
    const digit = parseInt(ch, base);
    if (!Number.isFinite(digit) || digit >= base) return null;
    value = value * base + digit;
    if (value > 0xffffffff) return null;
  }
  return value <= 0xffffff ? value : null;
}

/**
 * Decode IPv4 dotted, hexadecimal, octal, decimal-integer and shorthand forms.
 * Returns the canonical dotted-quad string or null.
 */
function parseIpv4(host) {
  if (typeof host !== 'string' || host.length === 0 || host.length > 64) return null;
  if (host.includes('%')) return null;
  if (DEC.test(host) || HEX.test(host) || OCT.test(host) || BIN.test(host) || LEGACY_OCT.test(host)) {
    let value = 0;
    if (HEX.test(host)) value = Number.parseInt(host.slice(2), 16);
    else if (OCT.test(host)) value = Number.parseInt(host.slice(2), 8);
    else if (BIN.test(host)) value = Number.parseInt(host.slice(2), 2);
    else if (LEGACY_OCT.test(host)) value = Number.parseInt(host.slice(1), 8);
    else value = Number.parseInt(host, 10);
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) return null;
    return fromUint32(value);
  }
  const parts = host.split('.');
  if (parts.length < 1 || parts.length > 4) return null;
  const values = [];
  for (const part of parts) {
    const octet = parseOctet(part);
    if (octet === null) return null;
    values.push(octet);
  }
  // a.b.c.d, a.b.c, a.b and a forms: the final field holds the remaining bits.
  if (values.length === 4 && values.slice(0, 3).every((v) => v <= 255) && values[3] <= 255) {
    return fromUint32(((values[0] << 24) | (values[1] << 16) | (values[2] << 8) | values[3]) >>> 0);
  }
  if (values.length === 3 && values[0] <= 255 && values[1] <= 255 && values[2] <= 0xffff) {
    return fromUint32(((values[0] << 24) | (values[1] << 16) | values[2]) >>> 0);
  }
  if (values.length === 2 && values[0] <= 255 && values[1] <= 0xffffff) {
    return fromUint32(((values[0] << 24) | values[1]) >>> 0);
  }
  if (values.length === 1 && values[0] <= 0xffffffff) return fromUint32(values[0] >>> 0);
  return null;
}

function fromUint32(value) {
  return `${(value >>> 24) & 255}.${(value >>> 16) & 255}.${(value >>> 8) & 255}.${value & 255}`;
}

function ipv4ToUint32(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!DEC.test(part)) return null;
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    value = value * 256 + n;
  }
  return value >>> 0;
}

function parseGroups(text) {
  if (text.length === 0) return [];
  const groups = [];
  for (const piece of text.split(':')) {
    if (!HEX_GROUP.test(piece)) return null;
    groups.push(Number.parseInt(piece, 16));
  }
  return groups;
}

function parseEmbeddedIpv4(token) {
  if (!token) return null;
  if (token.includes('.')) {
    const ipv4 = parseIpv4(token);
    if (ipv4 === null) return null;
    const [a, b, c, d] = ipv4.split('.').map(Number);
    return [((a << 8) | b) >>> 0, ((c << 8) | d) >>> 0];
  }
  if (!HEX_GROUP.test(token)) return null;
  return [Number.parseInt(token, 16)];
}

/**
 * Expand an IPv6 host (without brackets or zone ID) into eight 16-bit groups.
 * Handles embedded IPv4, full/compressed forms and IPv4-mapped representations.
 */
function parseIpv6(host) {
  if (typeof host !== 'string' || host.length === 0 || host.length > 128) return null;
  let text = host;
  if (text.includes('%')) {
    const idx = text.indexOf('%');
    text = text.slice(0, idx); // strip zone identifier; it never changes the address
  }
  if (text.includes('.')) {
    const lastColon = text.lastIndexOf(':');
    if (lastColon < 0) return null;
    const tail = text.slice(lastColon + 1);
    const tailGroups = parseEmbeddedIpv4(tail);
    if (tailGroups === null || tailGroups.length !== 2) return null;
    text = `${text.slice(0, lastColon + 1)}${tailGroups[0].toString(16)}:${tailGroups[1].toString(16)}`;
  }
  const compressed = text.includes('::');
  if (compressed) {
    if (text.indexOf('::') !== text.lastIndexOf('::')) return null;
    const [left, right] = text.split('::');
    const leftGroups = parseGroups(left);
    const rightGroups = parseGroups(right);
    if (!leftGroups || !rightGroups) return null;
    const missing = 8 - leftGroups.length - rightGroups.length;
    if (missing < 1) return null;
    return [...leftGroups, ...new Array(missing).fill(0), ...rightGroups];
  }
  const groups = parseGroups(text);
  if (!groups || groups.length !== 8) return null;
  return groups;
}

/** Extract a mapped IPv4 address from ::ffff:a.b.c.d or ::ffff:xxxx:xxxx, if present. */
function mappedIpv4(groups) {
  if (!groups || groups.length !== 8) return null;
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    return fromUint32(((groups[6] << 16) | groups[7]) >>> 0);
  }
  return null;
}

/** Extract the embedded IPv4 from a 6to4 (2002::/16) address. */
function sixToFourIpv4(groups) {
  if (!groups || groups.length !== 8 || groups[0] !== 0x2002) return null;
  return fromUint32(((groups[1] << 16) | groups[2]) >>> 0);
}

/** Extract the embedded IPv4 from a NAT64 (64:ff9b::/96) address. */
function nat64Ipv4(groups) {
  if (!groups || groups.length !== 8) return null;
  const prefix = [0x0064, 0xff9b, 0, 0, 0, 0];
  if (!prefix.every((g, i) => groups[i] === g)) return null;
  return fromUint32(((groups[6] << 16) | groups[7]) >>> 0);
}

/**
 * Detect the RFC 8215 local-use NAT64 prefix 64:ff9b:1::/48.
 * It is only valid inside a local network, so it is never a public destination.
 */
function isNat64LocalUse(groups) {
  return !!groups && groups.length === 8
    && groups[0] === 0x0064 && groups[1] === 0xff9b && groups[2] === 0x0001;
}

/** Extract the embedded IPv4 from an ISATAP interface identifier, if present. */
function isatapIpv4(groups) {
  if (!groups || groups.length !== 8) return null;
  if ((groups[4] !== 0x0000 && groups[4] !== 0x0200) || groups[5] !== 0x5efe) return null;
  return fromUint32(((groups[6] << 16) | groups[7]) >>> 0);
}

/** Extract the embedded IPv4 from an IPv4-compatible (::/96) address. */
function ipv4CompatibleIpv4(groups) {
  if (!groups || groups.length !== 8) return null;
  for (let i = 0; i < 6; i += 1) if (groups[i] !== 0) return null;
  return fromUint32(((groups[6] << 16) | groups[7]) >>> 0);
}

/** Extract the embedded IPv4 from an IPv4-translated SIIT (::ffff:0:0:0/96) address. */
function siitIpv4(groups) {
  if (!groups || groups.length !== 8) return null;
  if (groups[0] !== 0 || groups[1] !== 0 || groups[2] !== 0 || groups[3] !== 0) return null;
  if (groups[4] !== 0xffff || groups[5] !== 0) return null;
  return fromUint32(((groups[6] << 16) | groups[7]) >>> 0);
}

/** Classify a Teredo (2001:0000::/32) client/server address. */
function isTeredo(groups) {
  return !!groups && groups.length === 8 && groups[0] === 0x2001 && groups[1] === 0x0000;
}

/**
 * Decode the obfuscated client IPv4 of a Teredo address (XOR with 0xffffffff).
 * Example: 2001:0:4136:e378:8000:63bf:3fff:fdd2 decodes to 192.0.2.45.
 */
function teredoClientIpv4(groups) {
  if (!isTeredo(groups)) return null;
  const obfuscated = ((groups[6] << 16) | groups[7]) >>> 0;
  return fromUint32((obfuscated ^ 0xffffffff) >>> 0);
}

/** Canonicalize an IPv6 address to lowercase RFC 5952 compressed form. */
function formatIpv6(groups) {
  if (!groups || groups.length !== 8) return null;
  // Find the longest run of zeroes (length >= 2) to compress.
  let bestStart = -1;
  let bestLen = 0;
  let currentStart = -1;
  let currentLen = 0;
  for (let i = 0; i < 8; i += 1) {
    if (groups[i] === 0) {
      if (currentStart < 0) currentStart = i;
      currentLen += 1;
      if (currentLen > bestLen) { bestLen = currentLen; bestStart = currentStart; }
    } else { currentStart = -1; currentLen = 0; }
  }
  if (bestLen < 2) return groups.map((g) => g.toString(16)).join(':');
  const left = groups.slice(0, bestStart).map((g) => g.toString(16)).join(':');
  const right = groups.slice(bestStart + bestLen).map((g) => g.toString(16)).join(':');
  return `${left}::${right}`;
}

const IPV4_RANGES = [
  // Specific ranges first so classification names are precise.
  { name: 'cloud-metadata', base: [169, 254, 169, 254], bits: 32 },
  { name: 'cloud-metadata-aws-ctf', base: [169, 254, 170, 2], bits: 32 },
  { name: 'alibaba-metadata', base: [100, 100, 100, 200], bits: 32 },
  { name: 'azure-platform', base: [168, 63, 129, 16], bits: 32 },
  { name: 'broadcast', base: [255, 255, 255, 255], bits: 32 },
  { name: 'documentation-1', base: [192, 0, 2, 0], bits: 24 },
  { name: 'documentation-2', base: [198, 51, 100, 0], bits: 24 },
  { name: 'documentation-3', base: [203, 0, 113, 0], bits: 24 },
  { name: 'unspecified', base: [0, 0, 0, 0], bits: 8 },
  { name: 'loopback', base: [127, 0, 0, 0], bits: 8 },
  { name: 'private-10', base: [10, 0, 0, 0], bits: 8 },
  { name: 'private-172', base: [172, 16, 0, 0], bits: 12 },
  { name: 'ietf-protocol', base: [192, 0, 0, 0], bits: 24 },
  { name: 'as112', base: [192, 31, 196, 0], bits: 24 },
  { name: 'amt', base: [192, 52, 193, 0], bits: 24 },
  { name: '6to4-relay', base: [192, 88, 99, 0], bits: 24 },
  { name: 'direct-delegation', base: [192, 175, 48, 0], bits: 24 },
  { name: 'private-192', base: [192, 168, 0, 0], bits: 16 },
  { name: 'link-local', base: [169, 254, 0, 0], bits: 16 },
  { name: 'cgnat', base: [100, 64, 0, 0], bits: 10 },
  { name: 'multicast', base: [224, 0, 0, 0], bits: 4 },
  { name: 'benchmark', base: [198, 18, 0, 0], bits: 15 },
  { name: 'blackhole-240', base: [240, 0, 0, 0], bits: 4 },
];

const IPV6_RANGES = [
  { name: 'unspecified', base: [0, 0, 0, 0, 0, 0, 0, 0], bits: 128 },
  { name: 'loopback', base: [0, 0, 0, 0, 0, 0, 0, 1], bits: 128 },
  // 0000::/8 is reserved by the IETF. Every transition prefix inside it is
  // decoded before this list runs, so a hit here is an address no host routes.
  { name: 'reserved', base: [0, 0, 0, 0, 0, 0, 0, 0], bits: 8 },
  { name: 'link-local', base: [0xfe80, 0, 0, 0, 0, 0, 0, 0], bits: 10 },
  { name: 'unique-local', base: [0xfc00, 0, 0, 0, 0, 0, 0, 0], bits: 7 },
  { name: 'multicast', base: [0xff00, 0, 0, 0, 0, 0, 0, 0], bits: 8 },
  { name: 'benchmark', base: [0x2001, 0x0002, 0, 0, 0, 0, 0, 0], bits: 48 },
  { name: 'amt', base: [0x2001, 0x0003, 0, 0, 0, 0, 0, 0], bits: 32 },
  { name: 'orchid-deprecated', base: [0x2001, 0x0010, 0, 0, 0, 0, 0, 0], bits: 28 },
  { name: 'orchidv2', base: [0x2001, 0x0020, 0, 0, 0, 0, 0, 0], bits: 28 },
  { name: 'drone-remote-id', base: [0x2001, 0x0030, 0, 0, 0, 0, 0, 0], bits: 28 },
  // 2001::/23 is the IETF protocol-assignment parent block. More specific
  // entries above keep their precise names; every unassigned descendant is
  // still blocked instead of falling through as globally routable space.
  { name: 'ietf-protocol', base: [0x2001, 0, 0, 0, 0, 0, 0, 0], bits: 23 },
  { name: 'documentation', base: [0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], bits: 32 },
  { name: 'direct-delegation-as112', base: [0x2620, 0x004f, 0x8000, 0, 0, 0, 0, 0], bits: 48 },
  { name: 'srv6-sids', base: [0x5f00, 0, 0, 0, 0, 0, 0, 0], bits: 16 },
  { name: 'dummy-v6', base: [0x0100, 0, 0, 0x0001, 0, 0, 0, 0], bits: 64 },
  { name: 'documentation-2', base: [0x3fff, 0, 0, 0, 0, 0, 0, 0], bits: 20 },
  { name: 'discard-only', base: [0x0100, 0, 0, 0, 0, 0, 0, 0], bits: 64 },
  { name: 'aws-metadata', base: [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254], bits: 0 },
];

function prefixMatch(actual, expected, bits, totalBits) {
  if (totalBits === 32) {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return ((actual ^ expected) >>> 0 & mask) === 0;
  }
  let remaining = bits;
  for (let i = 0; i < 8; i += 1) {
    if (remaining <= 0) break;
    const mask = remaining >= 16 ? 0xffff : ((0xffff << (16 - remaining)) & 0xffff);
    if (((actual[i] ^ expected[i]) & mask) !== 0) return false;
    remaining -= 16;
  }
  return true;
}

const AWS_METADATA_FULL = [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254];

/** Classify an IP address string. Returns 'private', 'public', 'invalid', or a named range. */
function classifyIp(host) {
  if (typeof host !== 'string' || host.length === 0 || host.length > 253) return 'invalid';
  let text = host.trim();
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);
  if (text.includes('%')) text = text.slice(0, text.indexOf('%'));
  if (text.includes(':')) {
    const groups = parseIpv6(text);
    if (!groups) return 'invalid';
    const transitionClass = (embedded, name) => {
      const embeddedClass = classifyIpv4Value(embedded);
      return embeddedClass === 'public' ? name : embeddedClass;
    };
    const mapped = mappedIpv4(groups);
    if (mapped !== null) return transitionClass(mapped, 'ipv4-mapped');
    const sixFour = sixToFourIpv4(groups);
    if (sixFour !== null) return transitionClass(sixFour, '6to4');
    const nat = nat64Ipv4(groups);
    if (nat !== null) return transitionClass(nat, 'nat64');
    const siit = siitIpv4(groups);
    if (siit !== null) return transitionClass(siit, 'ipv4-translated');
    if (isNat64LocalUse(groups)) return 'nat64-local-use';
    if (isTeredo(groups)) return 'private';
    const isatap = isatapIpv4(groups);
    if (isatap !== null) return transitionClass(isatap, 'isatap');
    const compatible = ipv4CompatibleIpv4(groups);
    if (compatible !== null) {
      // :: and ::1 are RFC 4291 special forms, not IPv4-compatible addresses.
      if (groups.every((g) => g === 0)) return 'unspecified';
      if (groups[7] === 1 && groups.slice(0, 7).every((g) => g === 0)) return 'loopback';
      return transitionClass(compatible, 'ipv4-compatible');
    }
    for (const range of IPV6_RANGES) {
      if (range.bits === 0) {
        if (range.name === 'aws-metadata' && groups.every((g, i) => g === AWS_METADATA_FULL[i])) return range.name;
        continue;
      }
      if (prefixMatch(groups, range.base, range.bits, 128)) return range.name;
    }
    if (groups[0] < 0x2000 || groups[0] >= 0x4000) return 'reserved';
    return 'public';
  }
  const ipv4 = parseIpv4(text);
  if (ipv4 === null) return 'invalid';
  return classifyIpv4Value(ipv4);
}

function classifyIpv4Value(ip) {
  const value = ipv4ToUint32(ip);
  if (value === null) return 'invalid';
  for (const range of IPV4_RANGES) {
    const expected = ((range.base[0] << 24) | (range.base[1] << 16) | (range.base[2] << 8) | range.base[3]) >>> 0;
    if (prefixMatch(value, expected, range.bits, 32)) return range.name;
  }
  return 'public';
}

/** Normalize an IP host to a canonical string, or null if it is not an IP. */
function normalizeIp(host) {
  if (typeof host !== 'string' || host.includes('%')) return null;
  let text = host.trim();
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);
  if (text.includes(':')) {
    const groups = parseIpv6(text);
    return groups ? formatIpv6(groups) : null;
  }
  return parseIpv4(text);
}

/** Parse a CIDR like 10.0.0.0/8 or fd00::/8 into { family, base, bits }. */
function parseCidr(cidr) {
  if (typeof cidr !== 'string') return null;
  const slash = cidr.lastIndexOf('/');
  if (slash < 1) return null;
  const address = cidr.slice(0, slash);
  const bitsText = cidr.slice(slash + 1);
  if (!DEC.test(bitsText)) return null;
  const bits = Number(bitsText);
  if (address.includes(':')) {
    const groups = parseIpv6(address);
    if (!groups || bits > 128) return null;
    return { family: 6, groups, bits };
  }
  const ipv4 = parseIpv4(address);
  if (ipv4 === null || bits > 32) return null;
  const value = ipv4ToUint32(ipv4);
  return value === null ? null : { family: 4, value, bits };
}

/**
 * Return the IPv4 address carried by any transition form the classifier
 * decodes, so an IPv4 CIDR list cannot be evaded with a mapped or translated
 * spelling of the same destination.
 */
function embeddedIpv4(groups) {
  if (!groups) return null;
  const mapped = mappedIpv4(groups);
  if (mapped !== null) return mapped;
  const sixFour = sixToFourIpv4(groups);
  if (sixFour !== null) return sixFour;
  const nat = nat64Ipv4(groups);
  if (nat !== null) return nat;
  const siit = siitIpv4(groups);
  if (siit !== null) return siit;
  const isatap = isatapIpv4(groups);
  if (isatap !== null) return isatap;
  return ipv4CompatibleIpv4(groups);
}

function cidrContains(cidr, address) {
  const parsed = parseCidr(cidr);
  if (!parsed) return false;
  if (parsed.family === 4) {
    let ipv4 = parseIpv4(address);
    if (ipv4 === null) {
      const groups = parseIpv6(address);
      ipv4 = groups ? embeddedIpv4(groups) : null;
    }
    if (ipv4 === null) return false;
    const value = ipv4ToUint32(ipv4);
    return value !== null && prefixMatch(value, parsed.value, parsed.bits, 32);
  }
  const groups = parseIpv6(address);
  if (!groups) return false;
  return prefixMatch(groups, parsed.groups, parsed.bits, 128);
}

/** Audit one IP literal and return a structured, non-throwing decision. */
function auditIp(input) {
  const normalized = normalizeIp(input);
  const classification = typeof input === 'string' ? classifyIp(input) : 'invalid';
  if (normalized === null) {
    return Object.freeze({ ok: false, code: 'INVALID_IP', detail: 'input is not a valid IP literal', classification: 'invalid', normalized: null });
  }
  if (classification !== 'public') {
    return Object.freeze({ ok: false, code: 'PRIVATE_IP', detail: 'IP literal is not globally public', classification, normalized });
  }
  return Object.freeze({ ok: true, code: 'OK', detail: 'IP literal is globally public', classification, normalized });
}

exports.parseIpv4 = parseIpv4;
exports.ipv4ToUint32 = ipv4ToUint32;
exports.parseIpv6 = parseIpv6;
exports.mappedIpv4 = mappedIpv4;
exports.sixToFourIpv4 = sixToFourIpv4;
exports.nat64Ipv4 = nat64Ipv4;
exports.isNat64LocalUse = isNat64LocalUse;
exports.isatapIpv4 = isatapIpv4;
exports.ipv4CompatibleIpv4 = ipv4CompatibleIpv4;
exports.siitIpv4 = siitIpv4;
exports.isTeredo = isTeredo;
exports.teredoClientIpv4 = teredoClientIpv4;
exports.formatIpv6 = formatIpv6;
exports.classifyIp = classifyIp;
exports.normalizeIp = normalizeIp;
exports.parseCidr = parseCidr;
exports.cidrContains = cidrContains;
exports.auditIp = auditIp;
