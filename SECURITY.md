# Security policy

## Reporting a vulnerability

Use the private GitHub Security Advisory form at [Report a vulnerability](https://github.com/draarivpatel-ui/webhookcage/security/advisories/new). Do not open a public issue, pull request or discussion with exploit details.

Never include a live secret, token, cookie, private key, victim hostname or proprietary payload in a report. Use synthetic values and redacted transcripts.

## Supported versions

| Version | Status |
| --- | --- |
| 1.x | Supported |

Security fixes are applied to the latest release line.

## Scope

This policy covers inbound webhook signature verification, replay protection, key rotation and outbound delivery URL validation.

In scope:

- Signature canonicalization, HMAC comparison, timestamp or replay protection bypasses.
- Key rotation behavior that accepts an untrusted or wrong secret as valid.
- SSRF validation bypasses involving URL parsing, obfuscated IP literals, private ranges, metadata endpoints or DNS rebinding checks.
- Header normalization flaws that accept ambiguous security headers.

Out of scope:

- Live secrets or webhook payloads reported without authorization.
- Applications that parse JSON before preserving raw bytes or that disable validation.
- TLS termination, HTTP server parsing and cloud network controls outside the library.

## Coordinated disclosure

- Acknowledgment: within 48 hours.
- Initial assessment: within 7 calendar days.
- Fix or mitigation plan: within 30 calendar days for confirmed high-impact reports.
- Coordinated public disclosure: up to 90 days by default, adjusted by mutual agreement when exploitation or user risk requires a different date.
