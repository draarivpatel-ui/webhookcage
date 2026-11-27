# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.x     | Yes       |

## Reporting a vulnerability

Use the repository's private vulnerability reporting form, available from the
Security tab as "Report a vulnerability". Do not open a public issue for an
unfixed bypass.

Include the package version, Node.js version, operating system, provider or
URL involved, exact reproduction input, expected behavior, and observed
behavior. Do not include a live secret. Use a generated test secret.

## In scope

- Signature bypasses, canonicalization mistakes, or nonconstant-time secret
  comparison behavior.
- Replay-window, timestamp, clock-skew, key-rotation, or replay-store bypasses.
- Prototype-pollution paths that alter security behavior.
- SSRF validation bypasses involving URL parsing, obfuscated IP literals,
  cloud metadata endpoints, CIDR rules, IPv6 transition mechanisms, host policy,
  or resolved-address pinning.
- Header normalization flaws that accept ambiguous security headers.

## Out of scope

- A live secret or webhook payload reported without the owner's authorization.
- Vulnerabilities in an application that parses JSON before preserving the raw
  body, disables validation, or fetches without enforcing its own egress rules.
- TLS termination, HTTP server parsing, and cloud network controls outside the
  library.
