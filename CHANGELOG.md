# Changelog

## 1.0.0

Initial release.

- GitHub, Stripe, Slack, and Standard Webhooks signature verification.
- HMAC-SHA256 and HMAC-SHA512 signing helpers with constant-time comparison.
- Timestamp replay windows, future clock-skew guards, key rotation, and a
  bounded memory replay store.
- Outbound webhook URL and resolved-address SSRF validation.
- Dual ESM and CommonJS entry points with TypeScript declarations.
