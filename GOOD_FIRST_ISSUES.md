# Good first issues

Small scoped contributions that keep the core zero-dependency contract:

1. Add an adapter recipe for a framework while preserving byte-exact raw body
   handling. This should be documentation or an example, not a dependency.
2. Add additional known public webhook provider test vectors when the provider
   publishes a signed example and license permits copying it.
3. Expand documentation for persisting replay keys in Redis, SQL, or DynamoDB
   without adding those clients as dependencies.
4. Add more malformed Stripe and Standard Webhooks header vectors.
5. Add more outbound URL obfuscation vectors, especially IPv4 shorthand and
   IPv6 transition forms.
6. Add a threat-model diagram or integration checklist.
7. Add a fuzz regression seed for URL policy matching after reproducing it as
   a deterministic unit test.

Every item requires offline tests and must pass the full verification list in
`CONTRIBUTING.md`.
