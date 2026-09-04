# Section 6 — Log redaction

## What is redacted, and at which layer

`accounts-api` serves name, email, phone, IBAN, balance, and card last-4 —
all of it sensitive, some of it (IBAN, balance) directly reportable if
leaked. Redaction happens at **two layers**, because relying on either
alone has a failure mode:

1. **Application layer** ([`app/main.go`](../app/main.go)): the handler logs
   a structured event (`account_lookup`) with only `account_id` and
   `request_id` — never the response body, never the `Authorization`
   header, never raw query parameters. This is a positive allow-list (log
   these specific fields), not a denylist of "don't log X" — an allow-list
   doesn't silently start leaking a new PII field the day someone adds one
   to the response struct without also touching the log line, which is
   exactly the failure mode a denylist has.
2. **Infrastructure layer**: the ALB/CloudFront access logs (outside this
   repo, platform-owned) capture the request path and headers by default.
   The path here is `/accounts/{id}` — the account ID appears in the URL
   and therefore in edge access logs regardless of what the app does. This
   is accepted, not fixed, because account IDs alone are not the regulated
   PII (name/email/IBAN/card) and redacting URLs at the edge would break
   the ability to correlate an incident by request path at all.

## What this redaction still leaks

Being honest about the gaps matters more than claiming completeness:

- **The account ID itself, everywhere**: it's in the URL path, so it's in
  edge access logs, the app's own log line, and any APM/tracing tool that
  auto-instruments HTTP routes. An account ID is not itself the confidential
  fields (name/IBAN/etc.), but it is a pointer to them, and anyone with log
  access can pivot from account ID to a DB lookup if they also have DB
  access. This is accepted risk: fixing it means either not putting the ID
  in the URL (a bigger API design change, out of scope for this take-home)
  or redacting URLs at the edge (breaks operational debugging).
- **Downstream/dependency logging we don't control**: the Postgres driver,
  the AWS SDK, and any HTTP client library used to call the KYC provider
  may log request/response bodies at DEBUG level if that log level is ever
  enabled in production (misconfiguration, not by design). Nothing in this
  repo structurally prevents someone from flipping a library's log level
  and reintroducing a body-dump. The compensating control is that
  production log level is fixed at INFO by the deployment config, not by
  a code-level guarantee — a real gap if someone changes that config
  without review.
- **The KYC provider call itself**: whatever this service sends to the
  third party (likely including name, DOB, or ID document data for a KYC
  check) is logged by *their* systems under *their* redaction policy, which
  this repository has no visibility into or control over. Egress control
  (Section 5) restricts *where* that data can go; it says nothing about what
  the KYC vendor does with it once it arrives.
- **Panic/crash output**: Go's default panic handler prints a stack trace,
  which can include local variable values depending on where the panic
  occurs. If a panic happens inside the request handler with the account
  struct in scope, a crash log could contain PII that the normal log path
  would never emit. This service does not currently wrap the handler in a
  recover() that scrubs the panic payload before logging it — a real,
  named gap, and the first thing to fix in a real rollout (see
  DECISIONS-TRADEOFFS.md "what you cut").

## One line on encryption

Data in transit is TLS (ALB/CloudFront termination, platform-owned) and
data at rest is `storage_encrypted = true` on RDS with a customer-managed
KMS CMK (`terraform/rds.tf`) plus SSE-KMS on the CloudTrail/audit bucket
(`terraform/cloudtrail.tf`) — the CMK key-custody model means the bank
controls the key policy and can revoke/rotate independent of AWS, which is
the threat this addresses: a snapshot, backup, or bucket-policy mistake
exposing data still requires the CMK to read it, not just the storage
itself.
