# Waivers

A waiver suppresses one named finding from blocking a merge. It does not
suppress the finding from being reported — it only changes the merge gate's
verdict for that specific ID.

## Shape

One YAML file per waiver, in this directory, named `<finding-id>.yaml`:

```yaml
id: CVE-2024-XXXXX            # scanner finding ID or rule ID being waived
tool: trivy                   # trivy | semgrep | gitleaks | checkov
scope: app/go.sum              # file or path the waiver applies to
reason: >
  golang.org/x/net transitive dep flagged for a request-smuggling CVE in the
  HTTP/2 server path; accounts-api only uses this module's client-side DNS
  resolver, the vulnerable code path is never invoked. Confirmed by reading
  the vendored source at the pinned version.
requested_by: jdoe@digitalbank.com
approved_by: platform-lead@digitalbank.com   # must be in CODEOWNERS for /waivers
created: 2026-08-20
expires: 2026-09-20                          # hard cap: 30 days from creation
```

## Enforcement

- [`scripts/check-waivers.sh`](../scripts/check-waivers.sh) runs on every PR
  ([`pipeline-gates.yml`](../.github/workflows/pipeline-gates.yml)) and **fails
  the build** if any waiver file in this directory has an `expires` date in
  the past. There is no grace period — an expired waiver re-blocks the merge
  it was covering, on every PR, until someone either re-justifies it (new
  file, new 30-day clock, new approval) or the underlying finding is fixed.
- A daily scheduled job ([`.github/workflows/waiver-audit.yml`](../.github/workflows/waiver-audit.yml))
  runs the same check against `main` directly, independent of any PR, and
  opens/updates a tracking issue if something is about to lapse — so an
  expiring waiver surfaces even on a week with no PRs touching that code.
- **Who approves:** the `waivers/` path is a CODEOWNERS entry owned by the
  platform team (the 2 people in that role for this system). A waiver PR
  requires their review like any other change to `waivers/`; this is the
  "signed" part — GitHub's required-review + branch protection is the
  signature, rather than a detached PGP signature, because it's the
  mechanism already in place for every other merge and doesn't ask 40
  engineers to learn a new tool.
- **Max lifetime:** 30 days per waiver. A finding that still needs a waiver
  after 30 days needs a different conversation (accept the risk formally at
  the architecture-decision level, in DECISIONS.md, not via a renewed
  waiver file) — renewal-by-copy-paste is exactly the failure mode this
  mechanism exists to prevent.

## What happens when a waiver expires

The next PR gate run (or the daily audit) fails with a message naming the
expired file. The build stays red for *any* PR until the waiver is renewed
or removed — this is intentional: it forces the conversation back to the
platform team rather than letting an old risk-acceptance silently persist
forever.
