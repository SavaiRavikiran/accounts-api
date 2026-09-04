# Section 2 — Build and release integrity

## Registry choice

Pipeline pushes to `ghcr.io` (free, no cloud account needed to validate this
take-home). **AWS mapping:** production would push to ECR in a dedicated
"artifact" account, pulled cross-account by the workload accounts. One line:
same controls (digest pinning, signature verification, tag immutability)
exist in both; ECR's are just IAM-native instead of GitHub-native.

## Immutable tags — how we prevent tag mutation

Two independent mechanisms, because neither alone is sufficient:

1. **The tag itself never repeats.** [`build-release.yml`](../.github/workflows/build-release.yml)
   derives the tag from the commit SHA (`sha-<12 chars>`), so the same tag is
   never pushed twice for different content by *this pipeline*. This doesn't
   stop someone with registry push access from retagging out-of-band.
2. **Registry-enforced immutability** — the actual control. On ECR: enable
   `imageTagMutability = IMMUTABLE` on the repository (a one-line Terraform
   attribute we'd add to the ECR module in the real landing zone; not
   authored here since this repo doesn't own the registry resource). On
   GHCR: package tag protection rules restrict who can push to a given tag
   pattern. Either way, everything downstream of the registry (Kyverno's
   `verifyImages`, the deploy step) references the **digest**, not the tag,
   so even a mutability gap in the registry doesn't let a retag silently
   change what's already been verified and deployed.

## OIDC scoping

Trust policy: [`oidc/trust-policy.json`](../oidc/trust-policy.json).

The `sub` claim is scoped to
`repo:digitalbank/accounts-api:ref:refs/heads/main` for the deploy role (not
`repo:digitalbank/accounts-api:*`, and not `repo:digitalbank/*`).

**What this denies:** a workflow run on any branch other than `main` —
including a PR from a fork, a feature branch, or a `pull_request` event
triggered by an unreviewed change — cannot assume the deploy role. Someone
who compromises a feature branch or opens a malicious PR (T-03) gets a build
that still runs in CI, but it cannot obtain AWS credentials to deploy or
touch production infrastructure. It does **not** deny a compromise of `main`
itself (e.g. a merged malicious PR, or a maintainer account takeover) — see
`DECISIONS-TRADEOFFS.md` blast-radius scenario (b) for what that path
actually reaches and what evidence exists afterwards.

## What the signature proves and does not prove

**Proves:** this exact image digest was produced by the
`build-release.yml` workflow, running on the `main` branch of
`digitalbank/accounts-api`, at the commit recorded in the Rekor transparency
log entry. Anyone can verify this offline against Sigstore's public log —
no shared secret required.

**Does not prove:**
- That the source code is free of vulnerabilities or backdoors — a
  maliciously merged PR (T-03) would be signed just as validly as any other
  commit. The signature attests to *provenance*, not *safety*; Section 3's
  scanners are what attest to safety, and they run *before* this workflow
  by design (this workflow only runs on push to `main`, after PR gates).
- That the base image or a transitive dependency wasn't already compromised
  upstream (a poisoned `golang:1.22-bookworm` base, for instance) — the SBOM
  attestation gives us the *list* of what's inside so a later disclosure
  (e.g. a base-image CVE) can be matched against every image we've shipped,
  but the signature itself doesn't detect that at build time.
- That the running pod in the cluster is actually this image — that's what
  Kyverno's `verifyImages` admission check enforces at the other end; the
  signature is necessary but not sufficient without an admission-time check
  binding the two together.

A reviewer who reads this signature as "this code is safe" is over-reading
it. It answers "did our pipeline build this, unmodified, from this ref" —
nothing about the code's own correctness.
