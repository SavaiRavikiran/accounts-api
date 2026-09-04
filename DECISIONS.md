# Decisions

Architecture Decision Records for `accounts-api`. Each decision names the threats it addresses. If a control does not map to a threat, the reason is stated.

## ADR-001 — Policy as code is the reviewable control plane

**Status:** accepted  
**Threats:** T-02, T-03, T-08, T-09, T-13, T-15

We enforce the same rules twice:

1. **CI (Conftest / OPA)** — fails the PR before merge. Reviewers run `make policy-test`.
2. **Cluster (Kyverno)** — fails admission if something is applied out of band.

Shift-left alone is not enough (someone with `kubectl` can still apply YAML). Admission alone is not enough (feedback arrives too late and is hard to unit-test). Duplicating the *intent* in two engines is deliberate, not accidental drift: Conftest tests are the source of truth for reviewers; Kyverno is the runtime backstop.

We chose Conftest over a custom script so policies are data-driven Rego and have first-class unit tests.

## ADR-002 — Distroless, non-root, read-only, digest-pinned images

**Status:** accepted  
**Threats:** T-02, T-08, T-11, T-15

- Multi-stage Go build → `gcr.io/distroless/static-debian12:nonroot`.
- No shell in the runtime image (shrinks post-exploitation).
- Image references in Kubernetes use a digest placeholder; CI must rewrite tags to digests.
- `:latest` is denied by policy.

Chainguard images would be preferable in a real bank (SBOMs + signatures from the vendor). Distroless is used here so the build is reproducible without a paid registry.

## ADR-003 — Secrets never appear as env literals or in git

**Status:** accepted  
**Threats:** T-05, T-09, T-12

- Kubernetes manifests pull secrets via External Secrets Operator from AWS Secrets Manager.
- Encryption at rest is a CMK we own (`aws_kms_key.secrets`).
- Terraform does not store secret *values*; it stores secret *containers*.
- App reads `ACCOUNTS_DB_URL` from the filesystem (`/var/run/secrets/app/db-url`) rather than the process environment, reducing accidental dump via `/proc` and crash reports.

Vault would also be valid. Secrets Manager + ESO was chosen because it matches a typical AWS-hosted bank landing zone and keeps the IAM story (IRSA) in one cloud.

## ADR-004 — Workload identity via IRSA, not static keys

**Status:** accepted  
**Threats:** T-01, T-10

- The pod uses a dedicated ServiceAccount.
- AWS IAM role trust is conditioned on that SA (`system:serviceaccount:accounts:accounts-api`).
- GitHub Actions assumes a *separate* deploy role via OIDC. CI cannot call the database role; the pod cannot push images.

This is the highest-leverage identity control in the repo. Long-lived `AWS_ACCESS_KEY_ID` in GitHub secrets is treated as a finding, not a convenience.

## ADR-005 — Default-deny NetworkPolicy with an egress allow-list

**Status:** accepted  
**Threats:** T-06

Ingress: only from the ingress controller namespace.  
Egress: DNS, HTTPS to the cloud APIs / database CIDR. No intra-cluster east-west except what we name.

A service mesh (mTLS) would add encryption in transit between pods. We did **not** add Linkerd/Istio in this take-home: it is a platform decision, it doubles the operational surface, and NetworkPolicy already expresses the threat we named (lateral movement). If a mesh already exists in the bank, attach this workload to it — that control would then map to T-06 and T-16.

## ADR-006 — Restricted Pod Security + explicit securityContext

**Status:** accepted  
**Threats:** T-08, T-15

Namespace label `pod-security.kubernetes.io/enforce=restricted` plus an identical `securityContext` on the Pod and container. Policy fails closed if either is missing. We do not rely on the label alone (older clusters, exemptions).

## ADR-007 — CI is a gate, not a notifier

**Status:** accepted  
**Threats:** T-02, T-03, T-10, T-11

Pipeline on every pull request:

| Gate | Tool | Fail closed? |
| --- | --- | --- |
| Policy unit tests + manifest test | Conftest | Yes |
| Terraform | Checkov + Conftest | Yes |
| Go tests + gosec | `go test`, gosec | Yes |
| Filesystem CVE + misconfig | Trivy fs | Yes (HIGH/CRITICAL) |
| Image CVE | Trivy image | Yes (HIGH/CRITICAL) |
| SBOM | Syft | Produce-only (see below) |
| Image signature | Cosign keyless | Documented; requires registry OIDC in a real org |

SBOM generation does not fail the build: an SBOM is evidence, not a control. The control is Trivy against that SBOM/image. We still generate the SBOM so incident response can answer "what shipped?"

## ADR-008 — Terraform manages identity, encryption, and audit — not the app runtime

**Status:** accepted  
**Threats:** T-01, T-04, T-05, T-12

Kubernetes YAML is the workload interface (reviewed by app + platform). Terraform owns:

- KMS CMKs
- Secrets Manager skeleton
- IRSA roles and trust
- GitHub OIDC provider + CI role
- Encrypted, private, versioned audit bucket and log group

We did **not** put EKS itself in this repo. Cluster landing-zone modules are a platform team product; embedding a toy EKS module would pretend we own a control we do not.

## ADR-009 — Authentication is fail-closed, but full IdP integration is not faked

**Status:** accepted  
**Threats:** T-16

The API requires `Authorization: Bearer` on `/accounts/*` and rejects missing/invalid tokens. It does **not** implement a home-grown JWT stack or embed a real bank IdP. In production this is a platform sidecar or API gateway (OIDC + mTLS).

Building a toy JWT issuer would create a *false* control that does not map to how a bank actually authenticates. The threat is named; the durable control is gateway/mesh policy. The in-repo middleware exists so the binary is not an open data store if someone port-forwards the pod.

## ADR-010 — Controls we did not build (and why)

These are common checklist items we left out on purpose:

| Control | Why not | Threat still covered by |
| --- | --- | --- |
| Full service mesh | Platform-owned; high cost for a single service | T-06 NetworkPolicy |
| WAF / DDoS | Edge platform; not an app-repo artefact | T-16 (gateway) + platform |
| PCI DSS RoC evidence pack | Organisational process, not a YAML file | T-04, T-05 audit + secrets |
| Runtime EDR / falco rules | Valuable; needs a deployed agent we cannot assume | T-08 hardening reduces need |
| Multi-region active-active | Availability programme, not a named confidentiality threat | — |
| Honeypot / deception | Does not map to a named threat in this model | — |

No control in this repository is decorative. If a reviewer finds one that does not map to T-01–T-16, that is a defect in the decisions document — call it out.
