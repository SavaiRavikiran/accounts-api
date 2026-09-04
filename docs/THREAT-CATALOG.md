# Threat catalog (backing detail)

> This is the full STRIDE working catalog behind [THREAT-MODEL.md](THREAT-MODEL.md)
> — the one-page required deliverable. It exists because ADRs and policy
> comments throughout this repo cite `T-01`…`T-16` and need a definition to
> point at; it is deliberately **not** the graded threat-model artefact.

# Threat model: accounts-api

**System:** containerised `accounts-api` on Kubernetes  
**Context:** regulated digital bank (retail account data, auditability, least privilege)  
**Method:** asset-first STRIDE, plus supply-chain and insider paths that matter in a bank  
**Scope:** the service, its pipeline, cluster identity/secrets, and the controls that protect them  
**Out of scope:** core banking ledger, card processing, physical branches, customer-device malware

Every control in this repository maps to a named threat below. Residual risk is called out in [DECISIONS.md](../DECISIONS.md).

## Assets

| ID | Asset | Sensitivity | Why it matters |
| --- | --- | --- | --- |
| A-01 | Account records (balances, account numbers, customer identifiers) | Confidential / integrity-critical | Direct regulatory and fraud impact |
| A-02 | Runtime secrets (DB credentials, API keys, signing material) | Secret | Compromise equals data access |
| A-03 | Workload identity (K8s SA + cloud IAM) | Secret | Identity is the new perimeter |
| A-04 | Container image and SBOM | Integrity | What runs in prod is the control boundary |
| A-05 | CI/CD credentials and workflows | Secret / integrity | Pipeline is a privileged production path |
| A-06 | Audit logs | Integrity / availability | Required for investigation and regulators |
| A-07 | Cluster control plane and admission | Integrity | Misconfig here bypasses every workload control |

## Trust boundaries

```
 Internet
    |
    |  TLS terminate + WAF (platform, out of repo)
    v
 [Ingress] ---- NetworkPolicy ---- [accounts-api pod]
                                      |
                                      | IRSA / projected SA token
                                      v
                               [Cloud IAM + KMS]
                                      |
                                      v
                               [Secrets Manager / DB]
```

Additional boundaries: developer laptop → git; git → CI runners; CI → registry; registry → kubelet.

## Actors

- **Customer** — authenticated account holder (API consumer).
- **Platform operator** — cluster/CI admin (high privilege, trusted but must be constrained).
- **External attacker** — unauthenticated or stolen-credential adversary.
- **Malicious or compromised insider** — developer or operator who can open PRs or exec into clusters.
- **Compromised dependency / build** — tainted library, base image, or CI action.

## Threat catalog

| ID | STRIDE | Threat | Asset | Attack path | Controls in this repo |
| --- | --- | --- | --- | --- | --- |
| T-01 | Spoofing | Stolen or minted workload identity used to call cloud APIs | A-03 | Pod escape or leaked SA token → assume IRSA role | Dedicated SA, no token automount on unrelated pods, IRSA trust scoped to one SA, deny `cluster-admin` bindings |
| T-02 | Tampering | Poisoned image or unsigned image reaches the cluster | A-04 | Compromised registry tag, `latest`, or mutable digest | Digest-pinned images, deny `:latest`, Cosign verify in CI, Kyverno/admission require signed images |
| T-03 | Tampering | Malicious PR changes prod manifests or pipeline | A-05 | Unreviewed workflow or unprotected `main` | CODEOWNERS, required reviews (process), Conftest + Checkov gates on every PR |
| T-04 | Repudiation | Actions against accounts cannot be attributed | A-06 | Shared identities, no structured audit | App structured logs without secrets, CloudWatch log group KMS + retention, immutable S3 audit bucket |
| T-05 | Information disclosure | Secrets in git, images, logs, or env literals | A-02 | `.env` committed, `env.value` passwords, debug logs | No secret literals in manifests (policy), External Secrets, KMS, Dockerfile/gitignore hygiene, log redaction |
| T-06 | Information disclosure | Lateral movement reads account data from another namespace | A-01 | Compromised neighbour pod → cluster network | Default-deny NetworkPolicy, namespace isolation, egress allow-list |
| T-07 | Denial of service | Unbounded pod consumes node or starves API | A-01 | Missing limits, noisy neighbour, fork bomb | CPU/memory requests+limits required by policy, PDB, readiness/liveness probes |
| T-08 | Elevation of privilege | Privileged container or root + host mounts | A-07 | `privileged: true`, `hostPath`, added caps | PSS Restricted, drop ALL caps, non-root, read-only root FS, no hostPath (policy) |
| T-09 | Elevation of privilege | Over-broad RBAC lets a SA read all secrets | A-02 | `Role` with `secrets` get/list/* | Least-privilege Role (no secret list), no default SA |
| T-10 | Spoofing | Long-lived cloud keys in CI | A-05 | Leaked GitHub secret / AWS key | GitHub OIDC → cloud role (no static keys) |
| T-11 | Tampering | Vulnerable or unaudited dependency in the image | A-04 | Compromised npm/Go module or base CVE | Distroless image, `go.sum`, Trivy + gosec in CI, SBOM attached |
| T-12 | Information disclosure | Public cloud storage of logs or Terraform state | A-06 | Open S3, missing encryption | Public-access block, SSE-KMS, versioning, Checkov + Conftest on Terraform |
| T-13 | Tampering | Admission bypass via privileged namespace or policy exception | A-07 | Unlabelled namespace, missing Kyverno | Namespace labels, Kyverno ClusterPolicies, CI still enforces same rules |
| T-14 | Information disclosure | Account PII in application logs or error payloads | A-01 | Verbose errors, request body logging | Structured logs, no request-body dump, generic client errors |
| T-15 | Elevation of privilege | Writable root filesystem used to drop a backdoor | A-04 | RCE → write binary to `/` | `readOnlyRootFilesystem`, emptyDir for tmp, policy deny |
| T-16 | Spoofing | Unauthenticated or weakly authenticated API access | A-01 | Missing authn on account routes | Authn middleware stub + fail-closed design (see decisions); mTLS/OIDC at ingress is platform) |

## What we deliberately did not model as in-scope threats

- Card-present / ATM fraud — different system.
- Quantum cryptanalysis of TLS — not a near-term control decision for this service.
- Availability of the managed Kubernetes control plane — accepted as a platform residual; we add PDB and probes only.

## Abuse cases (reviewer shortcut)

1. **Stolen CI OIDC role** → can push an image; Cosign + admission + digest pin still required to run.
2. **RCE in accounts-api** → non-root, no caps, read-only FS, no secret files on disk, NetworkPolicy blocks sweep.
3. **Malicious internal PR** → Conftest/Checkov fail the build; CODEOWNERS blocks silent policy weakening.
