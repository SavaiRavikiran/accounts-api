# Threat model: accounts-api (one page)

Full STRIDE working notes: [THREAT-CATALOG.md](THREAT-CATALOG.md) (`T-01`…`T-16`,
cited throughout this repo). This page is the graded artefact.

## Trust boundaries

```
 Internet
    |  TLS + WAF (CloudFront/ALB, platform-owned)
    v
 [Ingress] --NetworkPolicy--> [accounts-api pod] --IRSA--> [IAM/KMS] --> [Secrets Manager/RDS]
                                    |                                          ^
                                    +--- egress allow-list ---> [KYC provider (internet)]
                                    |
                              [message stream] --> audit records

 Developer laptop -> git (40 mergers) -> GitHub Actions (CI) -> ghcr.io/ECR -> EKS (shared, ~12 other teams)
```

## Top 5 threats, ranked by likelihood of actually materialising here

| # | Threat | Entry point → what's reached | Control in this submission / risk accepted |
| --- | --- | --- | --- |
| 1 | **Secret leaks via git, env vars, or logs** (T-05) | Any of 40 engineers commits a `.env`, a plaintext `password =` in Terraform, or the app logs a request body → DB credential or KYC key exposed | External Secrets Operator (no plaintext in manifests/git), Gitleaks on **full history** every PR, structured app logging that never emits the response body ([LOG-REDACTION.md](LOG-REDACTION.md)) |
| 2 | **Misconfigured workload gets RCE→full node/namespace compromise** (T-08/T-09) — exactly the Section 4 manifest | A shipped `hostNetwork`/`hostPath`/root-container/wildcard-RBAC manifest (as provided) → node escape, cross-tenant blast radius on a shared cluster | Kyverno admission baseline + identical Conftest CI gate, fixed manifest + RBAC, test fixtures proving both ([SECTION4-REMEDIATION.md](SECTION4-REMEDIATION.md)) |
| 3 | **Lateral movement from a neighbouring team's compromised pod** (T-06) | The cluster hosts ~12 other services; one gets popped, attacker pivots inside the cluster network to reach `accounts-api` or its DB | Default-deny NetworkPolicy, namespace isolation, FQDN-scoped egress. Accepted residual: no mTLS between pods (platform decision, not made here — [DECISIONS.md](../DECISIONS.md) ADR-005) |
| 4 | **Supply-chain: unsigned or mutable image reaches prod** (T-02) | `:latest` tag or a retagged digest slips through CI or gets applied out-of-band | Digest pinning, Cosign keyless signing + verification, Kyverno `verifyImages` enforced (not just audited) day one — the one policy I judged worth enforcing immediately |
| 5 | **Long-lived cloud credentials in CI leak** (T-10) | A GitHub secret holding a static `AWS_ACCESS_KEY_ID` is exfiltrated from a workflow log or a compromised Action | GitHub OIDC only, no static keys, `sub` claim scoped to `ref:refs/heads/main` — denies any non-main branch/PR from assuming the deploy role |

## What's overrated here

**A sophisticated external attacker exploiting application-layer logic
(injection, business-logic abuse) directly over the internet.** This is the
default worry for "a bank's customer API," but `accounts-api` sits behind
CloudFront + ALB + WAF (platform-owned) and is described as "broadly
competent" — and every one of the top 5 above is cheaper for a real attacker
and doesn't require finding a novel app bug: a leaked secret, a bad
manifest, a neighbouring tenant, a poisoned image, or a leaked CI key all
get to the same data with far less effort than an internet-facing 0-day.
I did not spend this submission's budget on WAF tuning or deep app-layer
fuzzing; I spent it on identity, pipeline, and workload boundary controls,
where the actual foothold is more likely to come from.

## Deliberately out of scope

Core banking ledger, card processing, physical branches, customer-device
malware, quantum cryptanalysis of TLS, availability of the managed EKS
control plane (accepted as a platform residual; PDB + probes only).
