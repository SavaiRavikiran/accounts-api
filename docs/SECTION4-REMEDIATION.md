# Section 4 — Review and remediate

Ranking is by exploitability in *this* environment (shared multi-tenant EKS cluster,
public internet-facing API, RDS holding PII/IBAN/card-last-4) — not raw CVSS.

## a. Workload manifest + RBAC — [`k8s/original/vulnerable-deployment.yaml`](../k8s/original/vulnerable-deployment.yaml)

| Rank | Defect | Why it's exploitable here | Fix |
| --- | --- | --- | --- |
| 1 | `hostNetwork: true` | Pod shares the node's network namespace — sees every other pod's traffic on that node (a dozen other teams' services), can bind to node ports, bypasses NetworkPolicy (which selects pod IPs). Single highest-leverage line in the file on a shared cluster. | Removed. |
| 2 | `docker.sock` hostPath mount | Container-to-node-root escape trivially: `docker run -v /:/host ... chroot /host`. From RCE in the app to full node compromise, then every pod scheduled on that node. | Removed entirely; no workload has a legitimate reason to talk to the node's container runtime. |
| 3 | RBAC `Role` with `resources: ["secrets", ...], verbs: ["*"]` | Any credential leaked from this pod (env var dump, SSRF into the API server) can read/write/delete every Secret in the namespace — not just its own — and delete other teams' pods/configmaps if co-located. Turns one RCE into a namespace-wide breach. | Scoped to `get` on a single named ConfigMap; no secrets access via RBAC at all — secrets arrive via ESO-managed Secret mounted as a volume, never read through the API by app code. |
| 4 | `runAsUser: 0` | Root inside the container. Combined with (1)+(2) this is how you'd actually pivot; alone, with everything else fixed, it's a smaller uplift (no added Linux capabilities, no privileged flag) but still removes a layer of defense-in-depth and fails PSS `restricted`. | `runAsNonRoot: true`, `runAsUser: 65532`, `readOnlyRootFilesystem: true`, `capabilities: drop: [ALL]`, `allowPrivilegeEscalation: false`. |
| 5 | `host-logs` hostPath (`/var/log`) | Read access to every process's logs on the node, including other tenants'. Lower severity than (2) — read, not write — but still a cross-tenant confidentiality break and an easy log-injection vector. | Removed; app logs to stdout, collected by the cluster's log agent instead. |
| 6 | `:latest` tag, mutable digest implied | Not itself a runtime compromise, but removes the ability to know what is running or to roll back precisely, and defeats image signing (you can't sign "latest" meaningfully). | Pinned to `repo:semver@sha256:<digest>`; CI rewrites the tag to a digest before deploy (Section 2). |

Fixed versions: [`k8s/deployment.yaml`](../k8s/deployment.yaml), [`k8s/rbac.yaml`](../k8s/rbac.yaml) (already in this repo, written before this remediation pass — same fix).

**Policy-as-code:** [`admission/kyverno/`](../admission/kyverno) (cluster admission) and [`policy/rego/k8s/`](../policy/rego/k8s) (CI/Conftest) — see Section 5. Test fixtures under `admission/kyverno/tests/` and `policy/rego/k8s/tests/` fail on the original manifest and pass on the fixed one.

## b. Terraform — [`terraform/original/vulnerable.tf`](../terraform/original/vulnerable.tf)

| Rank | Defect | Why it's exploitable here | Fix |
| --- | --- | --- | --- |
| 1 | SG ingress `0.0.0.0/0` on 5432 | Database is reachable from the entire internet on the Postgres port. Combined with (2) below this is a direct path to every customer record without ever touching the application. | Ingress restricted to the EKS node/pod security group only. |
| 2 | `publicly_accessible = true` | RDS gets a public endpoint/IP; the SG rule above is what actually opens the door but this is what puts a doorframe on the internet in the first place. Defense-in-depth failure stacked with (1). | `publicly_accessible = false`; DB lives in private subnets only. |
| 3 | `password = var.db_password` (plaintext variable) | Credential ends up in `.tfvars`, CI logs, or state file in cleartext; 40 engineers can merge, so this is a wide blast radius for a leaked secret. | Removed; RDS uses `manage_master_user_password = true` (AWS-managed rotation in Secrets Manager) — no password variable at all. |
| 4 | `storage_encrypted = false` | Data at rest (PII, IBAN, card-last-4) unencrypted; anyone with snapshot/volume access (cross-account mistake, misconfigured backup share) reads plaintext. | `storage_encrypted = true`, `kms_key_id = aws_kms_key.rds.arn` (customer-managed CMK). |
| 5 | `backup_retention_period = 0` | No point-in-time recovery; a destructive bug or ransomware-style delete is unrecoverable. Availability/integrity risk, not confidentiality, hence ranked below the direct-access defects. | `backup_retention_period = 14`, deletion protection enabled. |
| 6 | `skip_final_snapshot = true` | Same category as (5): an accidental `terraform destroy` loses the data permanently. | `skip_final_snapshot = false` for prod. |
| 7 | CloudTrail: single-region, no log validation, no global events | This is a detection/forensics gap, not a way in — ranked lowest because it doesn't let anyone reach data, but it means an org-wide compromise via IAM (global service) or a non-`ap-south-1` region goes unlogged, and logs that exist can be tampered with undetected. | `is_multi_region_trail = true`, `include_global_service_events = true`, `enable_log_file_validation = true`, delivered to an encrypted, versioned, access-blocked S3 bucket. |

Fixed versions: [`terraform/rds.tf`](../terraform/rds.tf), [`terraform/security_group.tf`](../terraform/security_group.tf), [`terraform/cloudtrail.tf`](../terraform/cloudtrail.tf).

**Policy-as-code:** [`policy/rego/terraform/`](../policy/rego/terraform) (Conftest against `terraform plan` JSON) with fixtures under `policy/rego/terraform/tests/` — see Section 3.

## c. IAM policy on the pod identity role — [`iam/original-pod-identity-policy.json`](../iam/original-pod-identity-policy.json)

| Rank | Defect | Why it's exploitable here | Fix |
| --- | --- | --- | --- |
| 1 | First statement: `NotAction` + `Resource: "*"` | `NotAction` is an allow-list of *everything except* two IAM actions — this grants the pod's role essentially every AWS API in the account (S3, EC2, IAM `Put*`/`Attach*`, KMS key policy changes, and note it can still `iam:CreateUser`/`iam:AttachUserPolicy` to mint a persistent backdoor identity, since only `Delete*` is excluded). On a compromised-via-RCE pod this is full account takeover, not "read a secret." Ranked first because it dwarfs everything else in the file. | Removed entirely. |
| 2 | `Resource: "*"` on `secretsmanager:GetSecretValue` / `kms:Decrypt` | Even in isolation (without statement 1) this lets the pod read every secret and decrypt with every key in the account — every other team's DB credentials, KYC provider keys, CI signing material — not just its own. | Scoped to `arn:...:secret:accounts-api/*` and a single named CMK, with a `kms:ViaService` condition so the Decrypt grant can't be used outside Secrets Manager. |

**Rewritten policy:** [`iam/pod-identity-policy.json`](../iam/pod-identity-policy.json).

**One line:** the rewrite denies the pod identity every AWS action outside reading its own two named secrets and decrypting via its own CMK through Secrets Manager — the original allowed near-total account control including the ability to create a persistent IAM backdoor.
