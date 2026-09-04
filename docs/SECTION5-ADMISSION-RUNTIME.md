# Section 5 — Admission and runtime

## Rollout posture (day one → enforce)

The cluster is shared with ~a dozen other teams' services and there is no dedicated
security team, so a policy that flips straight to `Enforce` is a platform-team
outage waiting to happen. Posture:

| Policy | Day-one mode | Promotion trigger |
| --- | --- | --- |
| `disallow-host-namespaces-and-hostpath` | Audit | Zero violations across all namespaces for 14 consecutive days in the Kyverno policy-report, confirmed with the two other teams whose services still show violations |
| `require-restricted-securitycontext` | Audit | Same — this is the rule most likely to break existing workloads (non-root, read-only FS); needs a migration window and owning-team sign-off per namespace |
| `disallow-latest-and-require-digest` | Audit | Promote as soon as CI (Section 2) is rewriting tags to digests for `accounts-api`; other teams promote on their own timeline once their pipelines do the same |
| `require-resource-limits` | Audit | Promote once the platform team has billed/alerted on the top offenders — flipping to Enforce without warning teams first breaks their next deploy |
| `verify-image-signature` | **Enforce, day one, `accounts` namespace only** | N/A — see below |

**Why `verify-image-signature` is the one exception:** it is scoped to a single
namespace we own (`accounts`), it does not touch any other team's workload, and an
unsigned image reaching this namespace is the exact T-02 supply-chain threat this
whole submission is built around. Every other policy above is a cluster-wide
change with a blast radius outside this team's control, which is why they start
in Audit — the evidence bar for promotion is "no surprise breakage for the other
eleven teams," not "our own service passes."

**Evidence for promotion**, concretely: the Kyverno `PolicyReport`/`ClusterPolicyReport`
objects (`kubectl get policyreport -A`) show `pass` for every workload for the
soak period above. That report is also what gets attached to the change-ticket
that flips `validationFailureAction` to `Enforce`.

## Runtime detection — custom Falco rule

`accounts-api` reads a mounted secret file at `/var/run/secrets/app/db-url` and
otherwise has no reason to touch the filesystem outside `/tmp`. The generic
Falco ruleset's "Read sensitive file" rules are tuned for `/etc/shadow`-style
paths and won't fire on this. The rule below is specific to this workload:
anything reading that secret file *after* process start (i.e. not the Go
runtime's own startup read) means the container has been used to exfiltrate
the DB credential a second way — env dump, backup script, or an attacker
process — which is exactly the T-05 path this container is designed to close
off everywhere else.

See [`falco/accounts-api-rule.yaml`](../falco/accounts-api-rule.yaml) for the rule,
alert payload shape, routing, on-call owner, and the three-step runbook.

## Egress control

`accounts-api` legitimately calls exactly one external destination: the KYC
provider over HTTPS. See [`egress/README.md`](../egress/EGRESS.md) and
[`egress/networkpolicy-l3.yaml`](../egress/networkpolicy-l3.yaml) /
[`egress/ciliumnetworkpolicy-l7.yaml`](../egress/ciliumnetworkpolicy-l7.yaml)
for the two layers implemented and what each still fails to stop.
