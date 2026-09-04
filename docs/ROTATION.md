# Section 6 — Secret rotation

## Credentials this service holds

| Credential | Source of truth | Delivery path |
| --- | --- | --- |
| RDS master/app credential | AWS Secrets Manager (AWS-managed, see `terraform/rds.tf`'s `manage_master_user_password`) | Secrets Manager → External Secrets Operator ([`k8s/externalsecret.yaml`](../k8s/externalsecret.yaml)) → K8s `Secret` → mounted file at `/var/run/secrets/app/db-url` (never an env var — ADR-003) |
| KYC provider API key | Secrets Manager, entered by the platform team out of band (third party doesn't support AWS-native rotation) | Same ESO path, different `remoteRef.key` |
| Pod's own AWS identity | IRSA — not a stored credential at all; the projected service-account JWT is exchanged for temporary STS credentials by AWS, refreshed automatically every hour by the SDK/EKS pod identity webhook | N/A — nothing to rotate, nothing to leak to disk |

No plaintext credential appears in git, in a committed manifest, or in a
GitHub Actions secret for this service. Terraform stores secret *containers*
(the Secrets Manager resource and KMS key), never secret *values*.

## Rotation mechanism and interval

- **RDS credential**: AWS-managed rotation via Secrets Manager, 30-day
  interval (`manage_master_user_password` handles the Lambda + RDS API calls
  natively — no custom rotation Lambda to maintain). ESO's `refreshInterval:
  1h` on the `ExternalSecret` means the in-cluster copy is at most an hour
  stale relative to Secrets Manager.
- **KYC provider key**: no vendor-side rotation API, so this is manual —
  90-day interval, tracked as a recurring calendar task owned by the
  platform team, executed by generating a new key in the vendor portal,
  writing it to Secrets Manager, confirming ESO has synced (`kubectl get
  externalsecret -n accounts`), then revoking the old key at the vendor.
- **Pod AWS identity (IRSA)**: rotates itself hourly; nothing to schedule.

## Target time to rotate every credential during an active incident

**Target: under 10 minutes for the RDS credential, under 15 for the KYC key.**

Scheduled rotation above is designed for the calm case. During an incident
(suspected credential compromise — e.g. the Falco rule in
[`falco/accounts-api-rule.yaml`](../falco/accounts-api-rule.yaml) fires), waiting
for the next scheduled window is not acceptable. The emergency path:

1. **RDS credential**: `aws secretsmanager rotate-secret --secret-id
   <arn> --rotate-immediately` triggers Secrets Manager's rotation Lambda
   on demand instead of on schedule. This typically completes (new
   password set on the RDS instance, new version stored) in 1–3 minutes.
   ESO's 1-hour refresh interval is now the bottleneck — for an incident,
   the responder forces a pull with `kubectl annotate externalsecret
   accounts-api -n accounts force-sync=$(date +%s) --overwrite`, which ESO
   treats as a resync trigger, then restarts the deployment
   (`kubectl rollout restart deployment/accounts-api -n accounts`) so pods
   pick up the new mounted secret immediately rather than waiting for the
   volume's own propagation delay. End to end: under 10 minutes, most of
   it Kubernetes pod restart time, not the credential rotation itself.
2. **KYC provider key**: no API-driven rotation, so the incident-time
   version is the same manual steps as scheduled rotation, just done
   immediately instead of on the 90-day calendar — realistically 10–15
   minutes because it involves a human logging into a third-party portal.
   This is the weakest link in the "minutes not schedule" target, and it's
   weak because it depends on a vendor capability we don't control, not
   because of anything in this design.
3. **IRSA/pod identity**: nothing to do — already short-lived (1 hour) and
   cannot be "rotated early" in a meaningful sense; if the node or pod
   itself is compromised, the actual response is pod/node isolation (see
   the Falco runbook), not credential rotation.

**Honesty note:** the KYC key's manual step is the actual bottleneck against
the "minutes" target, and no control in this repository closes that gap — it
would need the vendor to offer a rotation API, which is outside this
system's control.
