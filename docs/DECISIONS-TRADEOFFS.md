# Part 2 — Decisions and trade-offs

## 1. Biggest decisions

**a. Kyverno admission ships in `Audit` mode everywhere except image
signature verification (Enforce, day one, our namespace only).**
Trade-off: for weeks, a bad manifest can still reach the shared cluster if
someone bypasses CI. I accepted this because the cluster hosts a dozen
other teams' workloads I don't control, and flipping cluster-wide policy to
`Enforce` without their sign-off risks breaking their deploys, not just
ours — a platform-trust cost worse than the residual window. This is the
"chose not to enforce a control" answer: I did not enforce the workload
security baseline at admission time on day one, and the compensating
control is the identical rule already enforced pre-merge in CI (Conftest),
plus the one policy I judged low-blast-radius enough to enforce immediately.

**b. IRSA + OIDC over any form of static credential, everywhere.**
Trade-off: more moving parts to get right initially (trust policies, `sub`
claim scoping, ESO configuration) versus a GitHub secret or a mounted AWS
key file. I judged this the highest-leverage identity decision in the whole
system — a leaked static key has no expiry and no audit trail tying it to
a specific workflow run or pod; a leaked OIDC-derived credential is
short-lived and provably scoped to one `sub`.

**c. Two scanning tools, not six.** Trivy for SCA + IaC misconfig, Semgrep
for SAST, Gitleaks for secrets, Checkov for Terraform depth. Trade-off:
consolidation means gaps a specialist tool might catch (Snyk's dependency
graph, tfsec's Terraform-specific rule depth) go uncaught. I chose this
because 2 platform engineers cannot maintain trust in six dashboards, and a
pipeline nobody trusts gets its `continue-on-error` flipped within a month.

## 2. Enforcement posture

**Blocks on day one:** secret scan (full history), SCA/SAST at HIGH/CRITICAL,
Checkov/Conftest on Terraform, the waiver-expiry check, and
`verify-image-signature` in the `accounts` namespace only.

**Warns on day one:** every other Kyverno cluster policy (host namespaces,
restricted securityContext, latest-tag/digest, resource limits) — Audit
mode, visible in `PolicyReport`, not blocking.

**Sequence to promote a warning to a block:** per-policy, gated on a
14-day soak with zero violations across all namespaces sharing the cluster,
confirmed with the owning teams of any namespace still showing a violation,
then a platform-team change ticket flips `validationFailureAction` to
`Enforce`. Evidence a gate is ready: the `ClusterPolicyReport` shows
consistent `pass` for the soak window — not "our own service is clean,"
since that's not a claim about blast radius on teams we don't control.

## 3. Blast radius

**(a) `accounts-api` compromised via RCE.**
*Reaches:* the container's own filesystem (read-only, so no persistence
there), the mounted DB credential file, and whatever the pod's IRSA role
can do (scoped to one Secrets Manager path + one CMK — Section 4c). Network:
only DNS, the KYC provider FQDN, and Secrets Manager/STS endpoints — no
lateral reach to other namespaces (NetworkPolicy default-deny) and no node
access (no hostPath, no hostNetwork).
*Denied:* privilege escalation (`allowPrivilegeEscalation: false`, non-root,
all capabilities dropped), writing a persistent backdoor to disk
(`readOnlyRootFilesystem`), reading any secret but its own two
(IAM policy rewrite), reaching any other team's pod or the node's
container runtime.
*Evidence afterward:* the Falco rule fires if the credential file is read
a second time; CloudTrail (multi-region, log-validated) shows every
`secretsmanager:GetSecretValue`/`kms:Decrypt` call the stolen role made;
Kyverno's admission log shows what image was actually running.
*Where it goes dark:* application-level behavior that never touches a
logged AWS API or the flagged file path — e.g., if the RCE'd process only
ever calls the KYC provider (an already-allowed egress destination) to
exfiltrate data it read from its own in-memory account cache, nothing
here detects that. That's the gap named in Section 4.

**(b) A maintainer's GitHub account is taken over and a workflow file is
modified.**
*Reaches:* the ability to open/merge a PR to `main` as that maintainer, and
therefore to modify `.github/workflows/*`. If merged to `main`, the
modified `build-release.yml` runs with the deploy role's OIDC trust — the
`sub` claim is scoped to `ref:refs/heads/main`, which a merge to `main`
satisfies, so this path *does* reach the AWS deploy role.
*Denied:* the attacker cannot get there without a merge to `main` — branch
protection requires review, and CODEOWNERS on `waivers/` and (in a full
rollout) `.github/workflows/` would require a second platform-team
approval specifically for workflow changes, which I did not fully wire up
in this take-home (see "what you cut"). The OIDC scoping denies the same
attack from any branch that isn't `main`, which is most of the attack
surface for a one-off malicious PR that doesn't get reviewed carefully.
*Evidence afterward:* the git history shows the modified workflow file and
its author/committer; GitHub's audit log shows the account's session and
IP at time of merge; CloudTrail shows what the assumed deploy role actually
did with its (narrow) EKS permissions.
*Where it goes dark:* if the review that approved the malicious PR was
itself compromised (a second maintainer account, or a reviewer who
rubber-stamps), the "requires review" control provides no real friction —
this is a process control with a single point of failure I did not
compensate for further (e.g. required review from a *specific*
security-trained reviewer) because there is no dedicated security team to
be that reviewer.

## 4. Detection coverage gap

**Not currently detected:** slow, low-and-slow data exfiltration through the
one legitimately-allowed egress channel (the KYC provider call) by a
compromised `accounts-api` process stuffing extra customer fields into
otherwise-legitimate KYC check requests. Egress policy authenticates the
*destination*, not the *content* (see `egress/EGRESS.md`). Closing this
needs application-layer output validation (a schema the KYC request body
must match, rejecting anything with extra fields) or DLP on the egress
path — realistically a week of engineering plus buy-in from whoever owns
the KYC integration code, which is a bigger lift than anything else in this
submission and is why I named it instead of half-building it.

## 5. Regulatory framing

| Control | Regulatory obligation it serves |
| --- | --- |
| Multi-region CloudTrail, log-file validation, encrypted+versioned bucket | Audit trail integrity — investigators need tamper-evident logs across the whole org, not just one region |
| RDS not publicly accessible, ingress from app tier only, storage encrypted with a customer CMK | Cardholder/account-data scope reduction — narrows the network and cryptographic boundary a PCI/data-protection assessor has to examine |
| IAM least-privilege pod identity (scoped secret + CMK, no `NotAction` wildcard) | Access review — an auditor can enumerate exactly what this workload can touch, rather than "everything except two actions" |
| Waiver mechanism with hard 30-day expiry and named approver | Access/exception review cadence — regulators expect risk acceptances to be time-boxed and re-justified, not permanent |
| Falco rule + runbook with named on-call and audit trail | Breach notification readiness — a detected, timestamped, evidenced incident is what starts a defensible notification clock; undetected compromise doesn't |
| Backup retention (14 days) + deletion protection on RDS | Data retention / recoverability — a regulator asking "can you produce this customer's record from last week" needs this to be yes |

## 6. What I cut

Deprioritized for time, roughly in the order I'd pick them back up on a real
Monday:

1. **Panic-safe log scrubbing** (named in `docs/LOG-REDACTION.md`) — a
   `recover()` wrapper that redacts before logging on crash. Small, high
   value, cut only for time.
2. **CODEOWNERS enforcement on `.github/workflows/`** requiring a second
   platform-team approval specifically for workflow file changes — this is
   the actual mitigation for blast-radius scenario (b) above and I only
   partially designed it (waivers/ has it; workflows don't yet).
3. **A real Gatekeeper/Kyverno test run against a live `kind` cluster** —
   I authored `kyverno-test.yaml` and hand-verified the expected pass/fail
   against the policy patterns, but did not have the `kyverno` CLI
   available in this environment to execute it. This is a claim I'm not
   over-making: see the note at the top of that file.
4. **A service mesh for mTLS between `accounts-api` and its dependencies** —
   named in `DECISIONS.md` ADR-005 as a platform-level decision I'm
   deliberately not making unilaterally for one service.
5. **DLP/content inspection on the KYC egress path** — the detection gap
   named in section 4 above; the right fix here is bigger than this
   take-home's scope and I'd rather name it than half-build a regex-based
   DLP that gives false confidence.

First thing I'd implement in a real rollout on Monday: **(2), CODEOWNERS on
workflow files** — it's the cheapest of the five and it's the one that
directly closes the scenario I spent the most words on in Section 3
(blast radius of a compromised maintainer account).
