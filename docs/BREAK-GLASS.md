# Break-glass: production-down incident

Every gate in [`pipeline-gates.yml`](../.github/workflows/pipeline-gates.yml)
is a required status check on `main`'s branch protection. This is the one
sanctioned way to bypass it without disabling the check for everyone.

## Path

1. A platform-team member (one of the two named in this system's scope)
   applies the `break-glass` label to the PR. Applying that label is
   restricted to the `platform-team` GitHub team via a repo ruleset — an
   individual engineer cannot self-authorize.
2. A second required workflow, `break-glass-override.yml` (triggered by the
   label), re-runs only the gates that are structurally unsafe to skip
   entirely — secret scanning and the Kyverno/Conftest workload baseline —
   and force-passes the rest, but only for that one PR, only while the
   label is present, and only if the PR also carries an `incident:` prefix
   in its title referencing an incident ticket ID.
3. Merge proceeds. GitHub's own audit log records who applied the label,
   who approved and merged the PR, and the exact diff that shipped — this
   is not a gap in evidence, it is a different evidence trail (label +
   incident ticket + merge commit) instead of the normal one (green
   checks).
4. **Mandatory follow-up, enforced by process not tooling:** within 24
   hours, a follow-up PR re-runs the full, un-bypassed gate suite against
   the same commit. If it fails, that is now a normal red build on `main`
   and gets fixed like any other — the incident urgency that justified the
   bypass does not extend to leaving the bypassed finding unresolved.
5. The platform team reviews every break-glass usage at the next weekly
   sync; three uses in a quarter for the same recurring finding is treated
   as a signal that the gate's threshold or the service's architecture
   needs to change, not that break-glass needs to get easier to invoke.

## What this does not do

Break-glass does not bypass the OIDC deploy scoping (Section 2) or the
Kyverno `verify-image-signature` policy (Section 5) — those still require a
signed image built by the pipeline. An incident that requires shipping code
CI has never built (e.g. a hotfix applied directly with `kubectl edit`) is a
different, worse scenario than this one and is out of scope for a
"gate bypass" procedure — it's a break-glass *cluster access* procedure,
which this system does not separately define here (deprioritized — see
DECISIONS-TRADEOFFS.md "what you cut").
