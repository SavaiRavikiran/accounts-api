# accounts-api security submission

Senior DevSecOps take-home: securing `accounts-api`, a containerised REST
service on EKS handling customer account PII/IBAN/card-last-4. This repo
contains the build artefacts (Part 1) and the reasoning document (Part 2).

No cloud account, cluster, or paid service is required to review this. Every
"apply"/"deploy"/"kyverno test" style command below is what a reviewer
*would* run with the tool installed; where I could not run a tool in this
environment (no `kyverno`, `terraform`, `conftest`, `checkov`, `cosign`
binaries available locally), the relevant doc says so explicitly rather than
claiming a result I didn't produce. What I *did* validate locally:
every YAML/JSON file in this repo parses (`python3 -c "yaml.safe_load_all(...)"`,
`json.load(...)`), and the waiver mechanism's shell script is executed and
shown failing/passing against fixtures (see below — this one you can run
right now with nothing installed but bash).

## Start here

1. [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — the one-page required
   threat model. [`docs/THREAT-CATALOG.md`](docs/THREAT-CATALOG.md) is the
   full STRIDE working notes it's drawn from (referenced as `T-01`…`T-16`
   throughout the repo).
2. [`DECISIONS.md`](DECISIONS.md) — architecture decision records, each
   tagged with the threat IDs it addresses.
3. [`docs/DECISIONS-TRADEOFFS.md`](docs/DECISIONS-TRADEOFFS.md) — Part 2:
   biggest decisions, enforcement posture, blast-radius scenarios,
   detection gap, regulatory framing, what was cut.

## Repo layout → assessment section

| Section | Where |
| --- | --- |
| 1. Threat model | `docs/THREAT-MODEL.md`, `docs/THREAT-CATALOG.md` |
| 2. Build/release integrity | `.github/workflows/build-release.yml`, `oidc/trust-policy.json`, `terraform/oidc.tf`, `docs/SECTION2-SUPPLY-CHAIN.md` |
| 3. Pipeline gates + waivers | `.github/workflows/pipeline-gates.yml`, `.github/workflows/waiver-audit.yml`, `waivers/`, `scripts/check-waivers.sh`, `docs/BREAK-GLASS.md` |
| 4. Review and remediate | `docs/SECTION4-REMEDIATION.md`, `k8s/original/`, `k8s/deployment.yaml` + `k8s/rbac.yaml`, `terraform/original/vulnerable.tf` + `terraform/rds.tf`/`security_group.tf`/`cloudtrail.tf`, `iam/original-pod-identity-policy.json` + `iam/pod-identity-policy.json`, `policy/rego/` |
| 5. Admission and runtime | `admission/kyverno/`, `falco/accounts-api-rule.yaml`, `egress/`, `docs/SECTION5-ADMISSION-RUNTIME.md` |
| 6. Secrets and data protection | `k8s/externalsecret.yaml`, `docs/ROTATION.md`, `docs/LOG-REDACTION.md` |
| Part 2. Decisions and trade-offs | `docs/DECISIONS-TRADEOFFS.md` |

## Tool substitutions (open-source, justified inline where used)

- **Registry:** ghcr.io instead of ECR (no cloud account needed to validate;
  mapping to ECR documented in `docs/SECTION2-SUPPLY-CHAIN.md`).
- **SBOM:** Syft, attested via GitHub's native attestation (Sigstore-backed),
  not dropped as a build-log artifact.
- **Signing:** Cosign, keyless (Sigstore Fulcio/Rekor) — no key custody
  burden on a 2-person platform team; justified in `docs/SECTION2-SUPPLY-CHAIN.md`.
- **SCA + IaC misconfig:** Trivy (one tool, two jobs — consolidation
  trade-off stated in `pipeline-gates.yml`'s header comment).
- **SAST:** Semgrep (`p/golang`, `p/security-audit`).
- **Secret scan:** Gitleaks, full git history (`fetch-depth: 0`), not diff-only.
- **IaC-specific depth:** Checkov, alongside a custom Conftest/Rego layer
  for the exact defects named in Section 4.
- **Admission:** Kyverno (YAML-native policies, no separate constraint
  templates to author, matches the "2 platform engineers" staffing reality).
- **Runtime detection:** Falco, one custom rule specific to this workload
  (not the default ruleset).
- **Egress L7:** Cilium `CiliumNetworkPolicy` — assumption stated in
  `egress/EGRESS.md` about which CNI the real cluster runs, with a named
  fallback (proxy/NAT gateway) if it's wrong.

## How to actually run the policy tests

```bash
# Waiver mechanism — runs right now, no tools to install:
bash scripts/check-waivers.sh scripts/test-fixtures/expired-waivers   # exits 1 (fails build)
bash scripts/check-waivers.sh scripts/test-fixtures/valid-waivers     # exits 0 (passes)
bash scripts/check-waivers.sh waivers                                 # the real waiver dir, exits 0 today
```

```bash
# Kubernetes/RBAC policy-as-code (OPA/Conftest), against fixtures for the
# Section 4 manifest (bad = as-provided, good = fixed):
brew install opa conftest   # or: go install github.com/open-policy-agent/opa@latest
opa test policy/rego/k8s               # unit tests, inline mock input — no CLI beyond opa needed
conftest test -p policy/rego/k8s policy/rego/k8s/tests/fixture-bad.yaml   # expect: FAIL
conftest test -p policy/rego/k8s policy/rego/k8s/tests/fixture-good-deployment.yaml  # expect: PASS
conftest test -p policy/rego/k8s policy/rego/k8s/tests/fixture-good-rbac.yaml        # expect: PASS
```

```bash
# Terraform IaC policy-as-code, against inline plan-JSON fixtures:
opa test policy/rego/terraform          # unit tests, bad_plan/good_plan fixtures inline

# Against the real Terraform (validate only — no apply, per the brief):
cd terraform && terraform init -backend=false && terraform validate
# Checkov, against the fixed config only (terraform/original is skipped, see .checkov.yml):
checkov -d terraform --config-file ../.checkov.yml
```

```bash
# Kyverno admission policy, against the same bad/good fixtures:
# (kyverno CLI was not available in this environment — I hand-verified the
#  expected results against the policy patterns; see the note at the top of
#  admission/kyverno/tests/kyverno-test.yaml.)
kyverno test admission/kyverno/tests
```

```bash
# Cosign signature verification (once an image has actually been built and
# signed by build-release.yml — not executed here, no registry push happened):
cosign verify --certificate-identity-regexp \
  "https://github.com/digitalbank/accounts-api/.github/workflows/build-release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/digitalbank/accounts-api@sha256:<digest>
```

## App

`app/` is a minimal Go service (not the real `accounts-api` — the brief says
assume it exists and is competent; this stand-in exists so the Dockerfile,
security context, and log-redaction claims have something concrete to point
at). `cd app && go test ./...` runs its one test file.

## Honesty summary (what wasn't executed)

- No real AWS account/cluster was used — Terraform is `validate`-only,
  Kubernetes manifests are `--dry-run`/policy-tested, not `kubectl apply`'d.
- No image was actually built/pushed/signed in this session — the pipeline
  YAML is authored and internally consistent, but `cosign verify` above has
  nothing real to verify against yet.
- `kyverno test`, `opa test`, `conftest test`, `terraform validate`, and
  `checkov` were authored but **not executed** in this environment — none of
  those binaries were available locally (verified with `which`). The Rego
  test files (`*_test.rego`) were written and hand-traced against the
  `deny` rules' logic, and the fixture YAML/JSON was checked for syntax
  validity (`python3 -c "yaml.safe_load_all(...)"` / `json.load(...)`
  across every file in the repo — all pass), but I have not seen `opa test`
  itself report green.
- The one thing I actually executed end-to-end in this session is
  `scripts/check-waivers.sh` against the expired/valid/real fixtures above
  — shown failing before, passing after, exactly as the waiver mechanism
  is supposed to behave. That's the graded claim I can stand behind without
  qualification; treat everything else in this list as authored-and-reasoned,
  not run-and-observed.
