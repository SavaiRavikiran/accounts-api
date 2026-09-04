package main

# Threat: T-09 — over-broad RBAC on the workload's own Role.
# Run with: conftest test -p policy/rego/k8s k8s/rbac.yaml

deny[msg] {
	input.kind == "Role"
	rule := input.rules[_]
	rule.verbs[_] == "*"
	msg := sprintf("T-09: Role '%s' must not grant wildcard verbs ('*')", [input.metadata.name])
}

deny[msg] {
	input.kind == "Role"
	rule := input.rules[_]
	rule.resources[_] == "secrets"
	msg := sprintf("T-09: Role '%s' must not grant access to core 'secrets' — use External Secrets / mounted volumes instead", [input.metadata.name])
}
