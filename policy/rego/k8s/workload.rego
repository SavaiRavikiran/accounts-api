package main

# CI-side mirror of the Kyverno cluster policies (admission/kyverno/).
# Run with: conftest test -p policy/rego/k8s k8s/deployment.yaml
# Threats: T-08 (privilege escalation / host access), T-02 (mutable image tags).

deny[msg] {
	input.kind == "Deployment"
	pod := input.spec.template.spec
	pod.hostNetwork == true
	msg := "T-08: hostNetwork must not be true (shares node network namespace with every co-scheduled pod)"
}

deny[msg] {
	input.kind == "Deployment"
	pod := input.spec.template.spec
	vol := pod.volumes[_]
	vol.hostPath
	msg := sprintf("T-08: hostPath volume '%s' is not allowed (node filesystem / docker.sock escape)", [vol.name])
}

deny[msg] {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	c.securityContext.privileged == true
	msg := sprintf("T-08: container '%s' must not run privileged", [c.name])
}

deny[msg] {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	c.securityContext.runAsUser == 0
	msg := sprintf("T-08: container '%s' must not run as root (runAsUser: 0)", [c.name])
}

deny[msg] {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.runAsNonRoot == true
	msg := sprintf("T-08: container '%s' must set securityContext.runAsNonRoot: true", [c.name])
}

deny[msg] {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("T-15: container '%s' must set readOnlyRootFilesystem: true", [c.name])
}

deny[msg] {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	caps := c.securityContext.capabilities.drop
	not "ALL" in caps
	msg := sprintf("T-08: container '%s' must drop capability ALL", [c.name])
}

deny[msg] {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	endswith(c.image, ":latest")
	msg := sprintf("T-02: container '%s' image must not use the ':latest' tag", [c.name])
}

deny[msg] {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not contains(c.image, "@sha256:")
	msg := sprintf("T-02: container '%s' image must be pinned by digest (@sha256:...)", [c.name])
}
