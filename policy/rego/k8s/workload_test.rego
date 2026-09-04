package main

# opa test policy/rego/k8s
# These mirror tests/fixture-bad.yaml and tests/fixture-good-deployment.yaml;
# `conftest test -p policy/rego/k8s policy/rego/k8s/tests/*.yaml` exercises the real files.

bad_deployment := {
	"kind": "Deployment",
	"spec": {"template": {"spec": {
		"hostNetwork": true,
		"volumes": [{"name": "docker-sock", "hostPath": {"path": "/var/run/docker.sock"}}],
		"containers": [{
			"name": "api",
			"image": "123456789012.dkr.ecr.ap-south-1.amazonaws.com/accounts-api:latest",
			"securityContext": {"privileged": false, "runAsUser": 0},
		}],
	}}},
}

good_deployment := {
	"kind": "Deployment",
	"spec": {"template": {"spec": {
		"hostNetwork": false,
		"volumes": [{"name": "tmp", "emptyDir": {}}],
		"containers": [{
			"name": "accounts-api",
			"image": "ghcr.io/digitalbank/accounts-api:0.1.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"securityContext": {
				"privileged": false,
				"runAsNonRoot": true,
				"runAsUser": 65532,
				"readOnlyRootFilesystem": true,
				"allowPrivilegeEscalation": false,
				"capabilities": {"drop": ["ALL"]},
			},
		}],
	}}},
}

test_bad_deployment_denied_hostnetwork {
	count(deny) > 0 with input as bad_deployment
}

test_bad_deployment_denied_hostpath {
	msgs := deny with input as bad_deployment
	some msg in msgs
	contains(msg, "hostPath")
}

test_bad_deployment_denied_root_user {
	msgs := deny with input as bad_deployment
	some msg in msgs
	contains(msg, "runAsUser: 0")
}

test_bad_deployment_denied_latest_tag {
	msgs := deny with input as bad_deployment
	some msg in msgs
	contains(msg, "latest")
}

test_good_deployment_has_no_denies {
	count(deny) == 0 with input as good_deployment
}
