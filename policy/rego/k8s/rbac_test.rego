package main

bad_role := {
	"kind": "Role",
	"metadata": {"name": "accounts-api"},
	"rules": [{"apiGroups": [""], "resources": ["secrets", "pods", "configmaps"], "verbs": ["*"]}],
}

good_role := {
	"kind": "Role",
	"metadata": {"name": "accounts-api"},
	"rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["accounts-api"], "verbs": ["get"]}],
}

test_bad_role_denied_wildcard_verb {
	msgs := deny with input as bad_role
	some msg in msgs
	contains(msg, "wildcard verbs")
}

test_bad_role_denied_secrets_access {
	msgs := deny with input as bad_role
	some msg in msgs
	contains(msg, "secrets")
}

test_good_role_has_no_denies {
	count(deny) == 0 with input as good_role
}
