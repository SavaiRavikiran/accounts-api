package main

bad_plan := {"resource_changes": [
	{"type": "aws_db_instance", "name": "accounts", "change": {"after": {
		"publicly_accessible": true,
		"storage_encrypted": false,
		"password": "hunter2",
		"backup_retention_period": 0,
	}}},
	{"type": "aws_security_group_rule", "name": "db_ingress", "change": {"after": {
		"type": "ingress", "from_port": 5432, "to_port": 5432, "cidr_blocks": ["0.0.0.0/0"],
	}}},
	{"type": "aws_cloudtrail", "name": "org", "change": {"after": {
		"is_multi_region_trail": false,
		"enable_log_file_validation": false,
	}}},
]}

good_plan := {"resource_changes": [
	{"type": "aws_db_instance", "name": "accounts", "change": {"after": {
		"publicly_accessible": false,
		"storage_encrypted": true,
		"backup_retention_period": 14,
	}}},
	{"type": "aws_security_group_rule", "name": "db_ingress", "change": {"after": {
		"type": "ingress", "from_port": 5432, "to_port": 5432, "cidr_blocks": ["10.0.1.0/24"],
	}}},
	{"type": "aws_cloudtrail", "name": "org", "change": {"after": {
		"is_multi_region_trail": true,
		"enable_log_file_validation": true,
	}}},
]}

test_bad_plan_denied_public_db {
	msgs := deny with input as bad_plan
	some msg in msgs
	contains(msg, "publicly_accessible")
}

test_bad_plan_denied_unencrypted {
	msgs := deny with input as bad_plan
	some msg in msgs
	contains(msg, "storage_encrypted")
}

test_bad_plan_denied_plaintext_password {
	msgs := deny with input as bad_plan
	some msg in msgs
	contains(msg, "plaintext password")
}

test_bad_plan_denied_open_sg {
	msgs := deny with input as bad_plan
	some msg in msgs
	contains(msg, "0.0.0.0/0")
}

test_bad_plan_denied_singleregion_trail {
	msgs := deny with input as bad_plan
	some msg in msgs
	contains(msg, "multi-region")
}

test_good_plan_has_no_denies {
	count(deny) == 0 with input as good_plan
}
