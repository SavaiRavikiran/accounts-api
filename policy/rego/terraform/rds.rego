package main

# Run against a `terraform show -json plan.tfplan` document:
# conftest test -p policy/rego/terraform plan.json
# Threats: T-05 (secrets in state/vars), T-06/T-12 (public exposure), T-04 (audit integrity).

resource_changes[rc] {
	rc := input.resource_changes[_]
}

deny[msg] {
	rc := resource_changes[_]
	rc.type == "aws_db_instance"
	rc.change.after.publicly_accessible == true
	msg := sprintf("T-06/T-12: aws_db_instance '%s' must not set publicly_accessible = true", [rc.name])
}

deny[msg] {
	rc := resource_changes[_]
	rc.type == "aws_db_instance"
	rc.change.after.storage_encrypted != true
	msg := sprintf("T-05/T-12: aws_db_instance '%s' must set storage_encrypted = true", [rc.name])
}

deny[msg] {
	rc := resource_changes[_]
	rc.type == "aws_db_instance"
	rc.change.after.password
	msg := sprintf("T-05: aws_db_instance '%s' must not set a plaintext password attribute; use manage_master_user_password", [rc.name])
}

deny[msg] {
	rc := resource_changes[_]
	rc.type == "aws_db_instance"
	rc.change.after.backup_retention_period == 0
	msg := sprintf("aws_db_instance '%s' must set backup_retention_period > 0", [rc.name])
}

deny[msg] {
	rc := resource_changes[_]
	rc.type == "aws_security_group_rule"
	rc.change.after.type == "ingress"
	rc.change.after.from_port <= 5432
	rc.change.after.to_port >= 5432
	cidr := rc.change.after.cidr_blocks[_]
	cidr == "0.0.0.0/0"
	msg := sprintf("T-06: security_group_rule '%s' must not open the database port to 0.0.0.0/0", [rc.name])
}

deny[msg] {
	rc := resource_changes[_]
	rc.type == "aws_cloudtrail"
	rc.change.after.is_multi_region_trail != true
	msg := sprintf("T-04: aws_cloudtrail '%s' must be multi-region", [rc.name])
}

deny[msg] {
	rc := resource_changes[_]
	rc.type == "aws_cloudtrail"
	rc.change.after.enable_log_file_validation != true
	msg := sprintf("T-04: aws_cloudtrail '%s' must enable log file validation", [rc.name])
}
