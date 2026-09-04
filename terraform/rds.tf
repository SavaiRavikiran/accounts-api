# Fixes ranked defects #2-6 in docs/SECTION4-REMEDIATION.md (b).
# T-05, T-12: no plaintext credential, encrypted at rest, not internet-reachable, recoverable.

resource "aws_kms_key" "rds" {
  description             = "CMK for accounts-prod RDS storage encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_db_instance" "accounts" {
  identifier     = "accounts-prod"
  engine         = "postgres"
  engine_version = "16.4"
  instance_class = "db.r6g.large"

  username = "accounts_app"
  # No plaintext password: AWS creates and rotates the master credential in
  # Secrets Manager for us. Removes the "password in tfvars/state" defect.
  manage_master_user_password = true
  master_user_secret_kms_key_id = aws_kms_key.rds.arn

  publicly_accessible      = false
  storage_encrypted        = true
  kms_key_id                = aws_kms_key.rds.arn
  backup_retention_period   = 14
  skip_final_snapshot       = false
  final_snapshot_identifier = "accounts-prod-final"
  deletion_protection       = true

  vpc_security_group_ids = [aws_security_group.db.id]
  db_subnet_group_name   = aws_db_subnet_group.accounts.name

  copy_tags_to_snapshot = true
}

resource "aws_db_subnet_group" "accounts" {
  name       = "accounts-prod"
  subnet_ids = [] # populated with private-subnet IDs at the environment layer
}

resource "aws_security_group" "db" {
  name        = "accounts-prod-db"
  description = "accounts-prod RDS — ingress from app tier only"
  vpc_id      = var.vpc_id
}
