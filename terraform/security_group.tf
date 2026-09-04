# Fixes ranked defect #1 in docs/SECTION4-REMEDIATION.md (b).
# T-06, T-12: DB reachable only from the application tier, never the internet.

resource "aws_security_group_rule" "db_ingress" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = var.app_security_group_id
  security_group_id        = aws_security_group.db.id
  description               = "accounts-api pods only"
}

resource "aws_security_group_rule" "db_egress_none" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["127.0.0.1/32"]
  security_group_id = aws_security_group.db.id
  description       = "RDS does not need to originate outbound connections"
}
