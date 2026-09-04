# Section 2 — CI-to-AWS auth via OIDC, no static keys (T-10).
# Trust policy sub claim is deliberately narrow — see oidc/trust-policy.json
# and docs/SECTION2-SUPPLY-CHAIN.md for what that scoping denies.

resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "gha_deploy" {
  name                 = "accounts-api-gha-deploy"
  assume_role_policy   = file("${path.module}/../oidc/trust-policy.json")
  max_session_duration = 900 # 15 min — deploy jobs are short-lived
}

resource "aws_iam_role_policy" "gha_deploy_scope" {
  name = "accounts-api-gha-deploy-scope"
  role = aws_iam_role.gha_deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EksDeployOnly"
        Effect   = "Allow"
        Action   = ["eks:DescribeCluster"]
        Resource = "arn:aws:eks:ap-south-1:222222222222:cluster/accounts-shared"
      }
    ]
  })
}
