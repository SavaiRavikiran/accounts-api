# Fixes ranked defect #7 in docs/SECTION4-REMEDIATION.md (b).
# T-04, T-12: multi-region, tamper-evident, durable audit trail for a regulated bank.

resource "aws_kms_key" "trail" {
  description             = "CMK for CloudTrail log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_s3_bucket" "trail" {
  bucket = var.trail_bucket_name
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.trail.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudtrail" "org" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  is_organization_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
  kms_key_id                    = aws_kms_key.trail.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}
