variable "region" {
  description = "AWS region. Assessment specifies ap-south-1."
  type        = string
  default     = "ap-south-1"
}

variable "vpc_id" {
  type = string
}

variable "app_security_group_id" {
  description = "SG attached to the EKS nodes/pods that host accounts-api."
  type        = string
}

variable "trail_bucket_name" {
  type    = string
  default = "digitalbank-org-cloudtrail-logs"
}
