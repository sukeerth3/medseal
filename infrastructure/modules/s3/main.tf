variable "project_name" { type = string }
variable "environment" { type = string }
variable "kms_key_arn" { type = string }
variable "force_destroy" { type = bool }

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "results" {
  bucket        = "${var.project_name}-results-${var.environment}-${data.aws_caller_identity.current.account_id}"
  force_destroy = var.force_destroy
  tags          = { Name = "${var.project_name}-results" }

  lifecycle {
    precondition {
      condition     = !var.force_destroy || lower(var.environment) == "dev"
      error_message = "S3 force_destroy may only be enabled for the dev environment."
    }
  }
}

resource "aws_s3_bucket_versioning" "results" {
  bucket = aws_s3_bucket.results.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "results" {
  bucket = aws_s3_bucket.results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "results" {
  bucket                  = aws_s3_bucket.results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "results" {
  bucket = aws_s3_bucket.results.id

  rule {
    id     = "expire-results"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "deny_insecure_transport" {
  bucket = aws_s3_bucket.results.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.results.arn,
        "${aws_s3_bucket.results.arn}/*"
      ]
      Condition = {
        Bool = {
          "aws:SecureTransport" = "false"
        }
      }
    }]
  })
}

output "bucket_name" { value = aws_s3_bucket.results.bucket }
output "bucket_arn" { value = aws_s3_bucket.results.arn }
