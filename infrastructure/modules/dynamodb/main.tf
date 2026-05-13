variable "project_name" { type = string }
variable "environment" { type = string }

resource "aws_dynamodb_table" "jobs" {
  name         = "${var.project_name}-jobs"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "jobId"

  attribute {
    name = "jobId"
    type = "S"
  }

  attribute {
    name = "ownerPrincipal"
    type = "S"
  }

  attribute {
    name = "updatedAt"
    type = "S"
  }

  global_secondary_index {
    name            = "ownerPrincipal-updatedAt-index"
    hash_key        = "ownerPrincipal"
    range_key       = "updatedAt"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }

  tags = { Name = "${var.project_name}-jobs" }
}

output "table_name" { value = aws_dynamodb_table.jobs.name }
output "table_arn" { value = aws_dynamodb_table.jobs.arn }
