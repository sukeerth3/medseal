variable "project_name" { type = string }
variable "environment" { type = string }
variable "s3_bucket_arn" { type = string }
variable "dynamodb_table_arn" { type = string }

# EC2 instance role with scoped service access
resource "aws_iam_role" "ec2" {
  name = "${var.project_name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

# S3 access (read/write encrypted results)
resource "aws_iam_role_policy" "s3" {
  name = "${var.project_name}-s3-policy"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:PutObject",
        "s3:GetObject"
      ]
      Resource = "${var.s3_bucket_arn}/results/*"
    }]
  })
}

# DynamoDB access (job tracking)
resource "aws_iam_role_policy" "dynamodb" {
  name = "${var.project_name}-dynamodb-policy"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query"
      ]
      Resource = [
        var.dynamodb_table_arn,
        "${var.dynamodb_table_arn}/index/*"
      ]
    }]
  })
}

# CloudWatch Logs
resource "aws_iam_role_policy" "cloudwatch" {
  name = "${var.project_name}-cloudwatch-policy"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "ec2" {
  name = "${var.project_name}-instance-profile"
  role = aws_iam_role.ec2.name
}

output "ec2_role_arn" { value = aws_iam_role.ec2.arn }
output "instance_profile_name" { value = aws_iam_instance_profile.ec2.name }
