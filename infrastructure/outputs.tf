output "ec2_instance_id" {
  value = module.ec2.instance_id
}

output "ec2_public_ip" {
  value = module.ec2.public_ip
}

output "kms_key_arn" {
  value = module.kms.key_arn
}

output "s3_bucket" {
  value = module.s3.bucket_name
}

output "dynamodb_table" {
  value = module.dynamodb.table_name
}

output "cloudwatch_dashboard" {
  value = module.observability.dashboard_name
}
