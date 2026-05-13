# Remote state is intentionally staged but disabled. Create the S3 bucket and
# DynamoDB lock table first, then uncomment this block and run:
# terraform init -migrate-state
#
# terraform {
#   backend "s3" {
#     bucket         = "medseal-terraform-state"
#     key            = "medseal/terraform.tfstate"
#     region         = "us-east-1"
#     dynamodb_table = "medseal-terraform-locks"
#     encrypt        = true
#   }
# }
