terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "MedSeal"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# Network
module "vpc" {
  source = "./modules/vpc"

  project_name = var.project_name
  environment  = var.environment
  vpc_cidr     = var.vpc_cidr
}

# Instance identity and service permissions
module "iam" {
  source = "./modules/iam"

  project_name       = var.project_name
  environment        = var.environment
  s3_bucket_arn      = module.s3.bucket_arn
  dynamodb_table_arn = module.dynamodb.table_arn
}

# Attested key release
module "kms" {
  source = "./modules/kms"

  project_name      = var.project_name
  environment       = var.environment
  enclave_role_arn  = module.iam.ec2_role_arn
  allowed_pcr0      = var.allowed_pcr0
  allowed_pcr1      = var.allowed_pcr1
  allowed_pcr2      = var.allowed_pcr2
  client_principals = var.client_kms_principal_arns
}

# Encrypted result storage
module "s3" {
  source = "./modules/s3"

  project_name  = var.project_name
  environment   = var.environment
  kms_key_arn   = module.kms.key_arn
  force_destroy = var.s3_force_destroy
}

# Job metadata
module "dynamodb" {
  source = "./modules/dynamodb"

  project_name = var.project_name
  environment  = var.environment
}

# Logs, metrics, and dashboard
module "observability" {
  source = "./modules/observability"

  project_name = var.project_name
  environment  = var.environment
}

# Nitro host
module "ec2" {
  source = "./modules/ec2"

  project_name          = var.project_name
  environment           = var.environment
  vpc_id                = module.vpc.vpc_id
  subnet_id             = module.vpc.public_subnet_id
  instance_profile_name = module.iam.instance_profile_name
  instance_type         = var.instance_type
  key_name              = var.key_name
  allowed_ingress_cidr  = var.allowed_ingress_cidr
  gateway_log_group     = module.observability.gateway_log_group_name
  nitro_log_group       = module.observability.nitro_log_group_name
  kms_proxy_log_group   = module.observability.kms_proxy_log_group_name
}
