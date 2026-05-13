variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "medseal"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "instance_type" {
  description = "EC2 instance type (must support Nitro Enclaves)"
  type        = string
  default     = "c5.xlarge"
}

variable "key_name" {
  description = "SSH key pair name"
  type        = string
}

variable "allowed_ingress_cidr" {
  description = "CIDR block allowed to reach the dev EC2 host over SSH and the gateway port"
  type        = string
}

variable "allowed_pcr0" {
  description = "Allowed Nitro Enclave PCR0 measurement for KMS attested requests"
  type        = string
}

variable "allowed_pcr1" {
  description = "Allowed Nitro Enclave PCR1 measurement for KMS attested requests"
  type        = string
}

variable "allowed_pcr2" {
  description = "Allowed Nitro Enclave PCR2 measurement for KMS attested requests"
  type        = string
}

variable "client_kms_principal_arns" {
  description = "IAM principal ARNs allowed to use the MedSeal KMS key directly for client-side envelope encryption and result decryption. Do not put the EC2 gateway role here."
  type        = list(string)
  default     = []
}

variable "s3_force_destroy" {
  description = "Allow Terraform destroy to remove all S3 result object versions in dev/demo stacks. Must be false outside dev."
  type        = bool
  default     = true
}
