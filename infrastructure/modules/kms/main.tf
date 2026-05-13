variable "project_name" { type = string }
variable "environment" { type = string }
variable "enclave_role_arn" { type = string }
variable "allowed_pcr0" { type = string }
variable "allowed_pcr1" { type = string }
variable "allowed_pcr2" { type = string }
variable "client_principals" {
  type    = list(string)
  default = []
}

locals {
  bootstrap_pcr = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# KMS key for envelope encryption
# The key policy enforces attestation-based access:
# only a verified Nitro Enclave with the correct PCR
# measurements can use this key for decryption.
resource "aws_kms_key" "enclave" {
  description             = "${var.project_name} enclave encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "${var.project_name}-key-policy"
    Statement = concat([
      # Account administrators may manage the key, but this deliberately does
      # not delegate cryptographic use through IAM. Runtime key use is granted
      # only by the narrower statements below.
      {
        Sid    = "EnableAccountKeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "kms:CancelKeyDeletion",
          "kms:Create*",
          "kms:Delete*",
          "kms:Describe*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Get*",
          "kms:List*",
          "kms:Put*",
          "kms:Revoke*",
          "kms:ScheduleKeyDeletion",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:Update*"
        ]
        Resource = "*"
      },
      # The parent EC2 role may use the envelope key only through a measured
      # Nitro Enclave. The role has no identity-policy KMS allow, so there is
      # no direct host/gateway plaintext data-key path.
      {
        Sid    = "AllowAttestedEnclaveKmsUse"
        Effect = "Allow"
        Principal = {
          AWS = var.enclave_role_arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
        Condition = {
          StringEqualsIgnoreCase = {
            "kms:RecipientAttestation:PCR0" = var.allowed_pcr0
            "kms:RecipientAttestation:PCR1" = var.allowed_pcr1
            "kms:RecipientAttestation:PCR2" = var.allowed_pcr2
          }
        }
      },
      # The gateway stores encrypted result blobs in an SSE-KMS S3 bucket. This
      # lets S3 use the key on the role's behalf without allowing the role to
      # call KMS Decrypt or GenerateDataKey directly.
      {
        Sid    = "AllowGatewayS3SseKmsOnly"
        Effect = "Allow"
        Principal = {
          AWS = var.enclave_role_arn
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
            "kms:ViaService"    = "s3.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      }
      ],
      length(var.client_principals) == 0 ? [] : [
        {
          Sid    = "AllowClientsEnvelopeKeyUse"
          Effect = "Allow"
          Principal = {
            AWS = var.client_principals
          }
          Action = [
            "kms:Decrypt",
            "kms:DescribeKey",
            "kms:Encrypt",
            "kms:GenerateDataKey",
            "kms:GenerateDataKeyWithoutPlaintext"
          ]
          Resource = "*"
        }
      ]
    )
  })

  lifecycle {
    precondition {
      condition = alltrue([
        for pcr in [var.allowed_pcr0, var.allowed_pcr1, var.allowed_pcr2] :
        !can(regex("(?i)placeholder", trimspace(pcr))) && (
          trimspace(pcr) == local.bootstrap_pcr ||
          can(regex("(?i)^[0-9a-f]{96}$", trimspace(pcr)))
        )
      ])
      error_message = "allowed_pcr0, allowed_pcr1, and allowed_pcr2 must be 96-character hex PCR measurements or the all-zero bootstrap value; empty and PLACEHOLDER values are rejected."
    }
  }

  tags = {
    Name = "${var.project_name}-enclave-key"
  }
}

resource "aws_kms_alias" "enclave" {
  name          = "alias/${var.project_name}-master"
  target_key_id = aws_kms_key.enclave.key_id
}

output "key_arn" {
  value = aws_kms_key.enclave.arn
}

output "key_alias" {
  value = aws_kms_alias.enclave.name
}
