variable "project_name" { type = string }
variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "subnet_id" { type = string }
variable "instance_profile_name" { type = string }
variable "instance_type" { type = string }
variable "key_name" { type = string }
variable "allowed_ingress_cidr" { type = string }
variable "gateway_log_group" { type = string }
variable "nitro_log_group" { type = string }
variable "kms_proxy_log_group" { type = string }

# Amazon Linux 2023 AMI
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Security group with only the demo ingress ports exposed
resource "aws_security_group" "enclave" {
  name_prefix = "${var.project_name}-enclave-"
  vpc_id      = var.vpc_id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ingress_cidr]
  }

  # Gateway API
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ingress_cidr]
  }

  # All outbound (needed for KMS, S3, DynamoDB, package managers)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-enclave-sg"
  }
}

# EC2 instance with Nitro Enclave enabled
resource "aws_instance" "enclave" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  key_name                    = var.key_name
  subnet_id                   = var.subnet_id
  iam_instance_profile        = var.instance_profile_name
  associate_public_ip_address = true

  vpc_security_group_ids = [aws_security_group.enclave.id]

  # Enable Nitro Enclaves
  enclave_options {
    enabled = true
  }

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  # User data script to set up the instance
  user_data = <<-EOF
#!/bin/bash
set -euxo pipefail

dnf update -y

# Install Nitro Enclaves CLI and development tools
dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel

# Add ec2-user to the Nitro Enclaves group created by the package
usermod -aG ne ec2-user

# Configure enclave allocator (4 GB for enclave, rest for host)
cat > /etc/nitro_enclaves/allocator.yaml <<ALLOC
---
memory_mib: 4096
cpu_count: 2
ALLOC

# Install Docker (for building enclave images)
dnf install -y docker
systemctl enable --now docker

# Install Java 17 (for Spring Boot gateway)
dnf install -y java-17-amazon-corretto-headless

# Install Python 3.11 (for vsock client helper)
dnf install -y python3.11 python3.11-pip

# Install CloudWatch agent for gateway, proxy, and Nitro logs.
dnf install -y amazon-cloudwatch-agent

# Add ec2-user to docker group
usermod -aG docker ec2-user

# Install MedSeal host service configuration. The gateway jar and env file are
# deployed later by scripts/deploy.sh.
install -d -m 0755 /etc/vsock-proxy /etc/medseal /etc/medseal/tls
install -d -o ec2-user -g ec2-user -m 0755 /opt/medseal
install -d -o ec2-user -g ec2-user -m 0755 /var/log/medseal

cat > /etc/vsock-proxy/medseal.yaml <<'VSOCKPROXY'
${file("${path.module}/files/vsock-proxy.yaml")}
VSOCKPROXY

cat > /etc/systemd/system/medseal-kms-proxy.service <<'KMSPROXYUNIT'
${file("${path.module}/files/medseal-kms-proxy.service")}
KMSPROXYUNIT

cat > /etc/systemd/system/medseal-gateway.service <<'GATEWAYUNIT'
${file("${path.module}/files/medseal-gateway.service")}
GATEWAYUNIT

cat > /opt/aws/amazon-cloudwatch-agent/etc/medseal.json <<'CWAGENT'
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "root"
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/medseal/gateway.log",
            "log_group_name": "${var.gateway_log_group}",
            "log_stream_name": "{instance_id}/gateway",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/log/medseal/kms-proxy.log",
            "log_group_name": "${var.kms_proxy_log_group}",
            "log_stream_name": "{instance_id}/kms-proxy",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/log/nitro_enclaves/nitro_enclaves.log",
            "log_group_name": "${var.nitro_log_group}",
            "log_stream_name": "{instance_id}/nitro",
            "timezone": "UTC"
          }
        ]
      }
    }
  }
}
CWAGENT

systemctl daemon-reload
systemctl enable --now nitro-enclaves-allocator.service
systemctl enable --now medseal-kms-proxy.service
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/medseal.json

echo "MedSeal instance setup complete" > /tmp/setup-complete
EOF

  tags = {
    Name = "${var.project_name}-enclave-${var.environment}"
  }
}

output "instance_id" {
  value = aws_instance.enclave.id
}

output "private_ip" {
  value = aws_instance.enclave.private_ip
}

output "public_ip" {
  value = aws_instance.enclave.public_ip
}
