from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_gateway_role_has_no_direct_kms_identity_policy():
    iam = (ROOT / "modules" / "iam" / "main.tf").read_text()

    assert 'resource "aws_iam_role_policy" "kms"' not in iam
    assert '"kms:Decrypt"' not in iam
    assert '"kms:GenerateDataKey"' not in iam


def test_kms_policy_keeps_runtime_use_narrow():
    kms = (ROOT / "modules" / "kms" / "main.tf").read_text()

    assert "EnableAccountKeyAdministration" in kms
    assert '"kms:*"' not in kms
    assert "kms:RecipientAttestation:PCR0" in kms
    assert "kms:RecipientAttestation:PCR1" in kms
    assert "kms:RecipientAttestation:PCR2" in kms
    assert "AllowGatewayS3SseKmsOnly" in kms
    assert "kms:ViaService" in kms


def test_observability_declares_dashboard_and_metric_filters():
    observability = (ROOT / "modules" / "observability" / "main.tf").read_text()
    ec2 = (ROOT / "modules" / "ec2" / "main.tf").read_text()

    assert 'resource "aws_cloudwatch_dashboard" "medseal"' in observability
    assert 'resource "aws_cloudwatch_log_metric_filter" "jobs_failed"' in observability
    assert 'resource "aws_cloudwatch_log_metric_filter" "enclave_hangup"' in observability
    assert "amazon-cloudwatch-agent" in ec2
    assert "/var/log/medseal/gateway.log" in ec2
