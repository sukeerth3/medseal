variable "project_name" { type = string }
variable "environment" { type = string }

locals {
  namespace           = "MedSeal/${var.environment}"
  gateway_log_group   = "/aws/medseal/${var.environment}/gateway"
  nitro_log_group     = "/aws/medseal/${var.environment}/nitro"
  kms_proxy_log_group = "/aws/medseal/${var.environment}/kms-proxy"
}

resource "aws_cloudwatch_log_group" "gateway" {
  name              = local.gateway_log_group
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "nitro" {
  name              = local.nitro_log_group
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "kms_proxy" {
  name              = local.kms_proxy_log_group
  retention_in_days = 30
}

resource "aws_cloudwatch_log_metric_filter" "jobs_completed" {
  name           = "${var.project_name}-${var.environment}-jobs-completed"
  log_group_name = aws_cloudwatch_log_group.gateway.name
  pattern        = "event=JOB_COMPLETED"

  metric_transformation {
    name      = "JobsCompleted"
    namespace = local.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "jobs_failed" {
  name           = "${var.project_name}-${var.environment}-jobs-failed"
  log_group_name = aws_cloudwatch_log_group.gateway.name
  pattern        = "event=JOB_FAILED"

  metric_transformation {
    name      = "JobsFailed"
    namespace = local.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "enclave_hangup" {
  name           = "${var.project_name}-${var.environment}-enclave-hangup"
  log_group_name = aws_cloudwatch_log_group.nitro.name
  pattern        = "\"Received hang-up event from the enclave\""

  metric_transformation {
    name      = "EnclaveHangups"
    namespace = local.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "jobs_failed" {
  alarm_name          = "${var.project_name}-${var.environment}-jobs-failed"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "JobsFailed"
  namespace           = local.namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "enclave_hangup" {
  alarm_name          = "${var.project_name}-${var.environment}-enclave-hangup"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "EnclaveHangups"
  namespace           = local.namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_dashboard" "medseal" {
  dashboard_name = "${var.project_name}-${var.environment}-operations"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "MedSeal job outcomes"
          region  = data.aws_region.current.name
          view    = "timeSeries"
          stacked = false
          metrics = [
            [local.namespace, "JobsCompleted"],
            [local.namespace, "JobsFailed"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Nitro enclave hangups"
          region = data.aws_region.current.name
          view   = "timeSeries"
          metrics = [
            [local.namespace, "EnclaveHangups"]
          ]
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        properties = {
          title  = "Recent MedSeal audit events"
          region = data.aws_region.current.name
          query  = "SOURCE '${local.gateway_log_group}' | fields @timestamp, @message | filter @message like /event=JOB_/ | sort @timestamp desc | limit 20"
        }
      }
    ]
  })
}

data "aws_region" "current" {}

output "gateway_log_group_name" { value = aws_cloudwatch_log_group.gateway.name }
output "nitro_log_group_name" { value = aws_cloudwatch_log_group.nitro.name }
output "kms_proxy_log_group_name" { value = aws_cloudwatch_log_group.kms_proxy.name }
output "dashboard_name" { value = aws_cloudwatch_dashboard.medseal.dashboard_name }
