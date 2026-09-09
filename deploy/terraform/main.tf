terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  has_email = var.notification_email != ""
}

# --- 코드 패키징: src/agent -> zip (외부 의존성 없음, 런타임 boto3 사용) ---
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../src"
  output_path = "${path.module}/build/agent.zip"
}

# --- SNS 알림 토픽 ---
resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-security-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = local.has_email ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# --- IAM 역할 ---
resource "aws_iam_role" "agent" {
  name = "${var.name_prefix}-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "basic_logs" {
  role       = aws_iam_role.agent.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# 읽기 전용 수집 권한
resource "aws_iam_role_policy" "reads" {
  name = "${var.name_prefix}-reads"
  role = aws_iam_role.agent.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecurityReads"
        Effect = "Allow"
        Action = [
          "guardduty:ListDetectors", "guardduty:ListFindings", "guardduty:GetFindings",
          "securityhub:GetFindings",
          "ec2:DescribeSecurityGroups", "ec2:DescribeNetworkAcls",
          "access-analyzer:ListAnalyzers", "access-analyzer:ListFindings",
          "cloudtrail:LookupEvents",
          "logs:StartQuery", "logs:GetQueryResults", "logs:StopQuery"
        ]
        Resource = "*"
      },
      {
        Sid      = "NotifyViaSns"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

# 대응(쓰기) 권한 - enable_remediation_policy=true 일 때만
resource "aws_iam_role_policy" "remediation" {
  count = var.enable_remediation_policy ? 1 : 0
  name  = "${var.name_prefix}-remediation"
  role  = aws_iam_role.agent.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "Remediation"
      Effect = "Allow"
      Action = [
        "ec2:CreateNetworkAclEntry", "ec2:RevokeSecurityGroupIngress", "ec2:ModifyInstanceAttribute",
        "s3:PutBucketPublicAccessBlock", "s3:GetBucketPublicAccessBlock",
        "wafv2:GetIPSet", "wafv2:UpdateIPSet",
        "iam:UpdateAccessKey"
      ]
      Resource = "*"
    }]
  })
}

# --- Lambda 함수 ---
resource "aws_lambda_function" "agent" {
  function_name    = "${var.name_prefix}-agent"
  role             = aws_iam_role.agent.arn
  handler          = "agent.handler.lambda_handler"
  runtime          = "python3.11"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 120
  memory_size      = 256

  environment {
    variables = {
      MIN_SEVERITY        = var.min_severity
      COLLECTORS          = var.collectors
      LOOKBACK_MINUTES    = var.lookback_minutes
      SLACK_WEBHOOK_URL   = var.slack_webhook_url
      SNS_TOPIC_ARN       = aws_sns_topic.alerts.arn
      REMEDIATION_ENABLED = var.remediation_enabled
      REMEDIATION_DRY_RUN = var.remediation_dry_run
    }
  }
}

# --- EventBridge: 주기적 폴링 ---
resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name_prefix}-schedule"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "schedule" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.agent.arn
}

resource "aws_lambda_permission" "schedule" {
  statement_id  = "AllowSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.agent.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

# --- EventBridge: 실시간 finding 이벤트 (여러 소스) ---
locals {
  event_patterns = {
    guardduty = {
      source      = ["aws.guardduty"]
      detail-type = ["GuardDuty Finding"]
    }
    securityhub = {
      source      = ["aws.securityhub"]
      detail-type = ["Security Hub Findings - Imported"]
    }
    access_analyzer = {
      source      = ["aws.access-analyzer"]
      detail-type = ["Access Analyzer Finding"]
    }
  }
}

resource "aws_cloudwatch_event_rule" "findings" {
  for_each      = local.event_patterns
  name          = "${var.name_prefix}-${each.key}"
  event_pattern = jsonencode(each.value)
}

resource "aws_cloudwatch_event_target" "findings" {
  for_each = local.event_patterns
  rule     = aws_cloudwatch_event_rule.findings[each.key].name
  arn      = aws_lambda_function.agent.arn
}

resource "aws_lambda_permission" "findings" {
  for_each      = local.event_patterns
  statement_id  = "AllowEvent-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.agent.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.findings[each.key].arn
}

# --- HTTP API: 써드파티 방화벽 webhook (선택) ---
resource "aws_apigatewayv2_api" "firewall" {
  count         = var.enable_firewall_endpoint ? 1 : 0
  name          = "${var.name_prefix}-firewall"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "firewall" {
  count                  = var.enable_firewall_endpoint ? 1 : 0
  api_id                 = aws_apigatewayv2_api.firewall[0].id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.agent.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "firewall" {
  count     = var.enable_firewall_endpoint ? 1 : 0
  api_id    = aws_apigatewayv2_api.firewall[0].id
  route_key = "POST /firewall"
  target    = "integrations/${aws_apigatewayv2_integration.firewall[0].id}"
}

resource "aws_apigatewayv2_stage" "firewall" {
  count       = var.enable_firewall_endpoint ? 1 : 0
  api_id      = aws_apigatewayv2_api.firewall[0].id
  name        = "prod"
  auto_deploy = true
}

resource "aws_lambda_permission" "firewall" {
  count         = var.enable_firewall_endpoint ? 1 : 0
  statement_id  = "AllowHttpApi"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.agent.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.firewall[0].execution_arn}/*/*/firewall"
}
