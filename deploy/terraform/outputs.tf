output "function_arn" {
  description = "Security Agent Lambda ARN"
  value       = aws_lambda_function.agent.arn
}

output "alerts_topic_arn" {
  description = "알림 SNS 토픽 ARN"
  value       = aws_sns_topic.alerts.arn
}

output "firewall_webhook_url" {
  description = "방화벽 장비가 POST 할 webhook URL (활성화 시). ?vendor= 로 벤더 지정 가능"
  value       = var.enable_firewall_endpoint ? "${aws_apigatewayv2_stage.firewall[0].invoke_url}/firewall" : "(disabled)"
}
