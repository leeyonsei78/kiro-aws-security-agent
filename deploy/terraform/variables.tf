variable "region" {
  description = "배포 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "name_prefix" {
  description = "리소스 이름 접두사"
  type        = string
  default     = "security-agent"
}

variable "min_severity" {
  description = "이 심각도 이상만 알림"
  type        = string
  default     = "MEDIUM"
}

variable "collectors" {
  description = "폴링에 사용할 collector (쉼표구분)"
  type        = string
  default     = "guardduty,securityhub"
}

variable "slack_webhook_url" {
  description = "Slack Incoming Webhook URL (선택)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "notification_email" {
  description = "이메일 알림 수신 주소 (선택, 입력 시 SNS 구독 생성)"
  type        = string
  default     = ""
}

variable "schedule_expression" {
  description = "폴링 스케줄"
  type        = string
  default     = "rate(1 hour)"
}

variable "lookback_minutes" {
  description = "폴링 조회 윈도우(분)"
  type        = string
  default     = "70"
}

variable "remediation_enabled" {
  description = "자동 대응 활성화 (기본 비활성)"
  type        = string
  default     = "false"
}

variable "remediation_dry_run" {
  description = "자동 대응 dry-run (기본 true)"
  type        = string
  default     = "true"
}

variable "enable_firewall_endpoint" {
  description = "써드파티 방화벽 webhook용 HTTP API 생성 여부"
  type        = bool
  default     = false
}

variable "enable_remediation_policy" {
  description = "대응(쓰기) IAM 권한 부여 여부 (실제 적용 시 true)"
  type        = bool
  default     = false
}
