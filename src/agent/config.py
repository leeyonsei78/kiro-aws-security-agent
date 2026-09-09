"""환경변수 기반 설정.

Lambda/로컬 공통으로 환경변수에서 설정을 읽는다.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .models import Severity


def _csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


@dataclass
class Config:
    # 활성화할 collector/notifier (쉼표구분). 비어있으면 자격증명/설정 기준 기본값 사용.
    collectors: list[str] = field(default_factory=lambda: _csv(os.getenv("COLLECTORS")) or ["guardduty", "securityhub"])
    notifiers: list[str] = field(default_factory=lambda: _csv(os.getenv("NOTIFIERS")))

    # 이 심각도 이상만 알림
    min_severity: Severity = field(
        default_factory=lambda: Severity.from_name(os.getenv("MIN_SEVERITY", "MEDIUM"))
    )

    # 폴링 조회 시간 윈도우(분)
    lookback_minutes: int = field(default_factory=lambda: int(os.getenv("LOOKBACK_MINUTES", "60")))

    # AWS
    region: str | None = field(default_factory=lambda: os.getenv("AWS_REGION"))

    # Slack
    slack_webhook_url: str = field(default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL", ""))

    # Email via SNS
    sns_topic_arn: str = field(default_factory=lambda: os.getenv("SNS_TOPIC_ARN", ""))

    # --- 자동 대응(remediation) ---
    # 기본 비활성. 켜더라도 dry_run 기본 True라 실제 변경은 이중으로 명시해야 함.
    remediation_enabled: bool = field(
        default_factory=lambda: os.getenv("REMEDIATION_ENABLED", "false").lower() == "true"
    )
    remediation_dry_run: bool = field(
        default_factory=lambda: os.getenv("REMEDIATION_DRY_RUN", "true").lower() != "false"
    )
    # 활성화할 remediator (쉼표구분). 비어있으면 등록된 전체.
    remediators: list[str] = field(default_factory=lambda: _csv(os.getenv("REMEDIATORS")))
    # 대응을 허용할 finding_type 접두사 화이트리스트. 비어있으면 각 remediator의 supported_types 전체.
    remediation_allowed_types: list[str] = field(
        default_factory=lambda: _csv(os.getenv("REMEDIATION_ALLOWED_TYPES"))
    )

    # WAF IPSet 차단 remediator 대상 (waf_ipset_block 사용 시 필수)
    waf_ipset_name: str = field(default_factory=lambda: os.getenv("WAF_IPSET_NAME", ""))
    waf_ipset_id: str = field(default_factory=lambda: os.getenv("WAF_IPSET_ID", ""))
    waf_ipset_scope: str = field(default_factory=lambda: os.getenv("WAF_IPSET_SCOPE", "REGIONAL"))

    # VPC Flow Logs collector (vpc_flow_logs 사용 시 필수)
    flowlogs_log_group: str = field(default_factory=lambda: os.getenv("FLOWLOGS_LOG_GROUP", ""))
    flowlogs_reject_threshold: int = field(
        default_factory=lambda: int(os.getenv("FLOWLOGS_REJECT_THRESHOLD", "100"))
    )
    flowlogs_distinct_ports_threshold: int = field(
        default_factory=lambda: int(os.getenv("FLOWLOGS_DISTINCT_PORTS_THRESHOLD", "20"))
    )

    # EC2 격리 remediator 대상 (ec2_quarantine 사용 시 필수)
    quarantine_sg_id: str = field(default_factory=lambda: os.getenv("QUARANTINE_SG_ID", ""))

    # --- 방화벽 webhook 인증 (firewall_syslog HTTP 엔드포인트 보호) ---
    # API 키: 요청 헤더 X-Api-Key 값과 일치해야 통과. 미설정 시 키 검사 안 함.
    firewall_api_key: str = field(default_factory=lambda: os.getenv("FIREWALL_API_KEY", ""))
    # IP 허용목록(쉼표구분, IP 또는 CIDR). 미설정 시 IP 검사 안 함.
    firewall_allowed_ips: list[str] = field(
        default_factory=lambda: _csv(os.getenv("FIREWALL_ALLOWED_IPS"))
    )

    @property
    def firewall_auth_configured(self) -> bool:
        return bool(self.firewall_api_key or self.firewall_allowed_ips)

    def resolved_notifiers(self) -> list[str]:
        """명시 설정이 없으면 자격정보가 채워진 채널을 자동 활성화."""
        if self.notifiers:
            return self.notifiers
        auto: list[str] = []
        if self.slack_webhook_url:
            auto.append("slack")
        if self.sns_topic_arn:
            auto.append("email_sns")
        return auto or ["stdout"]


def load_config() -> Config:
    return Config()
