"""Collector/Notifier 플러그인 등록소.

설정(config)에 지정된 이름을 실제 인스턴스로 매핑한다.
새 소스/채널을 추가하려면 여기 팩토리만 등록하면 코어는 변경 불필요.
"""

from __future__ import annotations

import logging
from typing import Callable

from .collectors.access_analyzer import AccessAnalyzerCollector
from .collectors.base import BaseCollector
from .collectors.cloudtrail import CloudTrailCollector
from .collectors.compliance import ComplianceCollector
from .collectors.firewall_syslog import FirewallSyslogCollector
from .collectors.guardduty import GuardDutyCollector
from .collectors.security_group import SecurityGroupCollector
from .collectors.securityhub import SecurityHubCollector
from .collectors.vpc_flow_logs import VpcFlowLogsCollector
from .config import Config
from .notifiers.base import BaseNotifier
from .notifiers.email_sns import EmailSnsNotifier
from .notifiers.slack import SlackNotifier
from .notifiers.stdout import StdoutNotifier
from .remediators.base import BaseRemediator
from .remediators.ec2_quarantine import Ec2QuarantineRemediator
from .remediators.iam_disable_key import IamDisableKeyRemediator
from .remediators.nacl_block_ip import NaclBlockIpRemediator
from .remediators.s3_public_block import S3PublicBlockRemediator
from .remediators.sg_revoke_ingress import SgRevokeIngressRemediator
from .remediators.waf_ipset_block import WafIpSetBlockRemediator

logger = logging.getLogger(__name__)

# 이름 -> collector 생성자
_COLLECTOR_FACTORIES: dict[str, Callable[[Config], BaseCollector]] = {
    "guardduty": lambda cfg: GuardDutyCollector(region=cfg.region),
    "securityhub": lambda cfg: SecurityHubCollector(region=cfg.region),
    "security_group": lambda cfg: SecurityGroupCollector(region=cfg.region),
    "access_analyzer": lambda cfg: AccessAnalyzerCollector(region=cfg.region),
    "cloudtrail": lambda cfg: CloudTrailCollector(region=cfg.region),
    "vpc_flow_logs": lambda cfg: VpcFlowLogsCollector(
        region=cfg.region,
        log_group=cfg.flowlogs_log_group,
        reject_threshold=cfg.flowlogs_reject_threshold,
        distinct_ports_threshold=cfg.flowlogs_distinct_ports_threshold,
    ),
    "firewall_syslog": lambda cfg: FirewallSyslogCollector(region=cfg.region),
    "compliance": lambda cfg: ComplianceCollector(region=cfg.region),
}

# 이름 -> remediator 팩토리 (설정으로 dry_run/allowed_types 및 remediator별 인자 주입)
_REMEDIATOR_FACTORIES: dict[str, Callable[[Config], BaseRemediator]] = {
    "nacl_block_ip": lambda cfg: NaclBlockIpRemediator(
        dry_run=cfg.remediation_dry_run,
        allowed_types=cfg.remediation_allowed_types or None,
        region=cfg.region,
    ),
    "sg_revoke_ingress": lambda cfg: SgRevokeIngressRemediator(
        dry_run=cfg.remediation_dry_run,
        allowed_types=cfg.remediation_allowed_types or None,
        region=cfg.region,
    ),
    "s3_public_block": lambda cfg: S3PublicBlockRemediator(
        dry_run=cfg.remediation_dry_run,
        allowed_types=cfg.remediation_allowed_types or None,
        region=cfg.region,
    ),
    "waf_ipset_block": lambda cfg: WafIpSetBlockRemediator(
        ipset_name=cfg.waf_ipset_name,
        ipset_id=cfg.waf_ipset_id,
        scope=cfg.waf_ipset_scope,
        dry_run=cfg.remediation_dry_run,
        allowed_types=cfg.remediation_allowed_types or None,
        region=cfg.region,
    ),
    "iam_disable_key": lambda cfg: IamDisableKeyRemediator(
        dry_run=cfg.remediation_dry_run,
        allowed_types=cfg.remediation_allowed_types or None,
        region=cfg.region,
    ),
    "ec2_quarantine": lambda cfg: Ec2QuarantineRemediator(
        quarantine_sg_id=cfg.quarantine_sg_id,
        dry_run=cfg.remediation_dry_run,
        allowed_types=cfg.remediation_allowed_types or None,
        region=cfg.region,
    ),
}

# EventBridge detail-type -> 그 이벤트를 처리할 collector 이름 (실시간 모드용)
EVENT_TYPE_TO_COLLECTOR: dict[str, str] = {
    "GuardDuty Finding": "guardduty",
    "Security Hub Findings - Imported": "securityhub",
    "Access Analyzer Finding": "access_analyzer",
    "AWS API Call via CloudTrail": "cloudtrail",
}


def _build_notifier(name: str, cfg: Config) -> BaseNotifier | None:
    if name == "slack":
        return SlackNotifier(webhook_url=cfg.slack_webhook_url)
    if name == "email_sns":
        return EmailSnsNotifier(topic_arn=cfg.sns_topic_arn, region=cfg.region)
    if name == "stdout":
        return StdoutNotifier()
    logger.warning("알 수 없는 notifier: %s", name)
    return None


def build_collectors(cfg: Config) -> list[BaseCollector]:
    collectors: list[BaseCollector] = []
    for name in cfg.collectors:
        factory = _COLLECTOR_FACTORIES.get(name)
        if not factory:
            logger.warning("알 수 없는 collector: %s", name)
            continue
        collectors.append(factory(cfg))
    return collectors


def build_collector(name: str, cfg: Config) -> BaseCollector | None:
    factory = _COLLECTOR_FACTORIES.get(name)
    return factory(cfg) if factory else None


def build_notifiers(cfg: Config) -> list[BaseNotifier]:
    notifiers: list[BaseNotifier] = []
    for name in cfg.resolved_notifiers():
        n = _build_notifier(name, cfg)
        if n:
            notifiers.append(n)
    return notifiers


def build_remediators(cfg: Config) -> list[BaseRemediator]:
    """설정에 따라 remediator 인스턴스 생성.

    remediation_enabled=False면 빈 목록. allowed_types가 비면 각 remediator 전체 허용.
    """
    if not cfg.remediation_enabled:
        return []
    names = cfg.remediators or list(_REMEDIATOR_FACTORIES.keys())
    remediators: list[BaseRemediator] = []
    for name in names:
        factory = _REMEDIATOR_FACTORIES.get(name)
        if not factory:
            logger.warning("알 수 없는 remediator: %s", name)
            continue
        remediators.append(factory(cfg))
    return remediators



# --- 기능 개요(웹 콘솔 표시용) ---------------------------------------------
# 사람이 읽는 설명. 코드 요소는 위 팩토리/목록에서 이름을, 여기서 설명을 가져온다.
_COLLECTOR_INFO: dict[str, dict[str, str]] = {
    "guardduty": {"label": "Amazon GuardDuty", "desc": "위협 탐지 finding 수집(폴링+실시간)", "mode": "폴링/실시간"},
    "securityhub": {"label": "AWS Security Hub", "desc": "ASFF 통합 finding 수집(다수 소스 집계)", "mode": "폴링/실시간"},
    "security_group": {"label": "Security Group", "desc": "인터넷 개방 위험 인바운드 규칙 스캔", "mode": "폴링"},
    "access_analyzer": {"label": "IAM Access Analyzer", "desc": "외부 공유(퍼블릭/크로스계정) 리소스 탐지", "mode": "폴링/실시간"},
    "cloudtrail": {"label": "CloudTrail", "desc": "위험 관리 API 호출/루트 활동 탐지", "mode": "폴링/실시간"},
    "vpc_flow_logs": {"label": "VPC Flow Logs", "desc": "대량 REJECT/포트 스캔 이상 트래픽 탐지", "mode": "폴링"},
    "firewall_syslog": {"label": "써드파티 방화벽", "desc": "Palo Alto/Fortinet/Check Point/CEF 로그 수신", "mode": "HTTP 수신"},
    "compliance": {"label": "컴플라이언스 점검", "desc": "KISA/CIS 기반 계정 구성 하드닝 점검", "mode": "폴링"},
}

_NOTIFIER_INFO: dict[str, dict[str, str]] = {
    "slack": {"label": "Slack", "desc": "Incoming Webhook 알림"},
    "email_sns": {"label": "Email (SNS)", "desc": "SNS 토픽 → 이메일 구독 알림"},
    "stdout": {"label": "표준 출력", "desc": "로컬/디버깅용 콘솔 출력"},
}

_REMEDIATOR_INFO: dict[str, dict[str, str]] = {
    "nacl_block_ip": {"label": "NACL IP 차단", "desc": "공격 원격 IP를 NACL deny 규칙으로 차단"},
    "sg_revoke_ingress": {"label": "SG 규칙 회수", "desc": "인터넷 개방 인바운드 규칙 revoke"},
    "s3_public_block": {"label": "S3 퍼블릭 차단", "desc": "공개 버킷에 Public Access Block 적용"},
    "waf_ipset_block": {"label": "WAF IPSet 차단", "desc": "악성 IP를 WAFv2 IPSet에 추가(앱 계층)"},
    "iam_disable_key": {"label": "IAM 키 비활성화", "desc": "침해 의심 액세스 키를 Inactive 전환"},
    "ec2_quarantine": {"label": "EC2 격리", "desc": "침해 의심 인스턴스를 격리 SG로 교체"},
}


def capabilities() -> dict:
    """웹 콘솔용 전체 기능 개요(이름/설명/메타)를 반환."""
    collectors = [
        {"name": n, **_COLLECTOR_INFO.get(n, {"label": n, "desc": "", "mode": ""})}
        for n in _COLLECTOR_FACTORIES
    ]
    notifiers = [
        {"name": n, **_NOTIFIER_INFO.get(n, {"label": n, "desc": ""})}
        for n in _NOTIFIER_INFO
    ]
    remediators = []
    for name, factory in _REMEDIATOR_FACTORIES.items():
        info = _REMEDIATOR_INFO.get(name, {"label": name, "desc": ""})
        supported: list[str] = []
        try:
            # 클래스의 supported_types를 읽기 위해 임시 인스턴스 생성(설정 무관 필드)
            from .config import Config
            inst = factory(Config(collectors=[], notifiers=[]))
            supported = list(getattr(inst, "supported_types", ()) or ())
        except Exception:  # noqa: BLE001
            supported = []
        remediators.append({"name": name, **info, "supported_types": supported})

    return {"collectors": collectors, "notifiers": notifiers, "remediators": remediators}
