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
    "guardduty": {
        "label": "Amazon GuardDuty", "mode": "폴링/실시간",
        "desc": "AWS의 위협 탐지 서비스. 머신러닝으로 계정의 악성 활동을 자동 탐지합니다.",
        "collects": "GuardDuty가 만든 finding(위협 탐지 결과) — 유형, 심각도, 대상 리소스, 공격자 IP 등",
        "example": "예) EC2 서버에 SSH 무차별 대입 공격, 유출된 자격증명 사용, 암호화폐 채굴 통신 탐지",
    },
    "securityhub": {
        "label": "AWS Security Hub", "mode": "폴링/실시간",
        "desc": "여러 보안 서비스의 결과를 한곳에 모으는 통합 대시보드 서비스입니다.",
        "collects": "GuardDuty·Inspector·Macie 등에서 온 통합 finding(ASFF 표준 형식)",
        "example": "예) S3 버킷이 공개됨, 규정 준수 검사 실패 등을 한 번에 수집",
    },
    "security_group": {
        "label": "Security Group (방화벽 규칙)", "mode": "폴링",
        "desc": "Security Group은 AWS 리소스의 가상 방화벽입니다. 어떤 IP/포트가 접근 가능한지 정의합니다.",
        "collects": "전체 보안 그룹을 스캔해, 인터넷 전체(0.0.0.0/0)에 위험 포트가 열린 규칙을 찾음",
        "example": "예) SSH(22)·RDP(3389)·DB(3306) 포트가 인터넷 전체에 개방된 설정을 탐지",
    },
    "access_analyzer": {
        "label": "IAM Access Analyzer", "mode": "폴링/실시간",
        "desc": "내 계정의 리소스가 외부(다른 계정·인터넷)에 공유되고 있는지 분석하는 서비스입니다.",
        "collects": "외부에서 접근 가능한 S3/IAM 역할/KMS 키 등의 finding",
        "example": "예) S3 버킷이 퍼블릭 공개됨, IAM 역할을 외부 계정이 맡을 수 있게 설정됨",
    },
    "cloudtrail": {
        "label": "CloudTrail (감사 로그)", "mode": "폴링/실시간",
        "desc": "CloudTrail은 계정에서 일어난 모든 API 호출(누가·언제·무엇을 했는지)을 기록합니다.",
        "collects": "위험한 관리 작업 로그 — 로깅 중지, 정책/키 변경, 루트 계정 사용 등",
        "example": "예) 누군가 CloudTrail 로깅을 끄거나, 루트 계정으로 로그인해 설정을 변경",
    },
    "vpc_flow_logs": {
        "label": "VPC Flow Logs (네트워크 로그)", "mode": "폴링",
        "desc": "VPC(가상 네트워크) 안팎으로 오간 트래픽 기록입니다. 누가 어디로 접속을 시도했는지 알 수 있습니다.",
        "collects": "CloudWatch Logs에 쌓인 흐름 로그를 분석해 비정상 트래픽 패턴을 집계",
        "example": "예) 한 IP가 짧은 시간에 수백 번 연결 거부(REJECT)당함 = 포트 스캔/공격 의심",
    },
    "firewall_syslog": {
        "label": "써드파티 방화벽", "mode": "HTTP 수신",
        "desc": "AWS 밖의 상용 방화벽 장비(Palo Alto/Fortinet/Check Point)가 보낸 로그를 수신합니다.",
        "collects": "방화벽이 webhook/syslog로 전송한 위협·차단 로그를 파싱해 통합 형식으로 변환",
        "example": "예) FortiGate가 탐지한 백도어 통신, Palo Alto가 차단한 취약점 공격 로그",
    },
    "compliance": {
        "label": "컴플라이언스 점검", "mode": "폴링",
        "desc": "계정 설정이 보안 기준(KISA/CIS)에 맞는지 규칙으로 점검합니다. '자체 보안 점검'에 해당합니다.",
        "collects": "S3·IAM·EC2·RDS·ECR 등의 구성을 16개 항목으로 점검해 위반을 찾고 점수화",
        "example": "예) 루트 계정 액세스 키 존재, MFA 미설정, 암호화 미적용, 오래된 키 등 위반 탐지",
    },
}

_NOTIFIER_INFO: dict[str, dict[str, str]] = {
    "slack": {"label": "Slack", "desc": "Slack 채널로 알림 전송(Incoming Webhook). 팀이 실시간으로 확인.",
              "collects": "심각도 이상 finding을 요약해 메시지로 발송"},
    "email_sns": {"label": "Email (SNS)", "desc": "AWS SNS 토픽에 이메일을 구독해 알림 수신.",
                  "collects": "finding 요약 + 권고 조치를 이메일 본문으로 발송"},
    "stdout": {"label": "표준 출력", "desc": "화면(콘솔)에 출력. 로컬 테스트/디버깅용.",
               "collects": "finding을 텍스트로 콘솔에 출력"},
}

_REMEDIATOR_INFO: dict[str, dict[str, str]] = {
    "nacl_block_ip": {"label": "NACL IP 차단",
                      "desc": "공격자 IP를 네트워크 ACL(서브넷 방화벽)에서 차단합니다.",
                      "example": "SSH 무차별 대입 공격자 IP 203.0.113.5를 서브넷에서 deny"},
    "sg_revoke_ingress": {"label": "SG 규칙 회수",
                          "desc": "인터넷에 열린 위험한 보안 그룹 인바운드 규칙을 제거합니다.",
                          "example": "0.0.0.0/0 → 22(SSH) 개방 규칙을 자동 회수"},
    "s3_public_block": {"label": "S3 퍼블릭 차단",
                        "desc": "공개된 S3 버킷에 퍼블릭 액세스 차단을 적용합니다.",
                        "example": "공개 노출된 버킷의 4개 퍼블릭 차단 옵션을 모두 켬"},
    "waf_ipset_block": {"label": "WAF IPSet 차단",
                        "desc": "악성 IP를 웹 방화벽(WAF) 차단 목록에 추가합니다(앱 계층).",
                        "example": "악성 IP를 WAF IPSet에 넣어 CloudFront/ALB 앞단에서 차단"},
    "iam_disable_key": {"label": "IAM 키 비활성화",
                        "desc": "침해가 의심되는 액세스 키를 비활성화(Inactive)합니다. 삭제가 아니라 되돌릴 수 있음.",
                        "example": "유출된 액세스 키 AKIA...를 즉시 Inactive 처리"},
    "ec2_quarantine": {"label": "EC2 격리",
                       "desc": "감염 의심 서버를 '격리용 보안 그룹'으로 교체해 네트워크에서 고립시킵니다(포렌식 보존).",
                       "example": "백도어 통신이 탐지된 인스턴스를 격리 SG로 교체(종료하지 않음)"},
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
