"""대응 플레이북 (Response Playbook).

탐지된 finding을 '무엇을, 어떤 순서로 조치해야 하는가'로 매핑하는 **결정론적(비-AI)** 모듈.
finding의 finding_type/source/제목을 보고 카테고리를 정한 뒤, 그 카테고리의
단계별 대응(즉시조치 → 조사 → 봉쇄 → 복구/재발방지)을 돌려준다.

⚠️ 안전 설계(이 프로젝트 전반의 원칙과 동일):
- 이 모듈은 **어떤 명령도 실행하지 않는다.** 반환하는 command는 항상 '참고용 텍스트'이며,
  사용자가 직접 검토 후 수동으로 실행해야 한다.
- 공격자 IP 차단 제안은 **외부(공인) IP에 대해서만** 한다. 사설/루프백 IP는 내부망을
  실수로 차단하지 않도록 차단 대상에서 제외한다.
- 자동으로 방화벽 규칙을 바꾸거나 키를 비활성화하는 등 되돌리기 어려운 동작은 제안만 한다.

설계 참고: ai-security-suite의 response_playbook.py 아이디어를 이 프로젝트의 finding
모델(SecurityFinding)과 컴플라이언스 코드(CA/SC/ZT) 체계에 맞게 새로 구현.
"""

from __future__ import annotations

import ipaddress

from .finding_utils import guardduty_remote_ip
from .models import SecurityFinding

# 내부/비공인 대역 — 이 대역의 IP는 차단 제안 대상에서 제외.
_PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    )
]


def _is_blockable_external_ip(ip: str | None) -> bool:
    """차단을 제안해도 되는 '외부(공인)' IP인지. 사설/루프백/미상 값은 제외."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return False
    return not any(addr in net for net in _PRIVATE_NETS)


# ---------------------------------------------------------------------------
# 카테고리 정의 — 단계별 대응 템플릿
# 각 단계: (phase, title, detail, commands[참고용])
# ---------------------------------------------------------------------------
_PLAYBOOKS: dict[str, dict] = {
    "network_exposure": {
        "label": "네트워크 노출 (열린 포트/보안그룹)",
        "severity_hint": "MEDIUM~HIGH",
        "steps": [
            ("즉시조치", "노출 범위 확인",
             "어떤 보안그룹의 어떤 포트가 0.0.0.0/0으로 열려 있는지 확인하고, 실제로 인스턴스에 연결돼 노출 중인지 파악한다.",
             ["aws ec2 describe-security-groups --group-ids <SG_ID>",
              "aws ec2 describe-network-interfaces --filters Name=group-id,Values=<SG_ID>"]),
            ("조사", "필요성 판단",
             "해당 포트 개방이 업무상 필요한지 확인한다. 관리 포트(22/3389)나 DB 포트가 전체 개방돼 있으면 거의 항상 오설정이다.",
             []),
            ("봉쇄", "규칙 축소",
             "0.0.0.0/0 규칙을 제거하고 필요한 경우 회사/특정 IP로만 제한한다. 기본(default) SG는 규칙을 비우고 사용하지 않는다.",
             ["aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port <PORT> --cidr 0.0.0.0/0"]),
            ("복구/재발방지", "접근 방식 개선",
             "SSH/RDP는 SSM Session Manager로 대체해 포트 노출 자체를 없앤다. IaC(테라폼 등)에 열린 규칙이 재생성되지 않도록 반영한다.",
             []),
        ],
    },
    "brute_force": {
        "label": "무차별 대입 / 원격 로그인 공격",
        "severity_hint": "HIGH",
        "steps": [
            ("즉시조치", "공격 출발지 확인",
             "탐지된 원본 IP와 대상 인스턴스를 확인한다. 로그인 성공 흔적이 있는지 우선 점검한다.",
             []),
            ("조사", "침해 여부 확인",
             "대상 인스턴스의 인증 로그(/var/log/auth.log, 이벤트 로그)에서 성공한 로그인·새 계정·크론/서비스 등록을 확인한다.",
             []),
            ("봉쇄", "출발지 차단 + 노출 축소",
             "공격 IP를 NACL/WAF에서 차단하고, 관리 포트의 인터넷 개방을 제거한다.",
             ["aws ec2 create-network-acl-entry --network-acl-id <ACL_ID> --rule-number <N> --protocol -1 --rule-action deny --egress false --cidr-block <ATTACKER_IP>/32"]),
            ("복구/재발방지", "인증 강화",
             "키 기반 인증 + MFA를 적용하고, 노출된 계정 비밀번호/키를 교체한다. GuardDuty로 지속 탐지한다.",
             []),
        ],
    },
    "credential_exposure": {
        "label": "자격증명 유출 / 권한 오남용",
        "severity_hint": "HIGH~CRITICAL",
        "steps": [
            ("즉시조치", "키 사용 중단 검토",
             "유출 의심 액세스 키/자격증명의 최근 사용 내역을 확인하고, 사용 중이 아니면 비활성화(삭제 아님)를 검토한다.",
             ["aws iam list-access-keys --user-name <USER>",
              "aws iam update-access-key --access-key-id <AKID> --status Inactive --user-name <USER>"]),
            ("조사", "행위 추적",
             "CloudTrail에서 해당 자격증명이 수행한 API 호출(신규 리소스 생성, 권한 변경, 데이터 접근)을 시간순으로 확인한다.",
             ["aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<AKID>"]),
            ("봉쇄", "권한 축소",
             "와일드카드(Action:* / Resource:*) 정책을 제거하고 최소권한으로 재발급한다. 루트 액세스 키는 삭제한다.",
             []),
            ("복구/재발방지", "키 위생",
             "키 정기 교체, 장기 미사용 키 비활성화, 가능한 곳은 임시 자격증명(역할)으로 전환한다.",
             []),
        ],
    },
    "data_exposure": {
        "label": "데이터 노출 (퍼블릭 스토리지/외부 공유)",
        "severity_hint": "HIGH~CRITICAL",
        "steps": [
            ("즉시조치", "공개 차단",
             "노출된 버킷/리소스에 퍼블릭 액세스 차단을 즉시 적용한다.",
             ["aws s3api put-public-access-block --bucket <BUCKET> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"]),
            ("조사", "노출 범위/유출 확인",
             "얼마 동안 공개됐는지, 접근 로그(S3 액세스 로그/CloudTrail 데이터 이벤트)로 외부 다운로드가 있었는지 확인한다.",
             []),
            ("봉쇄", "암호화/정책 정비",
             "기본 암호화를 적용하고 버킷 정책·ACL을 최소 공개로 재정비한다. Access Analyzer로 외부 공유를 재확인한다.",
             ["aws s3api put-bucket-encryption --bucket <BUCKET> --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"]),
            ("복구/재발방지", "조직 차원 차단",
             "계정 레벨 S3 Block Public Access를 켜고, 신규 버킷이 공개되지 않도록 SCP/가드레일을 검토한다.",
             []),
        ],
    },
    "logging_integrity": {
        "label": "로깅 무력화 / 감사 사각지대",
        "severity_hint": "HIGH",
        "steps": [
            ("즉시조치", "로깅 상태 확인",
             "CloudTrail 추적이 켜져 있는지, 최근에 중지/삭제된 이력이 있는지 확인한다. 중지됐다면 재개한다.",
             ["aws cloudtrail get-trail-status --name <TRAIL>",
              "aws cloudtrail start-logging --name <TRAIL>"]),
            ("조사", "누가 변경했는지 추적",
             "CloudTrail을 끈 주체(StopLogging/DeleteTrail 호출자)를 확인하고 정당한 변경인지 판단한다.",
             []),
            ("봉쇄", "다중 리전 추적 구성",
             "조직 전체 다중 리전 CloudTrail + 로그 파일 무결성 검증을 활성화한다.",
             ["aws cloudtrail create-trail --name <TRAIL> --s3-bucket-name <BUCKET> --is-multi-region-trail --enable-log-file-validation"]),
            ("복구/재발방지", "변경 알림",
             "CloudTrail 설정 변경에 EventBridge 알림을 걸고, 로그 버킷에 객체 잠금(Object Lock)을 적용한다.",
             []),
        ],
    },
    "supply_chain": {
        "label": "소프트웨어 공급망 위협",
        "severity_hint": "MEDIUM~HIGH",
        "steps": [
            ("즉시조치", "취약 아티팩트 식별",
             "스캔되지 않은 이미지, 지원 종료(EOL) 런타임, 변경 가능한 태그를 사용하는 리소스를 식별한다.",
             []),
            ("조사", "영향 범위 확인",
             "해당 이미지/런타임을 쓰는 서비스와 배포처를 확인한다.",
             []),
            ("봉쇄", "스캔/불변성 적용",
             "ECR 푸시 스캔과 태그 불변성을 켜고, 취약점 기준 미달 이미지의 배포를 차단한다.",
             ["aws ecr put-image-scanning-configuration --repository-name <REPO> --image-scanning-configuration scanOnPush=true",
              "aws ecr put-image-tag-mutability --repository-name <REPO> --image-tag-mutability IMMUTABLE"]),
            ("복구/재발방지", "최신 유지",
             "런타임/의존성을 최신으로 유지하고, EOL 런타임을 교체한다. 빌드 파이프라인에 스캔 게이트를 둔다.",
             []),
        ],
    },
    "account_hardening": {
        "label": "계정 정책 강화 (비밀번호/MFA)",
        "severity_hint": "MEDIUM",
        "steps": [
            ("즉시조치", "현재 정책 확인",
             "비밀번호 정책과 MFA 적용 현황을 확인한다.",
             ["aws iam get-account-password-policy",
              "aws iam list-users"]),
            ("조사", "취약 계정 파악",
             "MFA가 없는 콘솔 사용자, 약한 정책의 영향을 받는 계정을 파악한다.",
             []),
            ("봉쇄", "정책 강화",
             "강력한 비밀번호 정책(길이 14+, 복잡도, 재사용 제한)을 적용하고 전 사용자 MFA를 요구한다.",
             ["aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --password-reuse-prevention 5"]),
            ("복구/재발방지", "표준화",
             "팀 표준으로 문서화하고 신규 계정 온보딩 절차에 반영한다.",
             []),
        ],
    },
    "malware_c2": {
        "label": "악성코드 / C2 통신 의심",
        "severity_hint": "HIGH~CRITICAL",
        "steps": [
            ("즉시조치", "네트워크 격리",
             "감염 의심 인스턴스를 격리용 보안그룹으로 교체해 네트워크에서 고립시킨다(포렌식 위해 종료하지 않음).",
             []),
            ("조사", "감염 범위 확인",
             "프로세스/네트워크 연결/영속화 흔적을 수집하고, C2 목적지 IP/도메인을 확인한다.",
             []),
            ("봉쇄", "통신 차단",
             "C2 목적지로의 아웃바운드를 차단하고, 관련 자격증명을 교체한다.",
             []),
            ("복구/재발방지", "재구축",
             "감염 인스턴스는 신뢰 이미지로 재생성(재설치)하고, 유입 경로를 제거한다.",
             []),
        ],
    },
    "generic": {
        "label": "일반 대응 절차",
        "severity_hint": "-",
        "steps": [
            ("즉시조치", "finding 확인",
             "탐지 내용과 대상 리소스를 확인하고 오탐 여부를 우선 판단한다.",
             []),
            ("조사", "맥락 파악",
             "관련 로그와 리소스 상태를 확인해 실제 위험도를 평가한다.",
             []),
            ("봉쇄", "노출 축소",
             "필요 시 접근을 제한하고 변경을 되돌린다.",
             []),
            ("복구/재발방지", "원인 제거",
             "근본 원인을 수정하고 재발 방지 조치를 반영한다.",
             []),
        ],
    },
}


def _categorize(finding: SecurityFinding) -> str:
    """finding을 플레이북 카테고리로 분류(결정론적)."""
    ft = (finding.finding_type or "").upper()
    src = (finding.source or "").lower()
    title = (finding.title or "").lower()

    # 컴플라이언스 코드 기반 매핑 (Compliance:AWS/CA-30 등)
    code = ""
    if "/" in ft:
        code = ft.rsplit("/", 1)[-1]  # 예: CA-30
    compliance_map = {
        "CA-01": "data_exposure", "CA-02": "data_exposure", "CA-03": "data_exposure",
        "CA-10": "account_hardening", "CA-12": "account_hardening",
        "CA-11": "credential_exposure", "CA-13": "credential_exposure",
        "CA-20": "logging_integrity",
        "CA-30": "network_exposure",
        "CA-40": "network_exposure", "CA-41": "data_exposure",
        "SC-01": "supply_chain", "SC-02": "supply_chain", "SC-10": "supply_chain",
        "ZT-01": "credential_exposure", "ZT-02": "credential_exposure",
    }
    if code in compliance_map:
        return compliance_map[code]

    # GuardDuty/실시간 유형 키워드
    keys = f"{ft} {title}"
    if any(k in keys for k in ("SSHBRUTEFORCE", "RDPBRUTEFORCE", "BRUTE", "무차별", "PASSWORD")):
        return "brute_force"
    if any(k in keys for k in ("CREDENTIAL", "IAMUSER", "EXFILTRATION", "자격증명")):
        return "credential_exposure"
    if any(k in keys for k in ("BACKDOOR", "C&C", "C2", "TROJAN", "CRYPTOCURRENCY", "악성", "malware")):
        return "malware_c2"
    if any(k in keys for k in ("S3", "PUBLIC", "DATA EXPOSURE", "공개", "노출")):
        return "data_exposure"
    if any(k in keys for k in ("SECURITY GROUP", "보안그룹", "OPEN", "PORT", "SCAN", "스캔", "PORTPROBE")):
        return "network_exposure"
    if any(k in keys for k in ("CLOUDTRAIL", "LOGGING", "로깅")):
        return "logging_integrity"

    # 방화벽 소스는 대개 네트워크 계층 위협
    if src in ("firewall", "firewall_syslog", "security_group", "vpc_flow_logs"):
        return "network_exposure"
    return "generic"


def _attacker_ip(finding: SecurityFinding) -> str | None:
    """finding에서 공격자(원격) IP를 뽑되, 외부 공인 IP만 반환."""
    ip = guardduty_remote_ip(finding)
    if not ip:
        # 방화벽 등 다른 소스는 raw에 src/source_ip로 담길 수 있음
        raw = finding.raw or {}
        for k in ("src", "source_ip", "src_ip", "remote_ip", "attacker_ip"):
            if raw.get(k):
                ip = str(raw[k])
                break
    return ip if _is_blockable_external_ip(ip) else None


def build_playbook(finding: SecurityFinding) -> dict:
    """단일 finding에 대한 대응 플레이북(단계별)을 생성.

    반환 dict는 직렬화 가능(웹/CLI/JSON 공용). 명령은 참고용 텍스트다.
    """
    category = _categorize(finding)
    pb = _PLAYBOOKS[category]

    attacker_ip = _attacker_ip(finding)
    ip_note = None
    if attacker_ip:
        ip_note = (
            f"탐지된 외부 공격 IP: {attacker_ip} — 차단 명령의 <ATTACKER_IP> 자리에 사용할 수 있습니다."
        )

    steps = []
    for phase, title, detail, commands in pb["steps"]:
        cmds = list(commands)
        if attacker_ip:
            cmds = [c.replace("<ATTACKER_IP>", attacker_ip) for c in cmds]
        steps.append({
            "phase": phase,
            "title": title,
            "detail": detail,
            "commands": cmds,
        })

    return {
        "finding_id": finding.id,
        "finding_type": finding.finding_type,
        "source": finding.source,
        "severity": finding.severity.name,
        "category": category,
        "category_label": pb["label"],
        "attacker_ip": attacker_ip,
        "ip_note": ip_note,
        "remediation_hint": finding.remediation or None,
        "steps": steps,
        "safety": (
            "이 플레이북의 명령은 참고용입니다. 자동 실행되지 않으며, 본인 계정에서 "
            "검토 후 직접 실행하세요. 사설/내부 IP는 차단 제안 대상에서 자동 제외됩니다."
        ),
    }


def build_playbooks(findings: list[SecurityFinding]) -> list[dict]:
    """여러 finding에 대한 플레이북 목록(심각도 높은 순)."""
    ordered = sorted(findings, key=lambda x: x.severity, reverse=True)
    return [build_playbook(f) for f in ordered]


def format_playbook_text(pb: dict) -> str:
    """플레이북 하나를 CLI용 텍스트로 포매팅."""
    lines = [
        f"[{pb['severity']}] {pb['finding_id']}  ({pb['category_label']})",
        "-" * 56,
    ]
    if pb.get("ip_note"):
        lines.append(f"🌐 {pb['ip_note']}")
    if pb.get("remediation_hint"):
        lines.append(f"💡 권고: {pb['remediation_hint']}")
    lines.append("")
    for i, s in enumerate(pb["steps"], 1):
        lines.append(f"  {i}. [{s['phase']}] {s['title']}")
        lines.append(f"     {s['detail']}")
        for c in s["commands"]:
            lines.append(f"     $ {c}")
    lines.append("")
    lines.append(f"⚠️  {pb['safety']}")
    return "\n".join(lines)


def format_playbooks_text(playbooks: list[dict]) -> str:
    """여러 플레이북을 CLI용 텍스트로."""
    if not playbooks:
        return "대응 플레이북을 생성할 finding이 없습니다."
    header = f"대응 플레이북 {len(playbooks)}건 (심각도 높은 순)\n" + "=" * 56
    return header + "\n\n" + "\n\n".join(format_playbook_text(p) for p in playbooks)
