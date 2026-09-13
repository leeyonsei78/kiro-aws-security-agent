"""화이트해커 양성 커리큘럼 (방어자 관점).

각 모듈은 하나의 공격 유형을 다루되, **방어자가 알아야 할 만큼**만 개념을 설명하고
곧바로 (1) MITRE ATT&CK 매핑, (2) 이 에이전트의 어떤 탐지 규칙이 잡는지,
(3) 실무 방어 조치, (4) 연결된 실습 랩으로 이어준다.

여기에는 실행 가능한 공격 코드/익스플로잇/무기화 페이로드가 없다.
전부 '이런 공격이 있고, 이렇게 탐지하고, 이렇게 막는다'는 방어 지식이다.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Module:
    """학습 모듈 하나.

    Attributes:
        id: 모듈 식별자 (예: "M01").
        title: 제목.
        level: 난이도 ("입문" | "중급" | "심화").
        domain: 영역 (예: "네트워크", "자격증명/IAM", "데이터", "로깅/탐지", "공급망").
        summary: 한 줄 요약.
        attacker_view: 공격자가 이 기법으로 무엇을 노리는지(개념적 이해, 코드 없음).
        blue_view: 방어자가 무엇을 관찰/차단해야 하는지.
        mitre: 매핑되는 MITRE ATT&CK 기술 ID/이름.
        detected_by: 이 에이전트에서 관련된 탐지 규칙/신호(컴플라이언스 코드 또는 GuardDuty 타입 등).
        defenses: 실무 방어 조치 목록.
        lab_ids: 연결된 실습 랩 id 목록.
        references: 참고 표준/링크(짧게).
    """

    id: str
    title: str
    level: str
    domain: str
    summary: str
    attacker_view: str
    blue_view: str
    mitre: tuple[str, ...] = ()
    detected_by: tuple[str, ...] = ()
    defenses: tuple[str, ...] = ()
    lab_ids: tuple[str, ...] = ()
    references: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# 커리큘럼 정의 — 방어자 관점, 이 에이전트의 탐지 규칙과 1:1로 연결
# ---------------------------------------------------------------------------
_MODULES: list[Module] = [
    Module(
        id="M01",
        title="공격 표면 넓히기: 개방된 보안그룹/기본 SG",
        level="입문",
        domain="네트워크",
        summary="열려 있는 인바운드 규칙과 기본(default) 보안그룹이 어떻게 침투 통로가 되는지 이해하고 탐지한다.",
        attacker_view=(
            "공격자는 인터넷에 열린 포트(22/3389/DB 포트 등)를 스캔해 진입점을 찾는다. "
            "0.0.0.0/0 로 열린 관리 포트나, 아무 규칙이나 붙은 기본 보안그룹은 최우선 표적이다."
        ),
        blue_view=(
            "'누가 어떤 포트를 인터넷 전체에 열어 두었는가'를 지속 점검한다. "
            "기본 SG에는 규칙이 없어야 하고(사용 금지 권장), 관리 포트는 특정 IP로만 제한한다."
        ),
        mitre=("T1595 Active Scanning", "T1190 Exploit Public-Facing Application"),
        detected_by=("CA-30 기본 보안그룹 허용 규칙 존재", "security_group collector(열린 인바운드 탐지)"),
        defenses=(
            "관리 포트(22/3389)는 회사 IP/CIDR로만 허용, 0.0.0.0/0 금지",
            "기본 SG의 인바운드/아웃바운드 규칙 제거, 전용 SG만 사용",
            "SSM Session Manager로 SSH 없는 접속 전환",
        ),
        lab_ids=("LAB-SG-OPEN",),
        references=("CIS AWS 5.x", "KISA CII(네트워크)"),
    ),
    Module(
        id="M02",
        title="자격증명 무차별 대입/원격 로그인 공격",
        level="입문",
        domain="자격증명/IAM",
        summary="SSH/RDP 브루트포스가 어떻게 진행되며, GuardDuty와 이 에이전트가 어떻게 탐지·자동대응하는지 배운다.",
        attacker_view=(
            "열린 SSH/RDP에 대해 사전(dictionary)·자동화 도구로 로그인 시도를 반복한다. "
            "성공하면 인스턴스를 장악하거나 측면 이동의 발판으로 삼는다."
        ),
        blue_view=(
            "짧은 시간에 다수의 실패 로그인, 낯선 지역/IP에서의 접속 시도를 탐지한다. "
            "탐지 시 해당 원본 IP를 NACL로 차단하는 자동 대응을 검토한다(이 에이전트의 nacl_block_ip)."
        ),
        mitre=("T1110 Brute Force", "T1021 Remote Services"),
        detected_by=(
            "GuardDuty: UnauthorizedAccess:EC2/SSHBruteForce",
            "remediator: nacl_block_ip (원본 IP 차단, 기본 dry-run)",
        ),
        defenses=(
            "관리 포트 노출 최소화 + MFA + 키 기반 인증",
            "GuardDuty 활성화로 브루트포스 자동 탐지",
            "탐지 IP 자동 차단(dry-run으로 먼저 검증 후 적용)",
        ),
        lab_ids=("LAB-GD-SAMPLE",),
        references=("MITRE ATT&CK", "AWS GuardDuty finding types"),
    ),
    Module(
        id="M03",
        title="데이터 노출: 퍼블릭 S3 버킷",
        level="입문",
        domain="데이터",
        summary="스토리지 오설정으로 인한 대규모 정보 유출 사례를 이해하고, 퍼블릭 차단/암호화를 점검한다.",
        attacker_view=(
            "공격자는 잘못 공개된 버킷을 검색해 민감 데이터를 그대로 내려받는다. "
            "익스플로잇 없이 '오설정'만으로 유출이 일어나는 대표 사례다."
        ),
        blue_view=(
            "계정/버킷 단위 퍼블릭 액세스 차단(Block Public Access)과 기본 암호화를 강제한다. "
            "Access Analyzer로 외부 공유를 상시 탐지한다."
        ),
        mitre=("T1530 Data from Cloud Storage Object", "T1595 Active Scanning"),
        detected_by=(
            "CA-01 S3 퍼블릭 액세스 차단 미설정",
            "CA-02 S3 기본 암호화 미설정",
            "Security Hub: S3 public / Access Analyzer 외부공유",
            "remediator: s3_public_block",
        ),
        defenses=(
            "계정 레벨 S3 Block Public Access 활성화",
            "버킷 기본 암호화(SSE-S3/KMS) 적용",
            "Access Analyzer로 외부 공유 상시 점검",
        ),
        lab_ids=("LAB-S3-PUBLIC",),
        references=("CIS AWS 2.1.x", "KISA CII(데이터 보호)"),
    ),
    Module(
        id="M04",
        title="과도한 권한과 자격증명 탈취(권한 상승/측면 이동)",
        level="중급",
        domain="자격증명/IAM",
        summary="와일드카드 관리자 권한, 오래된 액세스 키, 자격증명 유출이 어떻게 권한 상승으로 이어지는지 배운다.",
        attacker_view=(
            "탈취한 키가 '*:*' 같은 광범위 권한을 가지면 계정 전체를 장악할 수 있다. "
            "장기 미사용 키·루트 액세스 키는 유출 시 피해가 크다."
        ),
        blue_view=(
            "최소권한 원칙을 강제하고, 와일드카드 관리자 정책·루트 키·오래된 키를 상시 탐지한다. "
            "자격증명 이상 사용 탐지 시 키 비활성화 대응을 검토한다."
        ),
        mitre=("T1078 Valid Accounts", "T1098 Account Manipulation", "T1548 Abuse Elevation Control"),
        detected_by=(
            "CA-11 루트 액세스 키 존재",
            "CA-13 다중 활성 액세스 키",
            "ZT-01 와일드카드 관리자 정책",
            "ZT-02 오래된(미사용) 액세스 키",
            "GuardDuty: InstanceCredentialExfiltration / remediator: iam_disable_key",
        ),
        defenses=(
            "루트 액세스 키 삭제, 루트는 MFA만",
            "와일드카드(Action:* / Resource:*) 정책 제거, 최소권한",
            "액세스 키 정기 교체, 90일+ 미사용 키 비활성화",
        ),
        lab_ids=("LAB-IAM-STALE-KEY",),
        references=("CIS AWS 1.x", "제로트러스트 원칙"),
    ),
    Module(
        id="M05",
        title="계정 정책 약화: 비밀번호 정책/MFA 미흡",
        level="입문",
        domain="자격증명/IAM",
        summary="약한 비밀번호 정책과 MFA 부재가 무차별 대입·자격증명 도용에 어떻게 활용되는지 이해한다.",
        attacker_view=(
            "짧고 단순한 비밀번호, MFA 없음은 온라인/오프라인 추측 공격의 성공률을 높인다."
        ),
        blue_view=(
            "강력한 비밀번호 정책(길이 14+, 복잡도, 재사용 제한)과 전 사용자 MFA를 강제한다."
        ),
        mitre=("T1110 Brute Force", "T1078 Valid Accounts"),
        detected_by=("CA-10 IAM 비밀번호 정책 미흡", "CA-12 IAM 사용자 MFA 미설정"),
        defenses=(
            "비밀번호 최소 14자 + 대소문자/숫자/기호 + 재사용 제한",
            "콘솔 접근 전 사용자 MFA 필수화",
        ),
        lab_ids=("LAB-IAM-PWPOLICY",),
        references=("CIS AWS 1.8~1.11", "KISA CII(계정관리)"),
    ),
    Module(
        id="M06",
        title="탐지 회피: 로깅 무력화",
        level="중급",
        domain="로깅/탐지",
        summary="공격자가 CloudTrail을 끄거나 우회해 흔적을 지우는 방식을 이해하고, 로깅 무결성을 보장한다.",
        attacker_view=(
            "침입 후 공격자는 CloudTrail 비활성화·로그 삭제로 흔적을 지워 탐지·포렌식을 방해한다."
        ),
        blue_view=(
            "다중 리전 CloudTrail을 항상 켜 두고, 로그 파일 무결성 검증과 변경 알림을 건다. "
            "'추적이 꺼졌다'는 사실 자체가 고위험 이벤트다."
        ),
        mitre=("T1562 Impair Defenses", "T1070 Indicator Removal"),
        detected_by=("CA-20 다중 리전 CloudTrail 미구성", "cloudtrail collector"),
        defenses=(
            "조직 전체 다중 리전 CloudTrail + 로그 파일 무결성 검증",
            "CloudTrail 설정 변경에 EventBridge 알림",
            "로그 버킷 접근 제한 + 객체 잠금(Object Lock)",
        ),
        lab_ids=("LAB-CT-DISABLED",),
        references=("CIS AWS 3.x", "KISA CII(감사/로깅)"),
    ),
    Module(
        id="M07",
        title="소프트웨어 공급망 위협",
        level="심화",
        domain="공급망",
        summary="취약한 컨테이너 이미지/오래된 런타임/변조 가능한 태그가 어떻게 공격 경로가 되는지 배운다.",
        attacker_view=(
            "공격자는 스캔되지 않은 이미지의 취약점, 변경 가능한(mutable) 태그로의 이미지 바꿔치기, "
            "지원 종료된 런타임의 알려진 결함을 노린다."
        ),
        blue_view=(
            "ECR 푸시 시 자동 스캔·태그 불변성을 강제하고, 지원 종료(EOL) 런타임 사용을 탐지한다."
        ),
        mitre=("T1195 Supply Chain Compromise", "T1525 Implant Internal Image"),
        detected_by=(
            "SC-01 ECR 푸시 스캔 미설정",
            "SC-02 ECR 태그 불변성 미설정",
            "SC-10 Lambda 지원종료 런타임 사용",
        ),
        defenses=(
            "ECR scan-on-push 활성화 + 취약점 기준 배포 차단",
            "이미지 태그 불변성(immutable) 설정",
            "런타임/의존성 최신 유지, EOL 런타임 교체",
        ),
        lab_ids=(),
        references=("SLSA", "KISA(공급망)"),
    ),
    Module(
        id="M08",
        title="방화벽 로그로 위협 읽기(경계 방어)",
        level="중급",
        domain="네트워크",
        summary="Fortinet/Palo Alto/Check Point 로그에서 스캔·침투·악성코드 신호를 읽고 통합 분석한다.",
        attacker_view=(
            "포트 스캔, 취약점 공격(예: 인젝션 시도), 악성코드 콜백(C2) 등은 경계 방화벽 로그에 흔적을 남긴다."
        ),
        blue_view=(
            "벤더별 로그를 통합 형식으로 정규화해 심각도·출발지 IP 기준으로 우선순위를 매기고, "
            "반복 공격 IP를 차단 목록에 반영한다."
        ),
        mitre=("T1595 Active Scanning", "T1071 Application Layer Protocol", "T1046 Network Service Discovery"),
        detected_by=(
            "firewall collector(fortinet/paloalto/checkpoint/cef 자동 인식)",
            "remediator: waf_ipset_block / nacl_block_ip",
        ),
        defenses=(
            "방화벽 로그 중앙 수집 + 통합 정규화",
            "반복 공격 IP를 WAF IPSet/NACL로 차단",
            "심각도 임계값 기반 알림(Slack)",
        ),
        lab_ids=("LAB-FW-PARSE",),
        references=("MITRE ATT&CK", "벤더 로그 포맷"),
    ),
]


def all_modules() -> list[Module]:
    return list(_MODULES)


def module_by_id(module_id: str) -> Module | None:
    for m in _MODULES:
        if m.id == module_id:
            return m
    return None


def modules_summary() -> list[dict]:
    """웹/CLI 표시용 요약(직렬화 가능한 dict)."""
    out: list[dict] = []
    for m in _MODULES:
        out.append(
            {
                "id": m.id,
                "title": m.title,
                "level": m.level,
                "domain": m.domain,
                "summary": m.summary,
                "attacker_view": m.attacker_view,
                "blue_view": m.blue_view,
                "mitre": list(m.mitre),
                "detected_by": list(m.detected_by),
                "defenses": list(m.defenses),
                "lab_ids": list(m.lab_ids),
                "references": list(m.references),
            }
        )
    return out
