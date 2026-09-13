"""안전한 실습 랩 (블루팀 훈련용).

각 랩은 '**본인 소유의 격리된 계정/리전**에서' 다음 사이클을 실습한다:
  1) setup   — 일부러 취약한(그러나 피해 없는) 설정을 만든다.
  2) detect  — 이 에이전트로 점검해 탐지되는지 확인한다.
  3) fix     — 탐지된 항목을 안전하게 원복/강화한다.
  4) teardown— 실습에 만든 자원을 정리한다.

안전 원칙:
- 이 모듈은 **명령을 실행하지 않는다.** dry-run 계획(수행할 AWS CLI 명령 텍스트)만 생성한다.
  실제 실행 여부/시점은 사용자가 본인 환경에서 직접 결정한다.
- 파괴적 작업(자원 삭제 등)은 teardown 단계에만 두고, 사용자 확인을 전제로 안내한다.
- 어떤 랩도 타인의 시스템을 대상으로 하지 않는다(합법적 범위: 본인 소유 계정).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LabStep:
    """실습 단계 하나."""

    name: str          # setup | detect | fix | teardown
    title: str
    explain: str       # 이 단계에서 무엇을/왜 하는지
    commands: tuple[str, ...] = ()   # 참고용 AWS CLI 명령(실행은 사용자 몫)
    destructive: bool = False        # 파괴적(삭제 등) 여부


@dataclass(frozen=True)
class Lab:
    """실습 랩 하나.

    Attributes:
        id: 랩 식별자(예: "LAB-SG-OPEN").
        title: 제목.
        module_id: 연결된 커리큘럼 모듈 id.
        objective: 학습 목표.
        detected_by: 탐지에 관여하는 이 에이전트의 규칙 코드/신호.
        prerequisites: 사전 조건(권한/환경).
        est_minutes: 예상 소요(분).
        cost_note: 비용 주의(무료 범위 여부).
        steps: 단계 목록.
        safety: 안전 유의사항.
    """

    id: str
    title: str
    module_id: str
    objective: str
    detected_by: tuple[str, ...]
    prerequisites: tuple[str, ...]
    est_minutes: int
    cost_note: str
    steps: tuple[LabStep, ...]
    safety: tuple[str, ...] = ()


# 공통 안전 문구
_COMMON_SAFETY = (
    "반드시 본인 소유의 테스트 계정/리전에서만 수행하세요(운영 계정 금지).",
    "이 도구는 명령을 자동 실행하지 않습니다. 아래 명령은 검토 후 직접 실행하세요.",
    "실습 후 teardown 단계로 만든 자원을 반드시 정리하세요.",
)

_REGION = "ap-northeast-2"


_LABS: list[Lab] = [
    Lab(
        id="LAB-SG-OPEN",
        title="열린 보안그룹 만들기 → 탐지 → 잠그기",
        module_id="M01",
        objective="0.0.0.0/0 로 열린 관리 포트가 어떻게 탐지되는지 체험하고 안전하게 잠근다.",
        detected_by=("CA-30", "security_group collector"),
        prerequisites=("EC2 SG 생성/수정 권한", f"리전 {_REGION}"),
        est_minutes=15,
        cost_note="보안그룹 자체는 과금 없음(무료).",
        steps=(
            LabStep(
                name="setup",
                title="테스트용 SG에 열린 인바운드 규칙 추가",
                explain="일부러 22번 포트를 전체 오픈해, '열린 관리 포트'가 위험 신호로 잡히는지 관찰한다. "
                        "인스턴스에 붙이지 않으면 실제 노출은 없다(설정 학습용).",
                commands=(
                    f'aws ec2 create-security-group --group-name lab-open-sg --description "academy lab" --region {_REGION}',
                    'aws ec2 authorize-security-group-ingress --group-id <SG_ID> '
                    f'--protocol tcp --port 22 --cidr 0.0.0.0/0 --region {_REGION}',
                ),
            ),
            LabStep(
                name="detect",
                title="에이전트로 점검",
                explain="컴플라이언스 점검을 돌려 열린 규칙/기본 SG 관련 finding이 나오는지 확인한다.",
                commands=(
                    f'$env:AWS_REGION="{_REGION}"; $env:PYTHONPATH="src"; python -m agent.cli --compliance-report',
                ),
            ),
            LabStep(
                name="fix",
                title="열린 규칙 제거(회사 IP로 제한)",
                explain="0.0.0.0/0 규칙을 지우고 필요한 경우 특정 IP로만 허용한다.",
                commands=(
                    'aws ec2 revoke-security-group-ingress --group-id <SG_ID> '
                    f'--protocol tcp --port 22 --cidr 0.0.0.0/0 --region {_REGION}',
                ),
            ),
            LabStep(
                name="teardown",
                title="테스트 SG 삭제",
                explain="실습용으로 만든 보안그룹을 정리한다.",
                commands=(f'aws ec2 delete-security-group --group-id <SG_ID> --region {_REGION}',),
                destructive=True,
            ),
        ),
        safety=_COMMON_SAFETY + ("실습 SG를 어떤 인스턴스에도 연결하지 마세요(실노출 방지).",),
    ),
    Lab(
        id="LAB-S3-PUBLIC",
        title="퍼블릭 위험 버킷 실습 → 탐지 → 차단",
        module_id="M03",
        objective="S3 퍼블릭 액세스 차단/암호화 미설정이 어떻게 위험으로 잡히는지 체험한다.",
        detected_by=("CA-01", "CA-02", "s3_public_block(remediator)"),
        prerequisites=("S3 버킷 생성/수정 권한", f"리전 {_REGION}"),
        est_minutes=15,
        cost_note="빈 버킷은 사실상 과금 없음. 실습 후 삭제 권장.",
        steps=(
            LabStep(
                name="setup",
                title="계정 차단 없이 테스트 버킷 생성(암호화 미설정 상태 관찰)",
                explain="퍼블릭 차단/기본 암호화가 없는 상태를 만들어 점검이 잡아내는지 본다. "
                        "실제로 데이터를 공개하지는 않는다(오브젝트를 올리지 않음).",
                commands=(
                    f'aws s3api create-bucket --bucket lab-academy-<유니크값> --region {_REGION} '
                    f'--create-bucket-configuration LocationConstraint={_REGION}',
                ),
            ),
            LabStep(
                name="detect",
                title="에이전트로 점검",
                explain="퍼블릭 차단/암호화 미설정 finding 확인.",
                commands=(
                    f'$env:AWS_REGION="{_REGION}"; $env:PYTHONPATH="src"; python -m agent.cli --compliance-report',
                ),
            ),
            LabStep(
                name="fix",
                title="퍼블릭 차단 + 기본 암호화 적용",
                explain="Block Public Access와 기본 암호화를 설정한다.",
                commands=(
                    'aws s3api put-public-access-block --bucket lab-academy-<유니크값> '
                    '--public-access-block-configuration '
                    'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true',
                    'aws s3api put-bucket-encryption --bucket lab-academy-<유니크값> '
                    '--server-side-encryption-configuration '
                    "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
                ),
            ),
            LabStep(
                name="teardown",
                title="테스트 버킷 삭제",
                explain="실습 버킷을 비우고 삭제한다.",
                commands=('aws s3 rb s3://lab-academy-<유니크값> --force',),
                destructive=True,
            ),
        ),
        safety=_COMMON_SAFETY + ("실습 버킷에 실제 민감 데이터를 절대 올리지 마세요.",),
    ),
    Lab(
        id="LAB-IAM-PWPOLICY",
        title="약한 비밀번호 정책 → 탐지 → 강화",
        module_id="M05",
        objective="비밀번호 정책 미흡이 어떻게 잡히는지 보고 안전한 기준으로 강화한다.",
        detected_by=("CA-10",),
        prerequisites=("IAM 계정 정책 변경 권한(계정 단위)",),
        est_minutes=10,
        cost_note="과금 없음.",
        steps=(
            LabStep(
                name="detect",
                title="현재 정책으로 먼저 점검",
                explain="정책이 없거나 약하면 CA-10 위반으로 잡힌다(대개 기본 계정은 미설정).",
                commands=(
                    f'$env:AWS_REGION="{_REGION}"; $env:PYTHONPATH="src"; python -m agent.cli --compliance-report',
                ),
            ),
            LabStep(
                name="fix",
                title="강력한 비밀번호 정책 적용",
                explain="길이 14자+복잡도+재사용 제한으로 강화한다.",
                commands=(
                    'aws iam update-account-password-policy --minimum-password-length 14 '
                    '--require-symbols --require-numbers --require-uppercase-characters '
                    '--require-lowercase-characters --password-reuse-prevention 5',
                ),
            ),
            LabStep(
                name="teardown",
                title="(선택) 원복",
                explain="계정 공용 설정이므로 팀 표준을 유지하는 것이 좋다. 되돌리려면 정책 삭제.",
                commands=('aws iam delete-account-password-policy',),
                destructive=True,
            ),
        ),
        safety=_COMMON_SAFETY + ("계정 전역 설정이므로 공용 테스트 계정에서만 변경하세요.",),
    ),
    Lab(
        id="LAB-IAM-STALE-KEY",
        title="오래된 액세스 키 탐지 실습",
        module_id="M04",
        objective="장기 미사용 액세스 키가 제로트러스트 관점에서 어떻게 위험으로 잡히는지 이해한다.",
        detected_by=("ZT-02", "CA-13"),
        prerequisites=("IAM 읽기 권한(ListAccessKeys 등)",),
        est_minutes=10,
        cost_note="과금 없음. (읽기 전용 점검 중심)",
        steps=(
            LabStep(
                name="detect",
                title="에이전트로 키 상태 점검",
                explain="오래된/다중 활성 키가 있으면 ZT-02/CA-13으로 잡힌다.",
                commands=(
                    f'$env:AWS_REGION="{_REGION}"; $env:PYTHONPATH="src"; python -m agent.cli --compliance-report',
                    'aws iam list-access-keys  # 키 목록/생성일 확인(수동 대조)',
                ),
            ),
            LabStep(
                name="fix",
                title="미사용 키 비활성화(주의)",
                explain="사용 중이지 않음을 확인한 뒤 비활성화한다. 즉시 삭제보다 비활성화 후 관찰을 권장.",
                commands=(
                    'aws iam update-access-key --access-key-id <AKID> --status Inactive --user-name <USER>',
                ),
                destructive=True,
            ),
        ),
        safety=_COMMON_SAFETY + ("사용 중인 키를 비활성화하면 서비스가 중단될 수 있습니다. 반드시 사용여부 확인 후 진행.",),
    ),
    Lab(
        id="LAB-CT-DISABLED",
        title="로깅 사각지대 이해 → 다중 리전 CloudTrail 켜기",
        module_id="M06",
        objective="CloudTrail 미구성이 왜 고위험인지 체감하고 다중 리전 추적을 구성한다.",
        detected_by=("CA-20",),
        prerequisites=("CloudTrail/S3 생성 권한",),
        est_minutes=20,
        cost_note="추적 자체는 저비용이나, 로그 저장 S3/데이터 이벤트는 소액 과금 가능. 실습 후 정리 권장.",
        steps=(
            LabStep(
                name="detect",
                title="현재 상태 점검",
                explain="다중 리전 추적이 없으면 CA-20으로 잡힌다.",
                commands=(
                    f'$env:AWS_REGION="{_REGION}"; $env:PYTHONPATH="src"; python -m agent.cli --compliance-report',
                ),
            ),
            LabStep(
                name="fix",
                title="다중 리전 CloudTrail 생성",
                explain="로그 버킷을 만들고 다중 리전 추적을 켠 뒤 로깅을 시작한다.",
                commands=(
                    'aws s3api create-bucket --bucket lab-ct-logs-<유니크값> '
                    f'--region {_REGION} --create-bucket-configuration LocationConstraint={_REGION}',
                    'aws cloudtrail create-trail --name lab-trail --s3-bucket-name lab-ct-logs-<유니크값> '
                    '--is-multi-region-trail --enable-log-file-validation',
                    'aws cloudtrail start-logging --name lab-trail',
                ),
            ),
            LabStep(
                name="teardown",
                title="추적/버킷 정리",
                explain="실습 자원을 정리한다.",
                commands=(
                    'aws cloudtrail delete-trail --name lab-trail',
                    'aws s3 rb s3://lab-ct-logs-<유니크값> --force',
                ),
                destructive=True,
            ),
        ),
        safety=_COMMON_SAFETY + ("운영 계정에서는 이미 CloudTrail이 있을 수 있으니 중복 생성/삭제에 주의.",),
    ),
    Lab(
        id="LAB-GD-SAMPLE",
        title="GuardDuty 샘플 finding으로 탐지→알림 흐름 체험",
        module_id="M02",
        objective="실제 공격 없이 GuardDuty 샘플 이벤트로 탐지→정규화→알림→대응(dry-run) 파이프라인을 관찰한다.",
        detected_by=("GuardDuty: SSHBruteForce 등", "nacl_block_ip(remediator, dry-run)"),
        prerequisites=("(선택) GuardDuty 활성화 — 30일 무료 체험", "웹 콘솔은 자격증명 불필요"),
        est_minutes=15,
        cost_note="샘플 finding 생성은 무료. 실제 탐지는 GuardDuty 유료(무료 체험 활용).",
        steps=(
            LabStep(
                name="detect",
                title="웹 콘솔에서 GuardDuty 샘플 이벤트 분석(권장, 자격증명 불필요)",
                explain="웹 콘솔의 'AWS 이벤트' 탭에서 GuardDuty 샘플을 넣고 전체 파이프라인 미리보기로 "
                        "정규화→필터→알림 메시지→자동대응 dry-run 계획을 관찰한다.",
                commands=(
                    'python -m agent.webui.server   # http://127.0.0.1:8080 → AWS 이벤트 탭',
                ),
            ),
            LabStep(
                name="fix",
                title="(선택) 실제 GuardDuty로 샘플 finding 생성",
                explain="GuardDuty를 켠 계정에서 샘플 finding을 만들어 EventBridge→에이전트→Slack 흐름을 확인한다.",
                commands=(
                    f'aws guardduty create-sample-findings --detector-id <DETECTOR_ID> --region {_REGION}',
                ),
            ),
            LabStep(
                name="teardown",
                title="(선택) 비용 방지",
                explain="테스트만 하려면 GuardDuty를 다시 비활성화해 과금을 막는다.",
                commands=('# 콘솔: GuardDuty → 설정 → 비활성화(또는 detector 삭제)',),
                destructive=True,
            ),
        ),
        safety=_COMMON_SAFETY + ("샘플 finding은 가짜 위협입니다. 실제 공격 트래픽을 생성하지 마세요.",),
    ),
    Lab(
        id="LAB-FW-PARSE",
        title="방화벽 로그 읽기 실습(자격증명 불필요)",
        module_id="M08",
        objective="Fortinet/Palo Alto/Check Point 로그 한 줄이 통합 finding으로 정규화되는 과정을 체험한다.",
        detected_by=("firewall collector(자동 벤더 인식)",),
        prerequisites=("없음(웹 콘솔/CLI 로컬 실행)",),
        est_minutes=10,
        cost_note="완전 무료(AWS 자원 불필요).",
        steps=(
            LabStep(
                name="detect",
                title="웹 콘솔 방화벽 탭에서 샘플 로그 분석",
                explain="'써드파티 방화벽 로그' 탭의 샘플 칩을 눌러 벤더 자동 인식·심각도·출발지 IP 정규화를 관찰한다.",
                commands=('python -m agent.webui.server   # http://127.0.0.1:8080 → 방화벽 탭',),
            ),
        ),
        safety=_COMMON_SAFETY,
    ),
]


def all_labs() -> list[Lab]:
    return list(_LABS)


def lab_by_id(lab_id: str) -> Lab | None:
    for l in _LABS:
        if l.id == lab_id:
            return l
    return None


def _step_to_dict(s: LabStep) -> dict:
    return {
        "name": s.name,
        "title": s.title,
        "explain": s.explain,
        "commands": list(s.commands),
        "destructive": s.destructive,
    }


def labs_summary() -> list[dict]:
    """웹/CLI 표시용 랩 목록 요약."""
    out: list[dict] = []
    for l in _LABS:
        out.append(
            {
                "id": l.id,
                "title": l.title,
                "module_id": l.module_id,
                "objective": l.objective,
                "detected_by": list(l.detected_by),
                "prerequisites": list(l.prerequisites),
                "est_minutes": l.est_minutes,
                "cost_note": l.cost_note,
                "steps": [_step_to_dict(s) for s in l.steps],
                "safety": list(l.safety),
            }
        )
    return out


def plan_lab(lab_id: str, *, execute: bool = False) -> dict:
    """실습 랩 실행 '계획'을 생성한다.

    안전상 이 함수는 **명령을 실행하지 않는다**. execute=True 여도 실제 실행은 하지 않고,
    '사용자가 직접 실행해야 한다'는 안내와 함께 계획만 반환한다(파괴적 단계 경고 포함).
    """
    lab = lab_by_id(lab_id)
    if lab is None:
        return {"ok": False, "error": f"알 수 없는 랩: {lab_id}"}

    steps = []
    has_destructive = False
    for s in lab.steps:
        if s.destructive:
            has_destructive = True
        steps.append(_step_to_dict(s))

    note = (
        "이 계획은 참고용입니다. 명령은 자동 실행되지 않으며, 본인 소유 테스트 계정에서 "
        "직접 검토 후 실행하세요."
    )
    if execute:
        note = (
            "안전을 위해 이 도구는 실습 명령을 자동 실행하지 않습니다. "
            "아래 단계를 본인 계정에서 직접 실행하세요."
        ) + (" 특히 destructive=true 단계는 자원을 삭제/비활성화하므로 주의하세요." if has_destructive else "")

    return {
        "ok": True,
        "id": lab.id,
        "title": lab.title,
        "module_id": lab.module_id,
        "objective": lab.objective,
        "detected_by": list(lab.detected_by),
        "prerequisites": list(lab.prerequisites),
        "est_minutes": lab.est_minutes,
        "cost_note": lab.cost_note,
        "safety": list(lab.safety),
        "has_destructive": has_destructive,
        "executed": False,  # 항상 False: 자동 실행하지 않음
        "note": note,
        "steps": steps,
    }
