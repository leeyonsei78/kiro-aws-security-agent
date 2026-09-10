"""모니터링 대상(target) 관리.

'어느 AWS 계정/리전에서, 어떤 collector로, 어떤 심각도 이상을 모니터링할지'를
- 현재 상태로 요약(target_status)하고,
- 사용자가 지정한 값으로 실제 적용 가능한 설정(환경변수/SAM/Terraform)을 생성(build_target_setup)한다.

웹 콘솔은 AWS 자격증명이 없으므로 여기서 실제 스캔은 하지 않는다.
대신 '대상을 이렇게 지정하면 된다'는 설정 스니펫을 만들어 배포/CLI에 쓰도록 한다.
"""

from __future__ import annotations

import os

from .config import Config
from .registry import _COLLECTOR_FACTORIES  # noqa: F401 - 내부 collector 목록 소스
from .registry import _COLLECTOR_INFO

# 실제 AWS 계정을 대상으로 하는(자격증명 필요) collector 목록.
# firewall_syslog는 수신형이라 계정 스캔 대상이 아님.
_ACCOUNT_COLLECTORS = [n for n in _COLLECTOR_FACTORIES if n != "firewall_syslog"]


def all_collector_names() -> list[str]:
    return list(_COLLECTOR_FACTORIES.keys())


def _has_aws_credentials() -> bool:
    """환경/프로파일에 AWS 자격증명 단서가 있는지(대략적)."""
    if os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE"):
        return True
    if os.getenv("AWS_ROLE_ARN") or os.getenv("AWS_WEB_IDENTITY_TOKEN_FILE"):
        return True
    # Lambda 실행 환경 표시
    if os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
        return True
    return False


def target_status(cfg: Config) -> dict:
    """현재 모니터링 대상 상태 요약(웹 표시용)."""
    active = cfg.collectors or ["guardduty", "securityhub"]
    return {
        "region": cfg.region or "(미지정 — SDK 기본/Lambda 리전 사용)",
        "region_set": bool(cfg.region),
        "account": "(배포된 계정 = Lambda 실행 계정 / 로컬은 자격증명 계정)",
        "active_collectors": active,
        "min_severity": cfg.min_severity.name,
        "lookback_minutes": cfg.lookback_minutes,
        "credentials_detected": _has_aws_credentials(),
        "note": (
            "웹 콘솔은 실제 AWS를 스캔하지 않습니다(자격증명 불필요). "
            "실제 대상은 에이전트를 배포한 계정과 아래 설정으로 정해집니다."
        ),
        "available_collectors": [
            {"name": n, "label": _COLLECTOR_INFO.get(n, {}).get("label", n),
             "account_scan": n in _ACCOUNT_COLLECTORS}
            for n in all_collector_names()
        ],
    }


def build_target_setup(*, region: str, collectors: list[str], min_severity: str,
                       lookback_minutes: int = 60) -> dict:
    """지정한 대상으로 적용 가능한 설정 스니펫(env/SAM/Terraform)을 생성.

    실제 값을 반영하지는 않고(웹은 자격증명 없음), 그대로 복사해 쓰는 설정 텍스트를 만든다.
    """
    # 유효한 collector만 채택
    valid = [c for c in collectors if c in _COLLECTOR_FACTORIES]
    collectors_csv = ",".join(valid) if valid else "guardduty,securityhub"
    region = (region or "").strip()

    # 1) 환경변수(로컬 CLI / 컨테이너)
    env_lines = [
        f"AWS_REGION={region or 'ap-northeast-2'}",
        f"COLLECTORS={collectors_csv}",
        f"MIN_SEVERITY={min_severity}",
        f"LOOKBACK_MINUTES={lookback_minutes}",
    ]
    env_text = "\n".join(env_lines)

    # 2) CLI 실행 예시
    cli_ps = (f'$env:AWS_REGION="{region or "ap-northeast-2"}"; '
              f'$env:COLLECTORS="{collectors_csv}"; $env:MIN_SEVERITY="{min_severity}"; '
              f'$env:PYTHONPATH="src"; python -m agent.cli --compliance-report')
    cli_sh = (f'AWS_REGION={region or "ap-northeast-2"} COLLECTORS={collectors_csv} '
              f'MIN_SEVERITY={min_severity} PYTHONPATH=src python -m agent.cli --compliance-report')

    # 3) SAM 배포 파라미터
    sam_text = (
        "sam deploy --guided --parameter-overrides "
        f"MinSeverity={min_severity} Collectors={collectors_csv}"
        + (f"  # 리전은 --region {region}" if region else "")
    )

    # 4) Terraform 변수
    tf_lines = [
        f'region              = "{region or "ap-northeast-2"}"',
        f'collectors          = "{collectors_csv}"',
        f'min_severity        = "{min_severity}"',
        f'lookback_minutes    = "{lookback_minutes}"',
    ]
    tf_text = "\n".join(tf_lines)

    return {
        "region": region or "ap-northeast-2",
        "collectors": valid or ["guardduty", "securityhub"],
        "min_severity": min_severity,
        "lookback_minutes": lookback_minutes,
        "env": env_text,
        "cli_powershell": cli_ps,
        "cli_bash": cli_sh,
        "sam": sam_text,
        "terraform_tfvars": tf_text,
    }
