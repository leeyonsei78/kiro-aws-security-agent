"""SW 공급망 보안(supply chain) 관련 컴플라이언스 체크.

컨테이너 이미지(ECR)와 서버리스 런타임(Lambda)의 공급망 위생을 점검한다.
점검 항목 코드 체계(SC-nn)와 공급망 보안 관점은 KISA 기반
KESE-KIT(https://github.com/cdppcorp/KESE-KIT, MIT)의 SW 공급망 가이드 접근을 참고했으며,
점검 로직은 boto3로 새로 구현했다.
"""

from __future__ import annotations

from typing import Any

from ..models import Severity
from .base import BaseComplianceCheck, CheckViolation

# 2026년 기준 이미 지원 종료(deprecated)된 Lambda 런타임 접두/식별자.
# 새 런타임이 EOL 되면 이 목록에 추가하면 된다.
DEPRECATED_LAMBDA_RUNTIMES = {
    "python2.7", "python3.6", "python3.7", "python3.8",
    "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x",
    "nodejs12.x", "nodejs14.x", "nodejs16.x", "nodejs18.x",
    "ruby2.5", "ruby2.7", "ruby3.2",
    "java8", "java8.al2",
    "go1.x",
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1",
    "dotnet5.0", "dotnet6", "dotnet7",
}


class EcrScanOnPushCheck(BaseComplianceCheck):
    code = "SC-01"
    title = "ECR 리포지토리 푸시 시 이미지 스캔 미설정"
    severity = Severity.MEDIUM
    service = "ecr"
    category = "공급망 보안"
    remediation = "PutImageScanningConfiguration으로 scanOnPush=true를 설정하거나, ECR 향상된 스캔(Inspector)을 활성화하세요."
    standards = ("KISA SW공급망", "NIST SP 800-218 SSDF")

    def run(self, client: Any) -> list[CheckViolation]:
        violations: list[CheckViolation] = []
        paginator = client.get_paginator("describe_repositories")
        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                name = repo.get("repositoryName", "")
                cfg = repo.get("imageScanningConfiguration", {}) or {}
                if not cfg.get("scanOnPush"):
                    violations.append(CheckViolation(
                        resource_id=name, resource_type="AwsEcrRepository",
                        detail=f"ECR 리포지토리 '{name}'에 푸시 시 스캔(scanOnPush)이 비활성",
                        evidence={"imageScanningConfiguration": cfg},
                    ))
        return violations


class EcrTagImmutabilityCheck(BaseComplianceCheck):
    code = "SC-02"
    title = "ECR 이미지 태그 불변성 미설정"
    severity = Severity.LOW
    service = "ecr"
    category = "공급망 보안"
    remediation = "imageTagMutability=IMMUTABLE로 설정해 동일 태그의 이미지가 교체(공급망 변조)되지 않도록 하세요."
    standards = ("KISA SW공급망", "NTIA SBOM")

    def run(self, client: Any) -> list[CheckViolation]:
        violations: list[CheckViolation] = []
        paginator = client.get_paginator("describe_repositories")
        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                name = repo.get("repositoryName", "")
                if repo.get("imageTagMutability") != "IMMUTABLE":
                    violations.append(CheckViolation(
                        resource_id=name, resource_type="AwsEcrRepository",
                        detail=f"ECR 리포지토리 '{name}'의 태그가 변경 가능(MUTABLE) 상태",
                        evidence={"imageTagMutability": repo.get("imageTagMutability")},
                    ))
        return violations


class LambdaDeprecatedRuntimeCheck(BaseComplianceCheck):
    code = "SC-10"
    title = "Lambda 함수 지원 종료(EOL) 런타임 사용"
    severity = Severity.HIGH
    service = "lambda"
    category = "공급망 보안"
    remediation = "지원 종료된 런타임은 보안 패치를 받지 못합니다. 최신 런타임으로 업그레이드하세요."
    standards = ("KISA SW공급망", "NIST SP 800-218 SSDF")

    def run(self, client: Any) -> list[CheckViolation]:
        violations: list[CheckViolation] = []
        paginator = client.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                runtime = fn.get("Runtime")
                if runtime and runtime in DEPRECATED_LAMBDA_RUNTIMES:
                    name = fn.get("FunctionName", "")
                    violations.append(CheckViolation(
                        resource_id=name, resource_type="AwsLambdaFunction",
                        detail=f"Lambda 함수 '{name}'가 지원 종료 런타임 '{runtime}' 사용 중",
                        evidence={"runtime": runtime},
                    ))
        return violations
