"""IAM 관련 컴플라이언스 체크."""

from __future__ import annotations

from typing import Any

from ..models import Severity
from .base import BaseComplianceCheck, CheckViolation


class IamPasswordPolicyCheck(BaseComplianceCheck):
    code = "CA-10"
    title = "IAM 비밀번호 정책 미흡"
    severity = Severity.MEDIUM
    service = "iam"
    remediation = "UpdateAccountPasswordPolicy로 최소 길이(14+), 대소문자/숫자/기호, 재사용 제한을 설정하세요."
    standards = ("KISA CII(계정관리)", "CIS AWS 1.8")

    MIN_LENGTH = 14

    def run(self, client: Any) -> list[CheckViolation]:
        try:
            policy = client.get_account_password_policy().get("PasswordPolicy", {})
        except Exception:  # noqa: BLE001 - 정책 자체가 없으면 위반
            return [CheckViolation(
                resource_id="account", detail="계정 비밀번호 정책이 설정되지 않음")]

        weak: list[str] = []
        if policy.get("MinimumPasswordLength", 0) < self.MIN_LENGTH:
            weak.append(f"최소 길이 {policy.get('MinimumPasswordLength', 0)} < {self.MIN_LENGTH}")
        if not policy.get("RequireSymbols"):
            weak.append("기호 미요구")
        if not policy.get("RequireNumbers"):
            weak.append("숫자 미요구")
        if not policy.get("RequireUppercaseCharacters"):
            weak.append("대문자 미요구")
        if not policy.get("RequireLowercaseCharacters"):
            weak.append("소문자 미요구")
        if not weak:
            return []
        return [CheckViolation(
            resource_id="account",
            detail="비밀번호 정책 미흡: " + ", ".join(weak),
            evidence={"PasswordPolicy": policy},
        )]


class IamRootAccessKeyCheck(BaseComplianceCheck):
    code = "CA-11"
    title = "루트 계정 액세스 키 존재"
    severity = Severity.CRITICAL
    service = "iam"
    remediation = "루트 액세스 키를 즉시 삭제하고, 일상 작업은 최소권한 IAM 사용자/역할로 수행하세요."
    standards = ("KISA CII(계정관리)", "CIS AWS 1.4")

    def run(self, client: Any) -> list[CheckViolation]:
        # 계정 요약의 AccountAccessKeysPresent 지표 사용
        try:
            summary = client.get_account_summary().get("SummaryMap", {})
        except Exception:  # noqa: BLE001
            return []
        if summary.get("AccountAccessKeysPresent", 0):
            return [CheckViolation(
                resource_id="root",
                detail="루트 계정에 액세스 키가 존재함(즉시 제거 권장)",
                evidence={"AccountAccessKeysPresent": summary.get("AccountAccessKeysPresent")},
            )]
        return []


class IamUserMfaCheck(BaseComplianceCheck):
    code = "CA-12"
    title = "콘솔 로그인 가능 IAM 사용자 MFA 미설정"
    severity = Severity.HIGH
    service = "iam"
    remediation = "콘솔 접근 사용자에게 MFA를 강제하세요(EnableMFADevice + 정책으로 MFA 미사용 차단)."
    standards = ("KISA CII(계정관리)", "CIS AWS 1.10")

    def run(self, client: Any) -> list[CheckViolation]:
        violations: list[CheckViolation] = []
        paginator = client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                name = user.get("UserName", "")
                # 콘솔 로그인 프로파일이 있는 사용자만 MFA 필요
                if not self._has_login_profile(client, name):
                    continue
                mfa = client.list_mfa_devices(UserName=name).get("MFADevices", [])
                if not mfa:
                    violations.append(CheckViolation(
                        resource_id=name, resource_type="AwsIamUser",
                        detail=f"콘솔 사용자 '{name}'에 MFA가 설정되지 않음",
                    ))
        return violations

    def _has_login_profile(self, client: Any, user_name: str) -> bool:
        try:
            client.get_login_profile(UserName=user_name)
            return True
        except Exception:  # noqa: BLE001 - NoSuchEntity 등 → 콘솔 접근 없음
            return False
