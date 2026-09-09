"""침해 의심 IAM 액세스 키를 비활성화(Inactive).

대상: GuardDuty의 자격증명 오남용 계열 finding.
  - UnauthorizedAccess:IAMUser/*  (예: InstanceCredentialExfiltration, MaliciousIPCaller)
  - CredentialAccess:IAMUser/*
  - Persistence:IAMUser/*, PrivilegeEscalation:IAMUser/* 등

액션: iam:UpdateAccessKey (Status=Inactive)  — 삭제가 아니라 비활성화라 롤백 가능.

안전:
  - dry-run 기본.
  - 삭제(DeleteAccessKey)가 아니라 Inactive라 되돌릴 수 있음(활성화 재설정 가능).
  - 루트 계정 키/역할 세션에는 적용하지 않음(사용자 키만 대상).
"""

from __future__ import annotations

from ..models import SecurityFinding
from .base import BaseRemediator, RemediationAction


class IamDisableKeyRemediator(BaseRemediator):
    name = "iam_disable_key"
    supported_types = (
        "UnauthorizedAccess:IAMUser",
        "CredentialAccess:IAMUser",
        "Persistence:IAMUser",
        "PrivilegeEscalation:IAMUser",
        "Discovery:IAMUser",
    )

    def _client(self):
        return self._make_client("iam")

    def _access_key_details(self, finding: SecurityFinding) -> dict:
        res = (finding.raw or {}).get("Resource", {}) or {}
        return res.get("AccessKeyDetails", {}) or {}

    def can_handle(self, finding: SecurityFinding) -> bool:
        if not super().can_handle(finding):
            return False
        details = self._access_key_details(finding)
        access_key_id = details.get("AccessKeyId")
        user_name = details.get("UserName")
        user_type = details.get("UserType", "")
        # IAM 사용자 키만 대상. 역할/루트/서비스 등은 제외(오작동 방지).
        if not access_key_id or not user_name:
            return False
        if user_type and user_type != "IAMUser":
            return False
        if user_name in ("root", "Root"):
            return False
        return True

    def _plan(self, finding: SecurityFinding) -> list[RemediationAction]:
        details = self._access_key_details(finding)
        access_key_id = details.get("AccessKeyId")
        user_name = details.get("UserName")
        if not access_key_id or not user_name:
            return []
        return [
            RemediationAction(
                description=f"IAM 사용자 '{user_name}'의 액세스 키 {_mask(access_key_id)} 비활성화",
                api="iam:UpdateAccessKey",
                params={
                    "UserName": user_name,
                    "AccessKeyId": access_key_id,
                    "Status": "Inactive",
                },
            )
        ]

    def _apply(self, finding: SecurityFinding, actions: list[RemediationAction]) -> None:
        client = self._client()
        for action in actions:
            client.update_access_key(
                UserName=action.params["UserName"],
                AccessKeyId=action.params["AccessKeyId"],
                Status="Inactive",
            )


def _mask(key_id: str) -> str:
    # 감사 로그에 전체 키 ID 노출 최소화 (앞4/뒤4만)
    if len(key_id) <= 8:
        return key_id
    return f"{key_id[:4]}...{key_id[-4:]}"
