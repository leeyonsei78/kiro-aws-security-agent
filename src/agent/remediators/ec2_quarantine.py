"""침해 의심 EC2 인스턴스를 격리 SG로 교체해 네트워크 격리.

대상: GuardDuty의 EC2 침해 계열 finding.
  - Backdoor:EC2/*  (C2 통신, DenialOfService 등)
  - Trojan:EC2/*
  - CryptoCurrency:EC2/*
  - UnauthorizedAccess:EC2/* 중 인스턴스 대상

액션: ec2:ModifyInstanceAttribute 로 인스턴스의 SG를 '격리 SG' 하나로 교체.
  - 격리 SG는 아웃바운드/인바운드를 최소화(예: 포렌식 접근만 허용)하도록 사전 구성 전제.

안전:
  - dry-run 기본.
  - 원래 SG 목록을 감사 로그(params.OriginalGroups)에 남겨 롤백 가능.
  - 인스턴스를 종료/중지하지 않음(포렌식 보존).
  - 격리 SG(QUARANTINE_SG_ID) 미설정 시 can_handle=False로 안전 스킵.
"""

from __future__ import annotations

from ..models import SecurityFinding
from .base import BaseRemediator, RemediationAction


class Ec2QuarantineRemediator(BaseRemediator):
    name = "ec2_quarantine"
    supported_types = (
        "Backdoor:EC2",
        "Trojan:EC2",
        "CryptoCurrency:EC2",
        "UnauthorizedAccess:EC2",
    )

    def __init__(
        self,
        quarantine_sg_id: str = "",
        dry_run: bool = True,
        allowed_types=None,
        region: str | None = None,
        session=None,
    ) -> None:
        super().__init__(dry_run=dry_run, allowed_types=allowed_types, region=region, session=session)
        self.quarantine_sg_id = quarantine_sg_id

    def _client(self):
        return self._make_client("ec2")

    def _instance_id(self, finding: SecurityFinding) -> str | None:
        res = (finding.raw or {}).get("Resource", {}) or {}
        instance = res.get("InstanceDetails", {}) or {}
        iid = instance.get("InstanceId")
        if iid:
            return iid
        # fallback: 정규화된 리소스에서 EC2 인스턴스 id
        for r in finding.resources:
            if r.type in ("Instance", "AwsEc2Instance") and r.id.startswith("i-"):
                return r.id
        return None

    def can_handle(self, finding: SecurityFinding) -> bool:
        if not super().can_handle(finding):
            return False
        if not self.quarantine_sg_id:
            return False
        return self._instance_id(finding) is not None

    def _original_groups(self, finding: SecurityFinding) -> list[str]:
        res = (finding.raw or {}).get("Resource", {}) or {}
        instance = res.get("InstanceDetails", {}) or {}
        groups: list[str] = []
        for ni in instance.get("NetworkInterfaces", []) or []:
            for g in ni.get("SecurityGroups", []) or []:
                gid = g.get("GroupId")
                if gid:
                    groups.append(gid)
        # 중복 제거(순서 보존)
        seen = set()
        uniq = []
        for g in groups:
            if g not in seen:
                seen.add(g)
                uniq.append(g)
        return uniq

    def _plan(self, finding: SecurityFinding) -> list[RemediationAction]:
        instance_id = self._instance_id(finding)
        if not instance_id:
            return []
        original = self._original_groups(finding)
        return [
            RemediationAction(
                description=f"인스턴스 {instance_id}를 격리 SG {self.quarantine_sg_id}로 교체(네트워크 격리)",
                api="ec2:ModifyInstanceAttribute",
                params={
                    "InstanceId": instance_id,
                    "Groups": [self.quarantine_sg_id],
                    "OriginalGroups": original,  # 롤백용
                },
            )
        ]

    def _apply(self, finding: SecurityFinding, actions: list[RemediationAction]) -> None:
        client = self._client()
        for action in actions:
            client.modify_instance_attribute(
                InstanceId=action.params["InstanceId"],
                Groups=action.params["Groups"],
            )
