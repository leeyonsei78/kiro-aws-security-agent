"""SecurityGroupCollector가 낸 '인터넷 개방' finding의 위험 인바운드 규칙을 회수.

대상 finding_type: NetworkExposure:SecurityGroup/OpenIngress:*
액션: 문제된 IpPermission을 RevokeSecurityGroupIngress로 제거.

안전:
  - dry-run 기본.
  - 회수하는 정확한 permission을 params에 남겨 롤백(재-authorize) 가능.
"""

from __future__ import annotations

from typing import Any

from ..models import SecurityFinding
from .base import BaseRemediator, RemediationAction


class SgRevokeIngressRemediator(BaseRemediator):
    name = "sg_revoke_ingress"
    supported_types = ("NetworkExposure:SecurityGroup/OpenIngress",)

    def _client(self):
        return self._make_client("ec2")

    def _sg_id(self, finding: SecurityFinding) -> str | None:
        if finding.resources and finding.resources[0].id:
            return finding.resources[0].id
        return None

    def _permission(self, finding: SecurityFinding) -> dict[str, Any] | None:
        """회수할 IpPermission을, 문제된 open CIDR만 포함하도록 재구성."""
        raw = finding.raw or {}
        perm = raw.get("Permission")
        open_cidrs = set(raw.get("OpenCidrs", []) or [])
        if not perm or not open_cidrs:
            return None

        revoke: dict[str, Any] = {"IpProtocol": perm.get("IpProtocol", "-1")}
        if perm.get("FromPort") is not None:
            revoke["FromPort"] = perm["FromPort"]
        if perm.get("ToPort") is not None:
            revoke["ToPort"] = perm["ToPort"]

        ipv4 = [r for r in (perm.get("IpRanges") or []) if r.get("CidrIp") in open_cidrs]
        ipv6 = [r for r in (perm.get("Ipv6Ranges") or []) if r.get("CidrIpv6") in open_cidrs]
        if ipv4:
            revoke["IpRanges"] = ipv4
        if ipv6:
            revoke["Ipv6Ranges"] = ipv6
        if not ipv4 and not ipv6:
            return None
        return revoke

    def _plan(self, finding: SecurityFinding) -> list[RemediationAction]:
        sg_id = self._sg_id(finding)
        perm = self._permission(finding)
        if not sg_id or not perm:
            return []
        return [
            RemediationAction(
                description=f"Security Group {sg_id}의 인터넷 개방 인바운드 규칙 회수",
                api="ec2:RevokeSecurityGroupIngress",
                params={"GroupId": sg_id, "IpPermissions": [perm]},
            )
        ]

    def _apply(self, finding: SecurityFinding, actions: list[RemediationAction]) -> None:
        client = self._client()
        for action in actions:
            client.revoke_security_group_ingress(
                GroupId=action.params["GroupId"],
                IpPermissions=action.params["IpPermissions"],
            )
