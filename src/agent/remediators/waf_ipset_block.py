"""악성/공격자 원격 IP를 WAFv2 IPSet에 추가해 앱 계층에서 차단.

대상: GuardDuty의 원격 IP를 포함하는 finding (brute force, malicious caller 등).
NACL 차단과의 차이:
  - NACL: 서브넷 네트워크 계층 차단(대상 EC2가 속한 서브넷).
  - WAF IPSet: CloudFront/ALB/API GW 앞단 앱 계층 차단(웹 노출 자원 보호).
  두 remediator를 함께 켜서 다층 방어할 수 있다.

전제: 차단용 IPSet이 미리 존재하고, 그 IPSet을 WebACL 규칙(Block)에 연결해 두어야 한다.
설정: WAF_IPSET_NAME, WAF_IPSET_ID, WAF_IPSET_SCOPE(REGIONAL|CLOUDFRONT).

안전:
  - dry-run 기본.
  - IPSet에 CIDR을 추가만 함(멱등). 이미 있으면 NO_ACTION.
  - LockToken으로 낙관적 동시성 보장(update_ip_set).
"""

from __future__ import annotations

from ..finding_utils import guardduty_remote_ip
from ..models import SecurityFinding
from .base import BaseRemediator, RemediationAction


class WafIpSetBlockRemediator(BaseRemediator):
    name = "waf_ipset_block"
    supported_types = (
        "UnauthorizedAccess:EC2/SSHBruteForce",
        "UnauthorizedAccess:EC2/RDPBruteForce",
        "UnauthorizedAccess:EC2/MaliciousIPCaller",
        "Recon:EC2/PortProbeUnprotectedPort",
    )

    def __init__(
        self,
        ipset_name: str = "",
        ipset_id: str = "",
        scope: str = "REGIONAL",
        dry_run: bool = True,
        allowed_types=None,
        region: str | None = None,
        session=None,
    ) -> None:
        super().__init__(dry_run=dry_run, allowed_types=allowed_types, region=region, session=session)
        self.ipset_name = ipset_name
        self.ipset_id = ipset_id
        self.scope = scope

    def _client(self):
        # CLOUDFRONT scope는 us-east-1에서만 동작
        region = "us-east-1" if self.scope == "CLOUDFRONT" else self.region
        return self._make_client("wafv2", region=region)

    def can_handle(self, finding: SecurityFinding) -> bool:
        if not super().can_handle(finding):
            return False
        # 대상 IPSet이 설정돼 있고 IP를 뽑을 수 있어야 함
        return bool(self.ipset_name and self.ipset_id) and self._extract_remote_ip(finding) is not None

    def _extract_remote_ip(self, finding: SecurityFinding) -> str | None:
        return guardduty_remote_ip(finding)

    def _plan(self, finding: SecurityFinding) -> list[RemediationAction]:
        ip = self._extract_remote_ip(finding)
        if not ip:
            return []
        cidr = f"{ip}/32"
        return [
            RemediationAction(
                description=f"원격 IP {cidr}를 WAF IPSet '{self.ipset_name}'({self.scope})에 추가",
                api="wafv2:UpdateIPSet",
                params={
                    "Name": self.ipset_name,
                    "Id": self.ipset_id,
                    "Scope": self.scope,
                    "AddAddress": cidr,
                },
            )
        ]

    def _apply(self, finding: SecurityFinding, actions: list[RemediationAction]) -> None:
        client = self._client()
        current = client.get_ip_set(Name=self.ipset_name, Id=self.ipset_id, Scope=self.scope)
        lock_token = current["LockToken"]
        addresses = list(current["IPSet"].get("Addresses", []))

        changed = False
        for action in actions:
            cidr = action.params["AddAddress"]
            if cidr not in addresses:
                addresses.append(cidr)
                changed = True
            action.params["AlreadyPresent"] = not changed

        if not changed:
            # 이미 모두 존재 -> 실제 호출 생략(멱등). NO_ACTION은 _plan에서만 나오므로
            # 여기서는 예외 대신 조용히 반환(감사 로그에 APPLIED로 남되 변경 0).
            return

        client.update_ip_set(
            Name=self.ipset_name,
            Id=self.ipset_id,
            Scope=self.scope,
            Addresses=addresses,
            LockToken=lock_token,
        )
