"""Brute-force 등에서 탐지된 원격 IP를 NACL deny 규칙으로 차단.

대상: GuardDuty의 UnauthorizedAccess:EC2/SSHBruteForce, RDPBruteForce 등.
NACL을 택한 이유: SG는 allow-only라 "차단"에 부적합하고, NACL은 명시적 deny가 가능.

안전:
  - dry-run 기본. 실제 적용 시 deny 규칙을 낮은(우선순위 높은) 룰 번호로 추가.
  - 롤백 지향: 특정 룰 번호 대역(기본 1~ )을 태깅해 회수 가능하도록 params에 명시.
"""

from __future__ import annotations

from ..finding_utils import guardduty_remote_ip
from ..models import SecurityFinding
from .base import BaseRemediator, RemediationAction


class NaclBlockIpRemediator(BaseRemediator):
    name = "nacl_block_ip"
    supported_types = (
        "UnauthorizedAccess:EC2/SSHBruteForce",
        "UnauthorizedAccess:EC2/RDPBruteForce",
        "UnauthorizedAccess:EC2/MaliciousIPCaller",
    )

    # deny 규칙을 넣을 룰 번호 시작값(낮을수록 먼저 평가)
    DENY_RULE_BASE = 1

    def _client(self):
        return self._make_client("ec2")

    def _extract_remote_ip(self, finding: SecurityFinding) -> str | None:
        return guardduty_remote_ip(finding)

    def _find_nacl_id(self, finding: SecurityFinding) -> str | None:
        """대상 인스턴스가 속한 서브넷의 NACL ID를 조회."""
        res = (finding.raw or {}).get("Resource", {}) or {}
        instance = res.get("InstanceDetails", {}) or {}
        subnet_id = None
        for ni in instance.get("NetworkInterfaces", []) or []:
            if ni.get("SubnetId"):
                subnet_id = ni["SubnetId"]
                break
        if not subnet_id:
            return None
        client = self._client()
        resp = client.describe_network_acls(
            Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
        )
        acls = resp.get("NetworkAcls", [])
        return acls[0]["NetworkAclId"] if acls else None

    def _plan(self, finding: SecurityFinding) -> list[RemediationAction]:
        ip = self._extract_remote_ip(finding)
        if not ip:
            return []
        cidr = f"{ip}/32"
        # nacl_id는 실행 시점에 조회하나, 계획 단계에서도 best-effort로 표시
        nacl_id = None
        try:
            nacl_id = self._find_nacl_id(finding)
        except Exception:  # noqa: BLE001 - dry-run 계획 단계에서 조회 실패는 무시
            nacl_id = None

        return [
            RemediationAction(
                description=f"원격 IP {cidr}를 NACL deny 규칙으로 인바운드 차단",
                api="ec2:CreateNetworkAclEntry",
                params={
                    "NetworkAclId": nacl_id or "<대상 서브넷 NACL 실행시 조회>",
                    "RuleNumber": self.DENY_RULE_BASE,
                    "Protocol": "-1",
                    "RuleAction": "deny",
                    "Egress": False,
                    "CidrBlock": cidr,
                },
            )
        ]

    def _apply(self, finding: SecurityFinding, actions: list[RemediationAction]) -> None:
        nacl_id = self._find_nacl_id(finding)
        if not nacl_id:
            raise RuntimeError("대상 서브넷의 NACL을 찾지 못함")
        client = self._client()
        rule_number = self._next_free_rule_number(client, nacl_id)
        for action in actions:
            cidr = action.params.get("CidrBlock")
            client.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=rule_number,
                Protocol="-1",
                RuleAction="deny",
                Egress=False,
                CidrBlock=cidr,
            )
            # 실제 사용한 값으로 감사 로그 보강
            action.params["NetworkAclId"] = nacl_id
            action.params["RuleNumber"] = rule_number
            rule_number += 1

    def _next_free_rule_number(self, client, nacl_id: str) -> int:
        resp = client.describe_network_acls(NetworkAclIds=[nacl_id])
        used = set()
        for acl in resp.get("NetworkAcls", []):
            for entry in acl.get("Entries", []):
                if not entry.get("Egress", False):
                    used.add(entry.get("RuleNumber"))
        num = self.DENY_RULE_BASE
        while num in used:
            num += 1
        return num
