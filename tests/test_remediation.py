"""Remediator 프레임워크 + SG collector 검증 (boto3 미사용 경로).

- dry-run 계획 산출, 화이트리스트, 감사 결과 상태
- SG collector의 위험 규칙 정규화
- core 통합: remediation_enabled 동작
실제 AWS 변경(_apply)은 network 제한으로 호출하지 않는다.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent.config import Config
from agent.core import _remediate
from agent.models import SecurityFinding, Severity, Resource
from agent.remediators.base import RemediationStatus
from agent.remediators.nacl_block_ip import NaclBlockIpRemediator
from agent.remediators.sg_revoke_ingress import SgRevokeIngressRemediator
from agent.collectors.security_group import SecurityGroupCollector


def _guardduty_bruteforce_finding() -> SecurityFinding:
    raw = {
        "Service": {
            "Action": {
                "NetworkConnectionAction": {
                    "RemoteIpDetails": {"IpAddressV4": "203.0.113.10"}
                }
            }
        },
        "Resource": {
            "InstanceDetails": {
                "NetworkInterfaces": [{"SubnetId": "subnet-0abc"}]
            }
        },
    }
    return SecurityFinding(
        id="gd-1", source="guardduty", title="SSH brute force",
        severity=Severity.HIGH,
        finding_type="UnauthorizedAccess:EC2/SSHBruteForce",
        raw=raw,
    )


def test_nacl_plan_dry_run():
    r = NaclBlockIpRemediator(dry_run=True)
    f = _guardduty_bruteforce_finding()
    assert r.can_handle(f)
    result = r.remediate(f)
    assert result.status == RemediationStatus.DRY_RUN
    assert result.actions[0].api == "ec2:CreateNetworkAclEntry"
    assert result.actions[0].params["CidrBlock"] == "203.0.113.10/32"
    print("OK nacl dry-run:", result.to_dict()["actions"][0]["params"]["CidrBlock"])


def test_nacl_whitelist_skip():
    # 허용 type을 다른 것으로 좁히면 스킵되어야 함
    r = NaclBlockIpRemediator(dry_run=True, allowed_types=["Recon:EC2/PortProbe"])
    f = _guardduty_bruteforce_finding()
    result = r.remediate(f)
    assert result.status == RemediationStatus.SKIPPED
    print("OK nacl whitelist skip")


def test_nacl_no_ip_no_action():
    r = NaclBlockIpRemediator(dry_run=True)
    f = _guardduty_bruteforce_finding()
    f.raw = {"Service": {"Action": {}}, "Resource": {}}
    result = r.remediate(f)
    assert result.status == RemediationStatus.NO_ACTION
    print("OK nacl no-action when no IP")


# --- SG collector -----------------------------------------------------------
def _sg_page(sg_id, perms):
    return {"SecurityGroups": [{
        "GroupId": sg_id, "GroupName": "web", "OwnerId": "111122223333",
        "VpcId": "vpc-1", "IpPermissions": perms,
    }]}


def test_sg_collector_detects_open_ssh():
    c = SecurityGroupCollector(region="ap-northeast-2")
    perms = [{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }]
    sg = _sg_page("sg-1", perms)["SecurityGroups"][0]
    findings = list(c._evaluate_sg(sg))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert "OpenIngress" in f.finding_type
    assert f.raw["OpenCidrs"] == ["0.0.0.0/0"]
    print("OK sg detect open ssh:", f.title)


def test_sg_collector_all_traffic_critical():
    c = SecurityGroupCollector(region="ap-northeast-2")
    perms = [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    sg = _sg_page("sg-2", perms)["SecurityGroups"][0]
    findings = list(c._evaluate_sg(sg))
    assert findings[0].severity == Severity.CRITICAL
    print("OK sg all-traffic critical")


def test_sg_collector_ignores_restricted():
    c = SecurityGroupCollector(region="ap-northeast-2")
    perms = [{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],  # 내부 대역
    }]
    sg = _sg_page("sg-3", perms)["SecurityGroups"][0]
    assert list(c._evaluate_sg(sg)) == []
    print("OK sg ignores restricted cidr")


def test_sg_revoke_plan():
    c = SecurityGroupCollector(region="ap-northeast-2")
    perms = [{
        "IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }]
    sg = _sg_page("sg-4", perms)["SecurityGroups"][0]
    finding = list(c._evaluate_sg(sg))[0]

    r = SgRevokeIngressRemediator(dry_run=True)
    assert r.can_handle(finding)
    result = r.remediate(finding)
    assert result.status == RemediationStatus.DRY_RUN
    params = result.actions[0].params
    assert params["GroupId"] == "sg-4"
    assert params["IpPermissions"][0]["FromPort"] == 3389
    assert params["IpPermissions"][0]["IpRanges"] == [{"CidrIp": "0.0.0.0/0"}]
    print("OK sg revoke plan:", params["GroupId"])


# --- core 통합 --------------------------------------------------------------
def test_core_remediation_disabled_by_default():
    cfg = Config(collectors=[], notifiers=["stdout"])  # remediation_enabled 기본 False
    results = _remediate([_guardduty_bruteforce_finding()], cfg)
    assert results == []
    print("OK core remediation disabled by default")


def test_core_remediation_enabled_dry_run():
    cfg = Config(
        collectors=[], notifiers=["stdout"],
        remediation_enabled=True, remediation_dry_run=True,
        remediators=["nacl_block_ip"],
    )
    results = _remediate([_guardduty_bruteforce_finding()], cfg)
    assert len(results) == 1
    assert results[0]["status"] == "DRY_RUN"
    assert results[0]["dry_run"] is True
    print("OK core remediation enabled (dry-run):", results[0]["status"])


if __name__ == "__main__":
    test_nacl_plan_dry_run()
    test_nacl_whitelist_skip()
    test_nacl_no_ip_no_action()
    test_sg_collector_detects_open_ssh()
    test_sg_collector_all_traffic_critical()
    test_sg_collector_ignores_restricted()
    test_sg_revoke_plan()
    test_core_remediation_disabled_by_default()
    test_core_remediation_enabled_dry_run()
    print("\nALL REMEDIATION TESTS PASSED")
