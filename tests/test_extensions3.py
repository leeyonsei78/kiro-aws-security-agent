"""추가 확장 2종 검증: VPC Flow Logs collector, EC2 격리 remediator.

boto3 실제 호출은 network 제한으로 미실행. 임계값 평가/정규화/_plan/화이트리스트/
설정 미비 시 안전 스킵을 검증한다.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent.config import Config
from agent.core import _remediate
from agent.models import SecurityFinding, Severity, Resource
from agent.remediators.base import RemediationStatus
from agent.remediators.ec2_quarantine import Ec2QuarantineRemediator
from agent.collectors.vpc_flow_logs import VpcFlowLogsCollector


# --- VPC Flow Logs collector ------------------------------------------------
def _row(src, rejects, ports):
    return {"srcAddr": src, "rejectCount": str(rejects), "distinctPorts": str(ports)}


def test_flowlogs_port_scan_high():
    c = VpcFlowLogsCollector(region="ap-northeast-2", reject_threshold=100, distinct_ports_threshold=20)
    f = c._evaluate_row(_row("203.0.113.9", 500, 40))
    assert f is not None
    assert f.severity == Severity.HIGH
    assert f.finding_type.endswith("/PortScan")
    assert f.resources[0].id == "203.0.113.9"
    print("OK flowlogs port scan -> HIGH")


def test_flowlogs_reject_flood_medium():
    c = VpcFlowLogsCollector(region="ap-northeast-2", reject_threshold=100, distinct_ports_threshold=20)
    f = c._evaluate_row(_row("198.51.100.3", 300, 2))  # 포트는 적지만 reject 많음
    assert f is not None
    assert f.severity == Severity.MEDIUM
    assert f.finding_type.endswith("/RejectFlood")
    print("OK flowlogs reject flood -> MEDIUM")


def test_flowlogs_below_threshold_ignored():
    c = VpcFlowLogsCollector(region="ap-northeast-2", reject_threshold=100, distinct_ports_threshold=20)
    assert c._evaluate_row(_row("10.0.0.5", 3, 1)) is None
    print("OK flowlogs below threshold ignored")


def test_flowlogs_row_parsing():
    c = VpcFlowLogsCollector(region="ap-northeast-2")
    row = [{"field": "srcAddr", "value": "1.2.3.4"}, {"field": "rejectCount", "value": "150"}]
    d = c._row_to_dict(row)
    assert d["srcAddr"] == "1.2.3.4"
    assert d["rejectCount"] == "150"
    print("OK flowlogs insights row parsing")


def test_flowlogs_no_log_group_no_collect():
    # log_group 미설정이면 collect가 아무것도 내지 않음(안전)
    c = VpcFlowLogsCollector(region="ap-northeast-2", log_group="")
    from datetime import datetime, timezone
    assert list(c.collect(datetime.now(timezone.utc))) == []
    print("OK flowlogs no log group -> empty")


# --- EC2 격리 remediator ----------------------------------------------------
def _gd_ec2_finding(instance_id="i-0abc123", groups=("sg-web", "sg-ssh")):
    return SecurityFinding(
        id="gd-ec2-1", source="guardduty", title="C2 backdoor",
        severity=Severity.HIGH,
        finding_type="Backdoor:EC2/C&CActivity.B",
        raw={"Resource": {"InstanceDetails": {
            "InstanceId": instance_id,
            "NetworkInterfaces": [{"SecurityGroups": [{"GroupId": g} for g in groups]}],
        }}},
    )


def test_ec2_quarantine_plan():
    r = Ec2QuarantineRemediator(quarantine_sg_id="sg-quarantine", dry_run=True)
    f = _gd_ec2_finding()
    assert r.can_handle(f)
    result = r.remediate(f)
    assert result.status == RemediationStatus.DRY_RUN
    a = result.actions[0]
    assert a.api == "ec2:ModifyInstanceAttribute"
    assert a.params["InstanceId"] == "i-0abc123"
    assert a.params["Groups"] == ["sg-quarantine"]
    # 롤백용 원본 SG 보존
    assert a.params["OriginalGroups"] == ["sg-web", "sg-ssh"]
    print("OK ec2 quarantine plan (rollback groups preserved):", a.params["OriginalGroups"])


def test_ec2_quarantine_no_sg_configured():
    # 격리 SG 미설정이면 can_handle=False (안전)
    r = Ec2QuarantineRemediator(quarantine_sg_id="", dry_run=True)
    assert r.can_handle(_gd_ec2_finding()) is False
    print("OK ec2 quarantine skips when SG not configured")


def test_ec2_quarantine_wrong_type_skipped():
    r = Ec2QuarantineRemediator(quarantine_sg_id="sg-quarantine", dry_run=True)
    f = _gd_ec2_finding()
    f.finding_type = "Recon:EC2/PortProbeUnprotectedPort"  # 지원 목록 밖
    assert r.can_handle(f) is False
    print("OK ec2 quarantine ignores unsupported type")


# --- core 통합 --------------------------------------------------------------
def test_core_ec2_quarantine_dry_run():
    cfg = Config(
        collectors=[], notifiers=["stdout"],
        remediation_enabled=True, remediation_dry_run=True,
        remediators=["ec2_quarantine"], quarantine_sg_id="sg-quarantine",
    )
    results = _remediate([_gd_ec2_finding()], cfg)
    assert len(results) == 1
    assert results[0]["status"] == "DRY_RUN"
    assert results[0]["remediator"] == "ec2_quarantine"
    print("OK core ec2_quarantine dry-run")


if __name__ == "__main__":
    test_flowlogs_port_scan_high()
    test_flowlogs_reject_flood_medium()
    test_flowlogs_below_threshold_ignored()
    test_flowlogs_row_parsing()
    test_flowlogs_no_log_group_no_collect()
    test_ec2_quarantine_plan()
    test_ec2_quarantine_no_sg_configured()
    test_ec2_quarantine_wrong_type_skipped()
    test_core_ec2_quarantine_dry_run()
    print("\nALL EXTENSION3 TESTS PASSED")
