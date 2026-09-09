"""moto 기반 EC2 통합 테스트.

실제 boto3 호출 경로를 moto 가상 AWS로 검증한다:
  - SecurityGroupCollector.collect (describe_security_groups)
  - SgRevokeIngressRemediator._apply (revoke_security_group_ingress)
  - NaclBlockIpRemediator._apply (describe/create_network_acl_entry)
  - Ec2QuarantineRemediator._apply (modify_instance_attribute)
"""

import boto3
from moto import mock_aws

from agent.collectors.security_group import SecurityGroupCollector
from agent.models import Severity
from agent.remediators.sg_revoke_ingress import SgRevokeIngressRemediator
from agent.remediators.nacl_block_ip import NaclBlockIpRemediator
from agent.remediators.ec2_quarantine import Ec2QuarantineRemediator

REGION = "us-east-1"


@mock_aws
def test_sg_collector_detects_open_ssh_real():
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )

    collector = SecurityGroupCollector(region=REGION)
    findings = [f for f in collector.collect(since=None) if f.resources and f.resources[0].id == sg]
    # 열린 22번 포트를 가진 SG에 대해 finding이 나와야 함
    assert any("OpenIngress" in f.finding_type for f in findings)
    f = next(f for f in findings if "OpenIngress" in f.finding_type)
    assert f.severity >= Severity.HIGH
    assert f.raw["OpenCidrs"] == ["0.0.0.0/0"]


@mock_aws
def test_sg_revoke_ingress_apply_real():
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="db", Description="db", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )

    # collector로 finding 생성 → remediator로 회수
    collector = SecurityGroupCollector(region=REGION)
    finding = next(f for f in collector.collect(since=None)
                   if f.resources and f.resources[0].id == sg)

    r = SgRevokeIngressRemediator(dry_run=False, region=REGION)
    assert r.can_handle(finding)
    result = r.remediate(finding)
    assert result.status.value == "APPLIED"

    # 실제로 규칙이 사라졌는지 확인
    desc = ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]
    open_rules = [p for p in desc["IpPermissions"]
                  if any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", []))]
    assert open_rules == []


@mock_aws
def test_ec2_quarantine_apply_real():
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    orig_sg = ec2.create_security_group(GroupName="orig", Description="o", VpcId=vpc)["GroupId"]
    quar_sg = ec2.create_security_group(GroupName="quarantine", Description="q", VpcId=vpc)["GroupId"]
    # 최신 amazon linux ami는 moto가 기본 제공하는 더미 ami 사용
    images = ec2.describe_images()["Images"]
    ami = images[0]["ImageId"] if images else "ami-12345678"
    inst = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SubnetId=subnet,
                             SecurityGroupIds=[orig_sg])["Instances"][0]["InstanceId"]

    # GuardDuty 형태의 finding 구성
    from agent.models import SecurityFinding
    finding = SecurityFinding(
        id="gd-ec2", source="guardduty", title="C2", severity=Severity.HIGH,
        finding_type="Backdoor:EC2/C&CActivity.B",
        raw={"Resource": {"InstanceDetails": {
            "InstanceId": inst,
            "NetworkInterfaces": [{"SecurityGroups": [{"GroupId": orig_sg}]}],
        }}},
    )

    r = Ec2QuarantineRemediator(quarantine_sg_id=quar_sg, dry_run=False, region=REGION)
    assert r.can_handle(finding)
    result = r.remediate(finding)
    assert result.status.value == "APPLIED"

    # 인스턴스의 SG가 격리 SG로 교체됐는지 확인
    desc = ec2.describe_instances(InstanceIds=[inst])
    sgs = [g["GroupId"] for g in desc["Reservations"][0]["Instances"][0]["SecurityGroups"]]
    assert quar_sg in sgs


@mock_aws
def test_nacl_block_ip_apply_real():
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]

    # 서브넷의 기본 NACL 확인
    acls = ec2.describe_network_acls(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet]}])["NetworkAcls"]
    assert acls, "서브넷에 연결된 NACL이 있어야 함"

    from agent.models import SecurityFinding
    finding = SecurityFinding(
        id="gd-ssh", source="guardduty", title="SSH brute", severity=Severity.HIGH,
        finding_type="UnauthorizedAccess:EC2/SSHBruteForce",
        raw={
            "Service": {"Action": {"NetworkConnectionAction": {
                "RemoteIpDetails": {"IpAddressV4": "203.0.113.66"}}}},
            "Resource": {"InstanceDetails": {"NetworkInterfaces": [{"SubnetId": subnet}]}},
        },
    )

    r = NaclBlockIpRemediator(dry_run=False, region=REGION)
    assert r.can_handle(finding)
    result = r.remediate(finding)
    assert result.status.value == "APPLIED"

    # deny 규칙이 추가됐는지 확인
    nacl_id = acls[0]["NetworkAclId"]
    entries = ec2.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]["Entries"]
    deny_ingress = [e for e in entries
                    if not e.get("Egress", True) and e.get("RuleAction") == "deny"
                    and e.get("CidrBlock") == "203.0.113.66/32"]
    assert deny_ingress, "203.0.113.66/32 에 대한 deny 인바운드 규칙이 있어야 함"
