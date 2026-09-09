# 확장 가이드

이 에이전트는 3개의 확장 포인트를 중심으로 설계됐다: **Collector**, **Notifier**, 그리고 향후 **Remediator**.
코어(`core.py`)는 개별 구현을 모르며, `registry.py`의 팩토리 등록만으로 기능이 붙는다.

## 1. 새 보안 소스 추가 (Collector)

로드맵: WAF, Shield, Inspector, Config, CloudTrail, IAM Access Analyzer,
Security Group/NACL, VPC Flow Logs, 써드파티(Palo Alto / Fortinet / Check Point).

### 단계

1. `src/agent/collectors/<name>.py` 생성, `BaseCollector` 상속

```python
from datetime import datetime
from typing import Iterable
from ..models import SecurityFinding, Severity, Resource
from .base import BaseCollector

class WafCollector(BaseCollector):
    name = "waf"

    def collect(self, since: datetime) -> Iterable[SecurityFinding]:
        # boto3로 wafv2 로그/샘플 요청 조회 후 SecurityFinding으로 정규화
        ...

    def parse_event(self, event) -> Iterable[SecurityFinding]:
        # (선택) 실시간 이벤트 지원 시 구현
        ...
```

2. `registry.py`에 등록

```python
from .collectors.waf import WafCollector

_COLLECTOR_FACTORIES["waf"] = lambda cfg: WafCollector(region=cfg.region)
# 실시간 지원 시:
EVENT_TYPE_TO_COLLECTOR["WAF ..."] = "waf"
```

3. `COLLECTORS=guardduty,securityhub,waf` 로 활성화. IAM 정책에 읽기 권한 추가.

### 소스별 참고

- **Security Hub는 이미 다수 소스를 집계**한다(GuardDuty, Inspector, Macie, Config 등을 ASFF로 통합). 많은 경우 Security Hub collector 하나로 커버되므로, 개별 collector는 "Security Hub에 안 올라오는" 신호(예: VPC Flow Logs 원본, 써드파티 어플라이언스 syslog)에 우선 투자하는 것이 효율적이다.
- **네트워크(SG/NACL/Flow Logs)**: Flow Logs는 CloudWatch Logs/S3에 적재되므로, 로그 쿼리(예: Logs Insights) 결과를 finding으로 정규화하는 collector로 붙인다.
- **써드파티 어플라이언스**: 대개 syslog/webhook로 이벤트를 낸다. 수신용 엔드포인트(예: API Gateway → Lambda)를 두고, 그 payload를 `parse_event`로 정규화하는 collector를 만든다.

## 2. 새 알림 채널 추가 (Notifier)

1. `src/agent/notifiers/<name>.py`에 `BaseNotifier` 상속 구현 (`notify(findings)` 작성).
   포맷 헬퍼 `summarize()`, `format_line()` 재사용 가능.
2. `registry.py`의 `_build_notifier`에 분기 추가.
3. `NOTIFIERS`로 활성화.

## 3. 자동 대응 (Remediator) — 구현됨

`core._dispatch`는 알림 이후 `_remediate` 단계를 실행한다. remediator는
`BaseRemediator`(`src/agent/remediators/base.py`)를 상속하며, 공통 흐름
(화이트리스트 검사 → dry-run 분기 → 감사 로깅)은 베이스가 처리한다.

### 현재 제공

| remediator | 대상 finding_type | 액션 |
|------------|-------------------|------|
| `nacl_block_ip` | `UnauthorizedAccess:EC2/SSHBruteForce` 등 | 원격 IP를 NACL deny 규칙으로 차단 |
| `sg_revoke_ingress` | `NetworkExposure:SecurityGroup/OpenIngress` | 인터넷 개방 인바운드 규칙 회수 |
| `s3_public_block` | `Effects/Data Exposure` 등 (S3 버킷 리소스) | 버킷에 Public Access Block 전체 적용 |
| `waf_ipset_block` | `UnauthorizedAccess:EC2/*`, `Recon:EC2/*` | 원격 IP를 WAFv2 IPSet에 추가(앱 계층 차단, IPSet 사전 구성 필요) |
| `iam_disable_key` | `UnauthorizedAccess:IAMUser/*`, `CredentialAccess:IAMUser/*` 등 | 침해 의심 IAM 액세스 키를 Inactive로 비활성화(삭제 아님, 롤백 가능) |
| `ec2_quarantine` | `Backdoor:EC2/*`, `Trojan:EC2/*`, `CryptoCurrency:EC2/*` 등 | 인스턴스를 격리 SG로 교체(종료/중지 없이 네트워크 격리, 원본 SG 롤백 보존) |

### 새 remediator 추가

1. `src/agent/remediators/<name>.py`에 `BaseRemediator` 상속:

```python
class MyRemediator(BaseRemediator):
    name = "my_remediator"
    supported_types = ("SomeFinding:Type/Prefix",)  # startswith 매칭

    def _plan(self, finding) -> list[RemediationAction]:
        # 실제 호출 없이 '무엇을 할지' 산출 (dry-run/실제 공통)
        ...

    def _apply(self, finding, actions) -> None:
        # 실행 모드에서만 호출: AWS API 실제 수행
        ...
```

2. `registry.py`의 `_REMEDIATOR_CLASSES`에 등록.
3. `REMEDIATION_ENABLED=true`로 활성화. 쓰기 권한은 `iam/remediation-policy.json` 참고.

### 안전장치 (베이스에 내장)

1. **dry-run 기본**: `_plan`만 실행하고 `_apply`는 건너뜀. 실제 적용은 `REMEDIATION_DRY_RUN=false` 명시 필요.
2. **화이트리스트**: `REMEDIATION_ALLOWED_TYPES`로 대응 대상 finding_type을 좁힘.
3. **감사 로깅**: 모든 시도가 `RemediationResult`로 기록되고 `[REMEDIATION-AUDIT]` 로그 + 핸들러 반환값 `remediations`에 포함.
4. **롤백 지향**: 회수/차단 규칙의 정확한 파라미터를 결과에 남겨 되돌리기 가능.

향후 대응 아이디어: S3 public bucket → `PutPublicAccessBlock`, 유출 의심 IAM 키 → 키 비활성화, 악성 IP → WAF IPSet 추가.


## 4. 새 방화벽 벤더 파서 추가 (Firewall)

써드파티 방화벽 로그는 `firewall_syslog` collector가 수신하고, 벤더 파서가 정규화한다.
파서는 `src/agent/firewall/`에 위치하며 `BaseFirewallParser`를 상속한다.

### 단계

1. `src/agent/firewall/<vendor>.py`에 파서 구현:

```python
from ..models import Severity
from .base import BaseFirewallParser
from .util import parse_kv, strip_syslog_priority

class MyVendorParser(BaseFirewallParser):
    vendor = "myvendor"

    def matches(self, line: str) -> bool:
        # 이 벤더 로그인지 판별(자동 감지용). 특유 필드/시그니처로 판단.
        return "myvendor-signature" in line.lower()

    def parse(self, line: str):
        fields = parse_kv(strip_syslog_priority(line))
        if not fields:
            return None
        return self._finding(
            event_id=..., title=..., severity=Severity.HIGH,
            finding_type="Firewall:MyVendor/...",
            description=..., src_ip=fields.get("src", ""),
            action=fields.get("action", ""), raw_fields=fields,
        )
```

2. `src/agent/firewall/registry.py`의 `_PARSER_ORDER`에 등록.
   벤더 특화 파서는 앞쪽에, 범용(CEF 같은) 파서는 뒤에 둔다(자동 감지 우선순위).

3. 끝. `firewall_syslog` collector가 자동 감지(또는 `vendor` 지정)로 새 파서를 사용한다.

### 파싱 안전 수칙

- `parse_kv`는 `key="value with spaces"`의 따옴표 내부를 구분자로 취급하지 않아 **필드 인젝션에 안전**하다. 자체 파싱을 만들 때도 동일 원칙을 지킨다.
- 한 라인 파싱이 실패해도 collector가 예외를 격리하므로, 파서는 관심 없는 라인에 `None`을 반환하면 된다.
- 외부 입력이므로 신뢰하지 말 것: API Gateway 단에서 인증/IP 제한을 두는 것을 전제로 한다.
