# 설정 (환경변수)

모든 설정은 환경변수로 주입한다 (Lambda 환경변수 / 로컬 export 동일).

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `COLLECTORS` | `guardduty,securityhub` | 활성화할 수집기(쉼표구분) |
| `NOTIFIERS` | (자동) | 활성화할 알림채널. 미설정 시 자격정보가 채워진 채널 자동 활성, 그것도 없으면 `stdout` |
| `MIN_SEVERITY` | `MEDIUM` | 이 심각도 이상만 알림 (`INFORMATIONAL`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`) |
| `LOOKBACK_MINUTES` | `60` | 폴링 시 조회할 과거 시간 윈도우(분). 스케줄 주기와 맞추는 것을 권장 |
| `AWS_REGION` | (SDK 기본) | 대상 리전 |
| `SLACK_WEBHOOK_URL` | - | Slack Incoming Webhook URL |
| `SNS_TOPIC_ARN` | - | 이메일 알림용 SNS 토픽 ARN |
| `REMEDIATION_ENABLED` | `false` | 자동 대응 활성화 여부 |
| `REMEDIATION_DRY_RUN` | `true` | 계획만 산출(실제 변경 안 함). 실제 적용은 `false`로 명시 |
| `REMEDIATORS` | (전체) | 활성화할 remediator (쉼표구분) |
| `REMEDIATION_ALLOWED_TYPES` | (전체) | 대응 허용 finding_type 접두사 화이트리스트(쉼표구분) |
| `WAF_IPSET_NAME` | - | `waf_ipset_block` 대상 IPSet 이름 (사용 시 필수) |
| `WAF_IPSET_ID` | - | `waf_ipset_block` 대상 IPSet ID (사용 시 필수) |
| `WAF_IPSET_SCOPE` | `REGIONAL` | IPSet 스코프 (`REGIONAL` 또는 `CLOUDFRONT`) |
| `FLOWLOGS_LOG_GROUP` | - | `vpc_flow_logs` collector 대상 CloudWatch Logs 로그그룹(사용 시 필수) |
| `FLOWLOGS_REJECT_THRESHOLD` | `100` | 소스 IP당 REJECT 횟수 임계값(초과 시 finding) |
| `FLOWLOGS_DISTINCT_PORTS_THRESHOLD` | `20` | 소스 IP당 고유 대상 포트 수 임계값(포트 스캔 판단) |
| `QUARANTINE_SG_ID` | - | `ec2_quarantine` remediator가 교체할 격리 SG ID(사용 시 필수) |
| `FIREWALL_API_KEY` | - | 방화벽 webhook 인증용 API 키. 요청 헤더 `X-Api-Key`와 일치해야 통과 |
| `FIREWALL_ALLOWED_IPS` | - | 방화벽 webhook 허용 소스 IP/CIDR(쉼표구분) |

## 사용 가능한 collector / notifier / remediator

- **collectors**: `guardduty`, `securityhub`, `security_group`, `access_analyzer`, `cloudtrail`, `vpc_flow_logs`, `firewall_syslog`, `compliance`
- **notifiers**: `slack`, `email_sns`, `stdout`
- **remediators**:
  - `nacl_block_ip` — brute-force 원격 IP를 NACL deny
  - `sg_revoke_ingress` — SG 인터넷 개방 규칙 회수
  - `s3_public_block` — 공개 노출 S3 버킷에 Public Access Block 적용
  - `waf_ipset_block` — 악성 IP를 WAFv2 IPSet에 추가(앱 계층 차단, IPSet 사전 구성 필요)
  - `iam_disable_key` — 침해 의심 IAM 액세스 키를 Inactive로 비활성화
  - `ec2_quarantine` — 침해 의심 EC2 인스턴스를 격리 SG로 교체(격리 SG 사전 구성 필요)

> **`cloudtrail` collector**: Security Hub에 집계되지 않는 위험 관리 이벤트(로깅 중지, 정책/키 변경, 루트 사용 등)를 `lookup_events`로 직접 감지합니다. 위험 이벤트 목록은 `collectors/cloudtrail.py`의 `RISKY_EVENTS`에서 조정할 수 있습니다.
>
> **`vpc_flow_logs` collector**: VPC Flow Logs가 CloudWatch Logs로 적재된 로그그룹에 Logs Insights 쿼리를 실행해 대량 REJECT/포트 스캔을 감지합니다. `FLOWLOGS_LOG_GROUP` 설정이 필수이며, 미설정 시 아무 동작도 하지 않습니다.
>
> **`ec2_quarantine` remediator**: 인스턴스를 종료/중지하지 않고 격리 SG로만 교체해 포렌식을 보존합니다. 원래 SG 목록은 감사 로그(`OriginalGroups`)에 남겨 롤백 가능합니다. `QUARANTINE_SG_ID` 미설정 시 대상에서 제외됩니다.

## 컴플라이언스 점검 (`compliance`)

AWS 계정 구성을 **규칙 기반으로 점검**해 위반을 finding으로 산출합니다(폴링 전용, 구성 스캔). GuardDuty/Security Hub가 실시간으로 못 잡는 "하드닝/구성" 관점을 커버합니다. 점검 항목 코드 체계(`CA-nn`)는 KISA 기반 [KESE-KIT](https://github.com/cdppcorp/KESE-KIT)(MIT)의 클라우드 점검 방식을 참고했고, 점검 로직은 boto3로 새로 구현했습니다.

| 코드 | 항목 | 심각도 | 카테고리 | 서비스 |
|------|------|:------:|---------|--------|
| `CA-01` | S3 계정 수준 퍼블릭 액세스 차단 미설정 | HIGH | 데이터 보호 | s3 |
| `CA-02` | S3 버킷 기본 암호화 미설정 | MEDIUM | 데이터 보호 | s3 |
| `CA-03` | EBS 기본 암호화 비활성화 | MEDIUM | 데이터 보호 | ec2 |
| `CA-10` | IAM 비밀번호 정책 미흡 | MEDIUM | 계정 관리 | iam |
| `CA-11` | 루트 계정 액세스 키 존재 | CRITICAL | 계정 관리 | iam |
| `CA-12` | 콘솔 사용자 MFA 미설정 | HIGH | 계정 관리 | iam |
| `CA-13` | IAM 사용자당 다중 활성 액세스 키 | MEDIUM | 계정 관리 | iam |
| `CA-20` | 다중 리전 CloudTrail 미구성 | HIGH | 감사/로깅 | cloudtrail |
| `CA-30` | 기본 보안그룹에 허용 규칙 존재 | MEDIUM | 네트워크 | ec2 |
| `CA-40` | RDS 인스턴스 퍼블릭 액세스 허용 | HIGH | 네트워크 | rds |
| `CA-41` | RDS 저장 데이터 암호화 미설정 | MEDIUM | 데이터 보호 | rds |
| `SC-01` | ECR 리포지토리 푸시 시 이미지 스캔 미설정 | MEDIUM | 공급망 보안 | ecr |
| `SC-02` | ECR 이미지 태그 불변성 미설정 | LOW | 공급망 보안 | ecr |
| `SC-10` | Lambda 함수 지원 종료(EOL) 런타임 사용 | HIGH | 공급망 보안 | lambda |
| `ZT-01` | 관리형 정책에 와일드카드 관리자 권한(Action:* Resource:*) | HIGH | 제로트러스트 | iam |
| `ZT-02` | 오래된 IAM 액세스 키(90일 초과 미교체) | MEDIUM | 제로트러스트 | iam |

> **SW 공급망(SC)/제로트러스트(ZT) 항목**은 KISA 기반 [KESE-KIT](https://github.com/cdppcorp/KESE-KIT)(MIT)의 SW 공급망·제로트러스트 가이드 접근을 참고해 AWS API로 새로 구현했습니다. (SC: NIST SSDF/NTIA SBOM, ZT: NIST SP 800-207 관점)

- 활성화: `COLLECTORS`에 `compliance` 추가 (예: `COLLECTORS=guardduty,securityhub,compliance`)
- 새 항목은 `src/agent/compliance/`에 체크 클래스를 추가하고 `compliance/registry.py`에 등록하면 됩니다([EXTENDING.md](EXTENDING.md) 참고).
- 필요한 읽기 권한은 [iam/agent-policy.json](../iam/agent-policy.json)의 `ComplianceRead`에 포함되어 있습니다.

### 점수/리포트 요약

점검 결과를 **100점 만점 점수 + 등급(A~F)**과 카테고리별/심각도별 집계로 요약합니다.

```bash
# CLI: 계정 점검 후 리포트(텍스트) 출력 — AWS 자격증명 필요
PYTHONPATH=src python -m agent.cli --compliance-report
PYTHONPATH=src python -m agent.cli --compliance-report --json   # JSON

# 웹 콘솔: "컴플라이언스 점검 항목" 탭 → "데모 리포트 보기" (AWS 없이 점수 UI 확인)
```

점수 모델(감점식): 기준 100점에서 위반 심각도별 가중치(CRITICAL 40 / HIGH 15 / MEDIUM 5 / LOW 2)를 차감(하한 0). 등급 A(90+) B(75+) C(60+) D(40+) F.

## 써드파티 방화벽 수신 (`firewall_syslog`)

Palo Alto / Fortinet / Check Point 등 외부 방화벽이 보낸 로그를 **수신**해 정규화합니다.
AWS 폴링이 아니라 **API Gateway → Lambda** HTTP 엔드포인트로 받습니다.

```
방화벽 장비 → (HTTP POST) → API Gateway → Lambda(handler) → 벤더 파서 → SecurityFinding → 알림/대응
```

- **입력 형식**: JSON `{"firewall_lines": ["<raw>", ...], "vendor": "fortinet"}` 또는
  `{"firewall_raw": "<multi-line>"}`, 혹은 `text/plain` 본문(개행 구분).
- **벤더 지정**: JSON `vendor` 필드 또는 쿼리스트링 `?vendor=fortinet`. 미지정 시 **로그 내용으로 자동 감지**.
- **지원 벤더**: `fortinet`(key=value), `paloalto`(CSV), `checkpoint`(key=value), `cef`(공통 fallback).
- **배포**: 이 collector는 스케줄/EventBridge가 아니라 HTTP 트리거로 동작합니다. handler가 API Gateway 이벤트(`httpMethod` 또는 `requestContext.http`)를 자동 인식해 방화벽 경로로 라우팅합니다.

### webhook 인증 (권장)

HTTP 엔드포인트는 공개 노출될 수 있으므로 **애플리케이션 레벨 인증**을 내장했습니다. `handler`가 로그를 파싱하기 **전에** 검사합니다.

- **API 키**: `FIREWALL_API_KEY`를 설정하면, 요청 헤더 `X-Api-Key`가 일치해야 통과(불일치 시 `401`). 상수 시간 비교로 타이밍 공격을 방지합니다.
- **IP 허용목록**: `FIREWALL_ALLOWED_IPS`(IP 또는 CIDR, 쉼표구분)를 설정하면 소스 IP가 목록에 있어야 통과(아니면 `403`). API Gateway v1(REST)/v2(HTTP) 이벤트를 모두 인식합니다.
- 둘 다 설정하면 **둘 다 통과**해야 합니다. 둘 다 미설정이면 인증을 적용하지 않고(기존 동작 유지) **경고 로그**를 남깁니다.

방화벽 장비 설정 예 (헤더에 키 추가):
```
FortiGate/PAN-OS webhook 설정에서 커스텀 헤더:
  X-Api-Key: <FIREWALL_API_KEY 값>
```

```bash
export FIREWALL_API_KEY="아무도-모르는-긴-랜덤-문자열"
export FIREWALL_ALLOWED_IPS="203.0.113.10,198.51.100.0/24"   # 방화벽 장비 IP 대역
```

> 심층 방어를 위해 API Gateway 자체 인증(API 키/mTLS/WAF/IP 정책)과 함께 사용하는 것을 권장합니다. 새 벤더는 `firewall/`에 파서를 추가하면 됩니다([EXTENDING.md](EXTENDING.md) 참고).

## 자동 대응 안전 수칙

자동 대응은 2중 안전장치로 보호됩니다:

1. `REMEDIATION_ENABLED=true` 로 기능을 켜도, `REMEDIATION_DRY_RUN` 이 기본 `true`라 **계획만** 산출합니다.
2. 실제 변경은 `REMEDIATION_ENABLED=true` **그리고** `REMEDIATION_DRY_RUN=false` 를 모두 지정해야 수행됩니다.

권장 도입 절차:
```bash
# 1단계: dry-run으로 어떤 액션이 계획되는지 감사 로그로 확인
export REMEDIATION_ENABLED=true          # dry_run은 기본 true
export REMEDIATION_ALLOWED_TYPES="UnauthorizedAccess:EC2/SSHBruteForce"

# 2단계: 화이트리스트를 좁게 유지한 채로만 실제 적용 전환
export REMEDIATION_DRY_RUN=false
```
모든 대응 시도는 `[REMEDIATION-AUDIT]` 접두사로 로깅되며, 실행 결과는 핸들러 반환값의 `remediations` 배열에 포함됩니다.

### `waf_ipset_block` 사전 요구사항

이 remediator는 **차단용 IPSet이 미리 존재**하고, 그 IPSet이 WebACL의 Block 규칙에 연결돼 있어야 실효가 있습니다.

```bash
export REMEDIATORS="waf_ipset_block"
export WAF_IPSET_NAME="threat-blocklist"
export WAF_IPSET_ID="12345678-90ab-cdef-1234-567890abcdef"
export WAF_IPSET_SCOPE="REGIONAL"   # ALB/API GW 앞단. CloudFront면 CLOUDFRONT (us-east-1)
```

> IPSet이 설정되지 않으면 `waf_ipset_block`은 안전하게 대상에서 제외됩니다(아무 동작 안 함).

## 예시

```bash
export MIN_SEVERITY=HIGH
export LOOKBACK_MINUTES=15
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/XXX/YYY/ZZZ"
export SNS_TOPIC_ARN="arn:aws:sns:ap-northeast-2:111122223333:security-alerts"
```

## 심각도 매핑 규칙

- **GuardDuty**: `Severity`(0.1~8.9 float)를 점수 구간으로 매핑 (7.0+ = HIGH, 9.0+ = CRITICAL 등)
- **Security Hub(ASFF)**: `Severity.Label`을 우선 사용, 없으면 `Normalized`(0~100)/10 점수로 매핑
