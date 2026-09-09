# AWS Security Monitoring Agent

AWS 보안 서비스/장비의 findings(위협 탐지 결과)를 **수집 → 정규화 → 필터링 → 알림**하는 확장 가능한 에이전트입니다.

> 🚀 **처음 오셨나요?** [**따라하기 매뉴얼**](따라하기_매뉴얼.md)을 그대로 따라 하면 내려받기부터 실행·검증(AWS 없이 약 10분)까지 완료할 수 있습니다.

## 특징

- **플러그인 구조**: 새 보안 소스(Collector)와 알림 채널(Notifier)을 코어 수정 없이 추가
- **통합 스키마**: 소스가 달라도 `SecurityFinding` 하나로 정규화
- **두 가지 실행 모드**: 주기적 폴링(EventBridge 스케줄) + 실시간 이벤트(EventBridge event pattern)
- **확장 로드맵 반영**: WAF/Shield/Inspector/Config/CloudTrail/네트워크/써드파티, 그리고 자동 대응(remediation)을 위한 확장 포인트 마련

## 현재 지원 (MVP)

| 구분 | 지원 |
|------|------|
| Collector | Amazon GuardDuty, AWS Security Hub, Security Group(위험 개방 감지), IAM Access Analyzer(외부 공유), CloudTrail(위험 API 감지), VPC Flow Logs(이상 트래픽), 써드파티 방화벽(Palo Alto / Fortinet / Check Point / CEF) |
| Notifier | Slack (Incoming Webhook), Email (SNS) |
| Remediator | `nacl_block_ip`, `sg_revoke_ingress`, `s3_public_block`, `waf_ipset_block`, `iam_disable_key`, `ec2_quarantine` |
| 실행 | AWS Lambda (스케줄 폴링 / 실시간 이벤트 / API Gateway HTTP 수신), 로컬 CLI |

> 자동 대응은 **기본 비활성 + dry-run 기본**입니다. 실제 변경은 `REMEDIATION_ENABLED=true`와 `REMEDIATION_DRY_RUN=false`를 모두 명시해야 수행됩니다. 자세한 내용은 [docs/CONFIG.md](docs/CONFIG.md) 참고.

## 로드맵 (확장 예정)

- Collector: WAF, Shield, Inspector, Config
- 실시간 이벤트 기반 처리 강화

## 프로젝트 구조

```
src/agent/
  models.py            # 통합 SecurityFinding 데이터 모델 (+ parse_ts)
  config.py            # 환경변수 기반 설정
  aws.py               # boto3 클라이언트 생성 공통 헬퍼
  finding_utils.py     # finding raw 파싱 공통 헬퍼 (GuardDuty 원격 IP 등)
  registry.py          # collector/notifier/remediator 플러그인 등록
  core.py              # 오케스트레이션 (수집→정규화→필터→알림→대응, preview_parse)
  collectors/
    base.py            # BaseCollector 인터페이스
    guardduty.py       # GuardDuty collector
    securityhub.py     # Security Hub collector
    security_group.py  # Security Group 위험 개방 감지 collector
    access_analyzer.py # IAM Access Analyzer(외부 공유) collector
    cloudtrail.py      # CloudTrail 위험 API 호출 감지 collector
    vpc_flow_logs.py   # VPC Flow Logs 이상 트래픽 감지 collector
    firewall_syslog.py # 써드파티 방화벽 수신 collector (webhook/syslog)
  firewall/            # 써드파티 방화벽 벤더 파서
    base.py            # BaseFirewallParser 인터페이스
    registry.py        # 파서 등록 + 벤더 자동 감지
    fortinet.py        # FortiGate key=value 파서
    paloalto.py        # PAN-OS CSV 파서
    checkpoint.py      # Check Point key=value 파서
    cef.py             # CEF 공통 파서 (벤더 fallback)
    util.py            # key=value / syslog 헤더 파싱 유틸
  notifiers/
    base.py            # BaseNotifier 인터페이스
    slack.py           # Slack notifier
    email_sns.py       # Email(SNS) notifier
    stdout.py          # stdout notifier (로컬/디버깅)
  remediators/
    base.py            # BaseRemediator + 안전장치(dry-run/화이트리스트/감사)
    nacl_block_ip.py   # 위협 IP를 NACL deny로 차단
    sg_revoke_ingress.py # SG 인터넷 개방 규칙 회수
    s3_public_block.py   # 공개 S3 버킷에 Public Access Block 적용
    waf_ipset_block.py   # 악성 IP를 WAF IPSet에 추가(앱 계층 차단)
    iam_disable_key.py   # 침해 의심 IAM 액세스 키 비활성화
    ec2_quarantine.py    # 침해 의심 EC2를 격리 SG로 교체
  webui/               # 로컬 웹 검증 콘솔 (http.server + 단일 HTML)
    server.py          # 검증 서버
    page.py            # UI 페이지
  handler.py           # Lambda 진입점 (스케줄 + 실시간 이벤트 + 방화벽 HTTP)
  cli.py               # 로컬 실행용 CLI
deploy/
  sam/template.yaml    # SAM 배포 템플릿
  terraform/           # Terraform 배포 구성
```

## 로컬 실행

```bash
pip install -r requirements.txt
# AWS 자격증명은 표준 방식(환경변수/프로파일)으로 설정
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export MIN_SEVERITY="MEDIUM"
PYTHONPATH=src python -m agent.cli --lookback-minutes 60
```

## 웹 검증 콘솔 (배포 없이 확인)

로그/이벤트를 브라우저에 붙여넣어 파싱→정규화→필터 결과를 즉시 확인 (AWS 자격증명 불필요):

```bash
PYTHONPATH=src python -m agent.webui.server   # http://127.0.0.1:8080
```

자세한 사용법은 [docs/WEBUI.md](docs/WEBUI.md).

## 배포

- **SAM**: [`deploy/sam/template.yaml`](deploy/sam/template.yaml)
- **Terraform**: [`deploy/terraform/`](deploy/terraform/)

Lambda + IAM + SNS + EventBridge(스케줄/실시간) + (선택)방화벽 HTTP API를 한 번에 생성. 절차는 [docs/DEPLOY.md](docs/DEPLOY.md).

자세한 설정은 [docs/CONFIG.md](docs/CONFIG.md) 참고.
