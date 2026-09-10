# 프로젝트 진행 상태 (이어서 작업용)

> 다음 세션에서 이 파일을 먼저 읽으면 어디까지 했고 무엇을 이어서 할지 바로 파악됩니다.
> 최종 업데이트: 2026-09-10 · 저장소: https://github.com/leeyonsei78/kiro-aws-security-agent (public)

---

## 🚀 실제 AWS 운영 진행 상황 (사용자: 실제 계정 사용 중)

> **이어서 하실 때 이 섹션부터 보세요.** 아래는 코드 개발이 아니라, **실제 AWS 계정에 이 도구를 적용**하는 진행 상황입니다.

### 완료한 것
- ✅ **AWS 계정 생성** — 무료 크레딧 $100, 유효기간 182일(2027-03-10까지)
- ✅ **예산 알림 설정** — $0.01 초과 지출 시 이메일 경고
- ✅ **IAM 사용자** `security-agent-user` 생성 + `ReadOnlyAccess` 정책
- ✅ **로컬 PC AWS CLI 설치 + `aws configure`** 완료 (리전 `ap-northeast-2`)
- ✅ **자체 점검 실행 성공** → **70점 (C등급), 위반 4건**
- ⚠️ GuardDuty/Security Hub는 **아직 안 켬**(과금 없음). 지금까지 무료 API만 사용.

### 자체 점검으로 나온 위반 4건 (다음에 고칠 대상)
| 코드 | 위반 | 심각도 | 수정 명령 |
|------|------|:------:|-----------|
| CA-20 | 다중 리전 CloudTrail 미구성 | HIGH | 콘솔에서 CloudTrail → "추적 생성"(다중 리전) 또는 `aws cloudtrail create-trail` + S3 버킷 |
| CA-10 | IAM 비밀번호 정책 미흡 | MEDIUM | `aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters` |
| CA-03 | EBS 기본 암호화 비활성화 | MEDIUM | `aws ec2 enable-ebs-encryption-by-default --region ap-northeast-2` |
| CA-30 | 기본 보안그룹 허용 규칙 존재(sg-0db51df4b707e3bb2) | MEDIUM | 콘솔 EC2 → 해당 기본 SG → 인바운드/아웃바운드 규칙 모두 제거 |

### 로컬에서 다시 점검하는 법 (재개 시 이 3줄)
```powershell
cd C:\kiro-aws-security-agent-main
aws sts get-caller-identity        # 로그인 확인(키는 이미 저장됨)
$env:AWS_REGION="ap-northeast-2"; $env:PYTHONPATH="src"; python -m agent.cli --compliance-report
```
> 웹 화면으로 보려면 `run.bat` 더블클릭 → http://127.0.0.1:8080

### ⏭️ 실제 운영 다음 할 일 (순서 추천)
1. **위반 4건 수정** → 다시 점검해서 점수 오르는지 확인 (위 표의 수정 명령 사용)
2. **자동화 배포** (`deploy/sam`): `sam build && sam deploy --guided` — 매일 자동 점검 + 이메일 알림. 파라미터: `MinSeverity=MEDIUM Collectors=guardduty,securityhub,compliance NotificationEmail=<내 이메일>`. 배포하려면 로컬에 **SAM CLI** 설치 필요.
3. (선택) **GuardDuty 30일 무료 체험** 켜서 위협 탐지 → 알림 테스트. 테스트 후 Disable로 과금 방지.
4. 배포 시 IAM 권한: 점검만이면 read 권한, 자동 대응까지면 `iam/remediation-policy.json` 추가.

### 💸 비용 안전 메모
- 지금은 과금 요인 없음(GuardDuty 미사용). 예산 알림 설정됨.
- GuardDuty/Security Hub는 30일 무료 후 과금 → 테스트만 하면 반드시 Disable.
- $100 크레딧이 대부분 커버하지만 크레딧 소진/기간 만료 후 주의.

---

## 한 줄 요약 (도구 자체)

AWS 보안 신호 + 써드파티 방화벽 로그를 **수집 → 정규화 → 필터 → 알림 → 자동 대응**하는 확장형 에이전트. 플러그인 구조, 웹 검증 콘솔, SAM/Terraform 배포, CI(단위+moto 통합)까지 완성. 현재 CI 전부 green.

---

## ✅ 지금까지 완료한 것

### 코어 기능
- **Collector 8종**: `guardduty`, `securityhub`, `security_group`, `access_analyzer`, `cloudtrail`, `vpc_flow_logs`, `firewall_syslog`, `compliance`(점검 16종: CA 11 + SC 3(공급망) + ZT 2(제로트러스트) + 점수/리포트, KESE-KIT 참고)
- **Notifier 3종**: `slack`, `email_sns`, `stdout` (각각 `render()`로 전송 없이 미리보기 지원)
- **Remediator 6종**: `nacl_block_ip`, `sg_revoke_ingress`, `s3_public_block`, `waf_ipset_block`, `iam_disable_key`, `ec2_quarantine` (기본 비활성 + dry-run + 화이트리스트 + 감사로그)
- **방화벽 파서 4종**: `fortinet`, `paloalto`, `checkpoint`, `cef` (자동 벤더 감지)
- **Lambda handler**: 스케줄 폴링 + EventBridge 실시간 + 방화벽 HTTP webhook 3경로 자동 라우팅

### 품질/운영
- **리팩터링 완료**: 공통 모듈 `aws.py`(make_client), `finding_utils.py`(guardduty_remote_ip), `models.parse_ts`, firewall `util`(slug/severity). ruff(F401/F811/F841) 통과
- **웹 검증 콘솔** (`src/agent/webui/`): 브라우저에서 확인. 탭 6개(전체 기능 개요 / 방화벽 / AWS 이벤트 / 컴플라이언스(점수 리포트) / 모니터링 대상 지정 / 용어 사전). boto3 없이 실행됨(aws.py 지연 import). Windows는 `run.bat` 더블클릭, mac/linux는 `./run.sh`. AWS 자격증명 불필요.
- **방화벽 webhook 인증** (`webhook_auth.py`): API 키(X-Api-Key, 상수시간 비교) + IP 허용목록(CIDR). 둘 다 미설정 시 경고 후 통과.
- **배포**: `deploy/sam/template.yaml`, `deploy/terraform/` (Lambda+IAM+SNS+EventBridge+선택 HTTP API, 인증/대응 파라미터화)
- **CI**: `.github/workflows/ci.yml` — 단위 테스트(py3.10/3.11/3.12) + moto 통합 잡. 현재 전부 success.
- **LICENSE**: MIT
- **문서**: `README.md`, `따라하기_매뉴얼.md`(스크린샷 5종 포함), `docs/{CONFIG,DEPLOY,WEBUI,EXTENDING}.md`

### 테스트 (총 9 단위 스위트 + 통합)
- 단위: `tests/test_*.py` — pipeline, remediation, extensions(1~3), firewall, webhook_auth, webui, pipeline_preview
  - 실행: `for t in tests/test_*.py; do PYTHONPATH="tests/_stubs" python "$t"; done`
- 통합(moto): `tests/integration/test_moto_*.py` — EC2/S3/IAM 실제 호출 경로. moto 미설치 시 자동 skip.
  - 실행: `pip install -r requirements-dev.txt && PYTHONPATH=src python -m pytest tests/integration -v`

---

## ⏭️ 다음에 이어서 할 후보 (우선순위 순)

1. **실제 웹 콘솔 스크린샷으로 교체**
   - 현재 `docs/img/*.svg`는 실제 렌더링이 아니라 색상·레이아웃 재현 이미지(sandbox에 브라우저 없어서).
   - 본인 PC에서 `PYTHONPATH=src python -m agent.webui.server` 실행 → 브라우저 캡처 → `docs/img/`에 PNG로 교체하면 매뉴얼이 더 정확해짐.

2. **영어 문서** (`README_EN.md`, 매뉴얼 영어판) — 오픈소스 공유/홍보용.

3. **CONTRIBUTING.md + 이슈/PR 템플릿** (`.github/`) — 기여 편의, public 저장소 기본기.

4. **통합 테스트 확대** — moto가 지원하는 범위에서 WAFv2 IPSet, CloudTrail 등 추가 커버.

5. **남은 collector** (Inspector, Config, WAF, Shield) — 다만 대부분 Security Hub에 집계되어 우선순위 낮음.

6. **알림 채널 추가** — PagerDuty/MS Teams notifier 등.

> 특별한 선호가 없으면 **1번(실제 스크린샷) 또는 3번(CONTRIBUTING/템플릿)** 부터 권장.

---

## 🔧 이어서 작업 재개 방법

```bash
# 1) 코드 받기 (또는 기존 sandbox면 이미 있음)
git clone https://github.com/leeyonsei78/kiro-aws-security-agent.git
cd kiro-aws-security-agent

# 2) 상태 확인
cat PROJECT_STATUS.md          # 이 파일
git log --oneline -5

# 3) 로컬 검증 (AWS 불필요)
for t in tests/test_*.py; do PYTHONPATH="tests/_stubs" python "$t"; done   # 단위 테스트
PYTHONPATH=src python -m agent.webui.server                                # 웹 콘솔 → http://127.0.0.1:8080

# 4) 새 작업 후 반영
ruff check src/agent --select F401,F811,F841
git add . && git commit -m "..." && git push origin main
# CI 결과: gh api repos/leeyonsei78/kiro-aws-security-agent/actions/runs?per_page=1
```

---

## ⚠️ 환경 제약 메모 (중요)

- 이 개발 sandbox는 **네트워크 제한(INTEGRATIONS_ONLY)** 이라 `pip install boto3/moto` **불가**.
  → 단위 테스트는 `tests/_stubs`의 boto3 stub으로 실행. moto 통합 테스트는 **CI(GitHub Actions)에서만** 실제 실행됨.
- sandbox에 **브라우저(chromium) 없음** → 웹 콘솔 실제 캡처 불가. 스크린샷은 SVG 재현본.
- GitHub 연동은 Settings > Agent > Connect GitHub 로 이미 연결됨(계정 leeyonsei78). push/PR은 `git push` / `gh api` REST로 처리.

---

## 파일 구조 빠른 참조

```
src/agent/
  models.py config.py aws.py finding_utils.py registry.py core.py
  handler.py cli.py webhook_auth.py
  collectors/  (guardduty, securityhub, security_group, access_analyzer, cloudtrail, vpc_flow_logs, firewall_syslog)
  notifiers/   (slack, email_sns, stdout, base)
  remediators/ (nacl_block_ip, sg_revoke_ingress, s3_public_block, waf_ipset_block, iam_disable_key, ec2_quarantine, base)
  firewall/    (fortinet, paloalto, checkpoint, cef, registry, util, base)
  webui/       (server, page)
deploy/  (sam/, terraform/)
docs/    (CONFIG, DEPLOY, WEBUI, EXTENDING, img/)
tests/   (test_*.py 단위, integration/ moto, _stubs/ boto3 stub)
.github/workflows/ci.yml
```
