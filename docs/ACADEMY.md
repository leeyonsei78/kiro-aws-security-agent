# 화이트해커(블루팀) 양성 프로그램

> "공격을 알아야 방어한다." 보안팀이 실제 공격 기법을 **방어자 관점**에서 이해하고,
> 그 지식을 이 에이전트의 탐지·대응에 바로 연결해 업무에 적용하도록 돕는 학습 + 실습 프로그램입니다.

## 설계 원칙 (안전 · 합법)

이 프로그램은 **레드팀 공격 도구가 아니라 블루팀 교육 도구**입니다.

- ✅ **방어자 관점**: 각 공격 유형을 "탐지·방어에 필요한 만큼" 개념적으로 설명합니다.
- ✅ **탐지 규칙 연결**: 각 공격이 이 에이전트의 어떤 점검 규칙(`CA-`/`SC-`/`ZT-`)이나 GuardDuty 신호로 잡히는지 매핑합니다.
- ✅ **MITRE ATT&CK 매핑**: 표준 기술 ID로 정리해 실무 위협 모델링과 연결합니다.
- ✅ **안전한 실습**: 본인 소유의 격리된 테스트 계정에서 "취약 설정 만들기 → 에이전트 탐지 → 안전하게 수정" 사이클을 체험합니다.
- ❌ **제공하지 않는 것**: 실제 익스플로잇 코드, 무기화된 페이로드, 타인 시스템 대상 공격 도구.
- ⚠️ **자동 실행 안 함**: 실습 계획은 참고용 AWS CLI 명령을 **텍스트로만** 보여줍니다. 실제 실행은 사용자가 본인 환경에서 직접 결정합니다.

> 모든 실습은 **반드시 본인 소유의 테스트 계정/리전에서만** 수행하세요. 운영 계정에서 실습하지 마세요.

## 학습 모듈 (8개)

| ID | 제목 | 난이도 | 영역 | 연결 탐지 규칙 |
|----|------|:------:|------|----------------|
| M01 | 공격 표면 넓히기: 개방된 보안그룹/기본 SG | 입문 | 네트워크 | CA-30, security_group |
| M02 | 자격증명 무차별 대입/원격 로그인 공격 | 입문 | 자격증명/IAM | GuardDuty SSHBruteForce, nacl_block_ip |
| M03 | 데이터 노출: 퍼블릭 S3 버킷 | 입문 | 데이터 | CA-01, CA-02, s3_public_block |
| M04 | 과도한 권한과 자격증명 탈취 | 중급 | 자격증명/IAM | CA-11, CA-13, ZT-01, ZT-02, iam_disable_key |
| M05 | 계정 정책 약화: 비밀번호 정책/MFA 미흡 | 입문 | 자격증명/IAM | CA-10, CA-12 |
| M06 | 탐지 회피: 로깅 무력화 | 중급 | 로깅/탐지 | CA-20, cloudtrail |
| M07 | 소프트웨어 공급망 위협 | 심화 | 공급망 | SC-01, SC-02, SC-10 |
| M08 | 방화벽 로그로 위협 읽기 | 중급 | 네트워크 | firewall(fortinet/paloalto/checkpoint/cef) |

각 모듈은 **공격자 관점 → 방어자 관점 → MITRE ATT&CK → 탐지 규칙 → 방어 조치 → 연결 실습**으로 구성됩니다.

## 실습 랩 (7개)

| ID | 제목 | 모듈 | 예상 | 탐지 규칙 |
|----|------|:----:|:----:|-----------|
| LAB-SG-OPEN | 열린 보안그룹 만들기 → 탐지 → 잠그기 | M01 | ~15분 | CA-30 |
| LAB-S3-PUBLIC | 퍼블릭 위험 버킷 실습 → 탐지 → 차단 | M03 | ~15분 | CA-01, CA-02 |
| LAB-IAM-PWPOLICY | 약한 비밀번호 정책 → 탐지 → 강화 | M05 | ~10분 | CA-10 |
| LAB-IAM-STALE-KEY | 오래된 액세스 키 탐지 실습 | M04 | ~10분 | ZT-02, CA-13 |
| LAB-CT-DISABLED | 로깅 사각지대 → 다중 리전 CloudTrail 켜기 | M06 | ~20분 | CA-20 |
| LAB-GD-SAMPLE | GuardDuty 샘플 finding으로 탐지→알림 흐름 체험 | M02 | ~15분 | GuardDuty, nacl_block_ip |
| LAB-FW-PARSE | 방화벽 로그 읽기 실습(자격증명 불필요) | M08 | ~10분 | firewall |

각 랩은 `setup`(취약 설정) → `detect`(에이전트 점검) → `fix`(안전하게 수정) → `teardown`(정리) 단계로 구성되며,
자원을 삭제/비활성화하는 단계는 `destructive`로 표시되어 사전 경고합니다.

## 사용법

### 웹 콘솔

```bash
python -m agent.webui.server   # http://127.0.0.1:8080
```
브라우저에서 **화이트해커 양성** 탭을 엽니다.
- **학습 모듈 불러오기**: 8개 모듈을 공격자/방어자 관점, MITRE, 탐지 규칙과 함께 표시
- **실습 랩 목록**: 랩 카드에서 **실습 계획 보기**로 단계별 명령/안전 유의사항 확인
- 모듈 카드의 연결 실습 칩을 눌러 해당 랩 계획으로 바로 이동

Windows는 `run.bat`, mac/Linux는 `./run.sh`로도 실행할 수 있습니다. AWS 자격증명이 없어도 됩니다.

### CLI

```bash
# 학습 모듈 목록
PYTHONPATH=src python -m agent.cli --academy

# 특정 모듈 상세
PYTHONPATH=src python -m agent.cli --module M02

# 실습 랩 목록
PYTHONPATH=src python -m agent.cli --list-labs

# 특정 실습 랩의 단계별 계획(명령은 자동 실행하지 않음)
PYTHONPATH=src python -m agent.cli --lab LAB-SG-OPEN

# JSON 출력
PYTHONPATH=src python -m agent.cli --academy --json
PYTHONPATH=src python -m agent.cli --lab LAB-SG-OPEN --json
```

> Windows PowerShell에서는 `$env:PYTHONPATH="src"; python -m agent.cli --academy` 형태로 실행하세요.

## 실습 → 업무 적용 흐름

1. 모듈로 공격 개념과 **어떤 탐지 규칙이 잡는지** 학습합니다.
2. 랩으로 본인 테스트 계정에서 취약 설정을 만들고 `--compliance-report`로 **실제 탐지**를 확인합니다.
3. `fix` 단계로 안전하게 수정하고 재점검해 점수가 오르는지 확인합니다.
4. 배포된 에이전트가 같은 규칙으로 운영 계정을 매시간 점검하고 Slack으로 알립니다.

## 확장하기

- 학습 모듈 추가: `src/agent/academy/curriculum.py`의 `_MODULES`에 `Module(...)` 항목 추가
- 실습 랩 추가: `src/agent/academy/labs.py`의 `_LABS`에 `Lab(...)` + `LabStep(...)` 추가
- 새 랩을 만들면 관련 모듈의 `lab_ids`에 연결하세요(정합성 유지).

새 점검 규칙과 연동하려면 [docs/EXTENDING.md](EXTENDING.md)의 컴플라이언스 체크 추가 방법을 함께 참고하세요.
