"""화이트해커(블루팀) 양성 프로그램.

보안팀이 '공격을 이해해야 방어한다'는 원칙 아래, **방어자 관점**의 학습 커리큘럼과
**안전한 실습 랩**을 제공한다. 실제 익스플로잇/무기화 페이로드는 포함하지 않는다.

- curriculum: 학습 모듈 데이터(공격 개념 + MITRE ATT&CK 매핑 + 이 에이전트의 탐지 규칙 연결 + 방어법)
- labs: 본인 소유 계정에서 안전하게 수행하는 실습(취약 설정 생성 → 에이전트 탐지 → 수정) 정의/안내

설계 원칙(안전/합법):
1) 모든 실습은 **본인 소유의 격리된 계정/리전**에서만 수행.
2) 실습 실행기는 기본 **dry-run(계획만 출력)**. 실제 변경은 명시적 확인이 있을 때만.
3) 공격 기법은 '탐지·방어를 위한 이해' 수준으로 설명하고, 공격 도구/코드는 제공하지 않는다.
"""

from __future__ import annotations

from .curriculum import (
    Module,
    all_modules,
    module_by_id,
    modules_summary,
)
from .labs import (
    Lab,
    all_labs,
    lab_by_id,
    labs_summary,
    plan_lab,
)

__all__ = [
    "Module",
    "all_modules",
    "module_by_id",
    "modules_summary",
    "Lab",
    "all_labs",
    "lab_by_id",
    "labs_summary",
    "plan_lab",
]
