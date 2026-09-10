"""AWS 공통 유틸.

boto3 클라이언트 생성을 한 곳으로 통합해 collector/remediator/notifier가 재사용한다.

boto3는 실제 AWS 호출 시점에만 필요하므로 지연 import한다.
→ 웹 검증 콘솔(파싱/미리보기 경로)은 boto3 미설치 환경에서도 실행된다.
"""

from __future__ import annotations

from typing import Any


def make_client(service: str, region: str | None = None, session: Any = None):
    """boto3 클라이언트 생성 공통 헬퍼.

    - session이 주어지면 그 세션을, 아니면 기본 세션을 사용.
    - region은 빈 문자열을 None으로 정규화(모든 호출부 동작 일관화).
    - boto3는 이 함수가 실제 호출될 때만 import한다(미설치 시 여기서만 오류).
    """
    import boto3  # 지연 import: 실제 AWS 호출 시점에만 필요

    sess = session or boto3.Session()
    return sess.client(service, region_name=region or None)
