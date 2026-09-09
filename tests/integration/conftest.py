"""moto 통합 테스트 공통 설정.

moto/boto3가 설치돼 있지 않으면(개발 sandbox는 네트워크 제한으로 설치 불가)
이 디렉터리의 테스트 모듈을 수집 대상에서 제외한다 → CI에서만 실행된다.
"""

import os
import sys

# src 를 import 경로에 추가
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

# moto/boto3 미설치 시 통합 테스트 파일을 수집에서 제외(에러가 아니라 조용히 skip).
try:
    import boto3  # noqa: F401
    import moto  # noqa: F401

    _DEPS_OK = True
except ImportError:
    _DEPS_OK = False

# 이 디렉터리의 테스트 파일들 (deps 없으면 수집 제외)
collect_ignore = [] if _DEPS_OK else ["test_moto_ec2.py", "test_moto_s3_iam.py"]


if _DEPS_OK:
    import pytest

    @pytest.fixture(autouse=True)
    def _aws_creds(monkeypatch):
        """moto용 더미 자격증명/리전 (실제 AWS 호출 방지)."""
        for k, v in {
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_SECURITY_TOKEN": "testing",
            "AWS_SESSION_TOKEN": "testing",
            "AWS_DEFAULT_REGION": "us-east-1",
        }.items():
            monkeypatch.setenv(k, v)
