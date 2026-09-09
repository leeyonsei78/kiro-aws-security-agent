"""테스트 전용 최소 boto3 stub.

네트워크 제한 sandbox에서 import 체인이 끊기지 않도록 하는 용도.
실제 AWS 호출(collect)은 이 stub으로 하지 않으며, parse_event/필터/알림만 검증한다.
"""

__version__ = "stub"


class _StubClient:
    def __getattr__(self, name):
        def _method(*args, **kwargs):
            raise RuntimeError(f"boto3 stub: '{name}' 호출은 테스트에서 지원하지 않음")
        return _method


class Session:
    def __init__(self, *args, **kwargs):
        pass

    def client(self, *args, **kwargs):
        return _StubClient()
