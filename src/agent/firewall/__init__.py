"""써드파티 방화벽 로그 파서.

Palo Alto / Fortinet / Check Point 등의 syslog/webhook 로그를 SecurityFinding으로 정규화한다.
벤더별 파서는 BaseFirewallParser를 상속하고 registry에 등록한다.
"""
