"""화이트해커 양성 프로그램의 CLI 텍스트 출력 포매터."""

from __future__ import annotations

from .curriculum import module_by_id, modules_summary
from .labs import labs_summary, plan_lab


def _bullet(items: list[str], indent: str = "    - ") -> str:
    return "\n".join(f"{indent}{x}" for x in items) if items else f"{indent}(없음)"


def format_modules_list() -> str:
    """학습 모듈 한 줄 요약 목록."""
    mods = modules_summary()
    lines = [f"화이트해커(블루팀) 양성 — 학습 모듈 {len(mods)}개", "=" * 48]
    for m in mods:
        labs = (" · 실습: " + ", ".join(m["lab_ids"])) if m["lab_ids"] else ""
        lines.append(f"[{m['id']}] ({m['level']}/{m['domain']}) {m['title']}")
        lines.append(f"       {m['summary']}{labs}")
    lines.append("")
    lines.append("모듈 상세: --module <ID> (예: --module M01) · 실습 목록: --list-labs")
    return "\n".join(lines)


def format_module_detail(module_id: str) -> str:
    """특정 모듈 상세."""
    m = module_by_id(module_id)
    if m is None:
        return f"알 수 없는 모듈: {module_id} (목록은 --academy)"
    lines = [
        f"[{m.id}] {m.title}  ({m.level} / {m.domain})",
        "=" * 56,
        f"요약: {m.summary}",
        "",
        f"🔴 공격자 관점:\n    {m.attacker_view}",
        f"🔵 방어자 관점:\n    {m.blue_view}",
        "",
        "🎯 MITRE ATT&CK:",
        _bullet(list(m.mitre)),
        "🛡️ 이 에이전트의 탐지 규칙:",
        _bullet(list(m.detected_by)),
        "✅ 방어 조치:",
        _bullet(list(m.defenses)),
    ]
    if m.lab_ids:
        lines += ["🧪 연결된 실습 랩:", _bullet(list(m.lab_ids))]
    if m.references:
        lines += ["📚 참고:", _bullet(list(m.references))]
    return "\n".join(lines)


def format_labs_list() -> str:
    """실습 랩 목록."""
    labs = labs_summary()
    lines = [f"안전한 실습 랩 {len(labs)}개 (본인 소유 테스트 계정에서만 · 자동 실행 안 함)", "=" * 56]
    for l in labs:
        lines.append(f"[{l['id']}] (모듈 {l['module_id']} · ~{l['est_minutes']}분) {l['title']}")
        lines.append(f"       목표: {l['objective']}")
        lines.append(f"       탐지: {', '.join(l['detected_by'])} | {l['cost_note']}")
    lines.append("")
    lines.append("실습 계획: --lab <ID> (예: --lab LAB-SG-OPEN)")
    return "\n".join(lines)


def format_lab_plan(lab_id: str) -> str:
    """특정 실습 랩의 단계별 실행 계획(참고용, 자동 실행 안 함)."""
    p = plan_lab(lab_id)
    if not p.get("ok"):
        return p.get("error", f"알 수 없는 실습: {lab_id}")
    lines = [
        f"[{p['id']}] {p['title']}  (~{p['est_minutes']}분, 모듈 {p['module_id']})",
        "=" * 56,
        f"목표: {p['objective']}",
        f"탐지 규칙: {', '.join(p['detected_by'])}",
        "사전 조건:",
        _bullet(p["prerequisites"]),
        f"비용: {p['cost_note']}",
        "",
        "⚠️ 안전 유의사항:",
        _bullet(p["safety"]),
        "",
        f"ℹ️  {p['note']}",
    ]
    if p.get("has_destructive"):
        lines.append("⚠️ 이 실습에는 자원 삭제/비활성화(destructive) 단계가 포함되어 있습니다.")
    lines.append("")
    lines.append("단계:")
    for i, s in enumerate(p["steps"], 1):
        tag = f"[{s['name']}]" + ("(삭제/비활성)" if s["destructive"] else "")
        lines.append(f"  {i}. {tag} {s['title']}")
        lines.append(f"     {s['explain']}")
        for c in s["commands"]:
            lines.append(f"     $ {c}")
    return "\n".join(lines)
