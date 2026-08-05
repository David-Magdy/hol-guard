from pathlib import Path

path = Path("scripts/patch_desktop_review_fixes.py")
source = path.read_text(encoding="utf-8")
old = '''replace_once(
    APPROVALS,
    \'\'\'    if search is not None:\n        search_clause, search_params = _approval_search_clause(search)\n        clauses.append(search_clause)\n        params.extend(search_params)\n    where_clause = f"where {\' and \'.join(clauses)}" if clauses else ""\n\'\'\',
    \'\'\'    if search is not None:\n        search_clause, search_params = _approval_search_clause(search)\n        clauses.append(search_clause)\n        params.extend(search_params)\n    if resolved_at_from is not None:\n        clauses.append("resolved_at >= ?")\n        params.append(resolved_at_from)\n    if resolved_at_before is not None:\n        clauses.append("resolved_at < ?")\n        params.append(resolved_at_before)\n    where_clause = f"where {\' and \'.join(clauses)}" if clauses else ""\n\'\'\',
)'''
new = '''replace_once(
    APPROVALS,
    \'\'\'    resolved_at_before: str | None = None,\n) -> int:\n    clauses = []\n    params: list[object] = []\n    if status is not None:\n        clauses.append("status = ?")\n        params.append(status)\n    if harness is not None:\n        clauses.append("harness = ?")\n        params.append(harness)\n    if search is not None:\n        search_clause, search_params = _approval_search_clause(search)\n        clauses.append(search_clause)\n        params.extend(search_params)\n    where_clause = f"where {\' and \'.join(clauses)}" if clauses else ""\n\'\'\',
    \'\'\'    resolved_at_before: str | None = None,\n) -> int:\n    clauses = []\n    params: list[object] = []\n    if status is not None:\n        clauses.append("status = ?")\n        params.append(status)\n    if harness is not None:\n        clauses.append("harness = ?")\n        params.append(harness)\n    if search is not None:\n        search_clause, search_params = _approval_search_clause(search)\n        clauses.append(search_clause)\n        params.extend(search_params)\n    if resolved_at_from is not None:\n        clauses.append("resolved_at >= ?")\n        params.append(resolved_at_from)\n    if resolved_at_before is not None:\n        clauses.append("resolved_at < ?")\n        params.append(resolved_at_before)\n    where_clause = f"where {\' and \'.join(clauses)}" if clauses else ""\n\'\'\',
)'''
if source.count(old) != 1:
    raise RuntimeError(f"expected one ambiguous replacement block, found {source.count(old)}")
path.write_text(source.replace(old, new, 1), encoding="utf-8")
