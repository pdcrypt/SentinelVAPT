"""M11 backend mutation harness (security posture dashboard). M7 harness
mechanics: CAUGHT only if a named test FAILED; files restored; tree hash
checked. No migration is involved."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m7_mutations as h  # noqa: E402

T = "tests/integration/test_m11_posture.py::"
INV = "tests/unit/test_route_inventory.py::"
REPO = "app/repositories/posture.py"
SERVICE = "app/services/posture.py"
ROUTER = "app/api/v1/routers/posture.py"

MEMBER_FILTER = "            .where(ProjectMember.user_id == user_id)\n"

MUTATIONS = [
    ("1 remove the project membership filter", [
        (REPO, MEMBER_FILTER, ""),
    ], [T + "test_nothing_crosses_project_boundaries", T + "test_project_posture_follows_project_visibility"]),
    ("2 make a global administrator see every project", [
        (REPO, MEMBER_FILTER,
         "            .where((ProjectMember.user_id == user_id) | select(User.global_role)"
         ".where(User.id == user_id).scalar_subquery().in_(['admin']))\n"),
        (REPO, "    Target,\n)", "    Target,\n    User,\n)"),
    ], [T + "test_project_posture_follows_project_visibility"]),
    ("3 count findings of scans outside the request", [
        (REPO, "            .where(Finding.scan_id.in_(scan_ids))\n            .group_by", "            .group_by"),
    ], [T + "test_nothing_crosses_project_boundaries", T + "test_counts_follow_persisted_findings_and_triage"]),
    ("4 include incomplete scans and analyses", [
        (REPO, "                Scan.status == ScanStatus.COMPLETED,\n                _analysed(Scan.id),\n", ""),
    ], [T + "test_the_latest_analysed_scan_is_selected"]),
    ("5 choose the oldest scan instead of the latest", [
        (REPO, ".order_by(Scan.target_id, Scan.finished_at.desc(), Scan.id.desc())",
         ".order_by(Scan.target_id, Scan.finished_at.asc(), Scan.id.asc())"),
    ], [T + "test_the_latest_analysed_scan_is_selected"]),
    ("6 drop the deterministic tie-break", [
        (REPO, ".order_by(Scan.target_id, Scan.finished_at.desc(), Scan.id.desc())",
         ".order_by(Scan.target_id, Scan.finished_at.desc(), Scan.id.asc())"),
    ], [T + "test_the_latest_analysed_scan_is_selected"]),
    ("7 calculate 'open' as every non-false-positive", [
        (SERVICE, "        if status == OPEN:", "        if status != FALSE_POSITIVE:"),
    ], [T + "test_counts_follow_persisted_findings_and_triage"]),
    ("8 count comparison states from current findings, not records", [
        (SERVICE, '''        for state_group in self.repo.comparison_state_counts(
            [c.comparison_id for c in comparisons.values()]
        ):
            states[state_group.comparison_id][state_group.state] = state_group.count''',
         '''        for c in comparisons.values():
            states[c.comparison_id] = {"unchanged": sum(n for _, _, n in per_scan.get(c.current_scan_id, []))}'''),
    ], [T + "test_retest_outcome_and_reports_follow_persisted_records"]),
    ("9 leak another project's names through recent scans", [
        (REPO, "            .where(Target.project_id == project_id)\n            .order_by(Scan.created_at.desc(), Scan.id.desc())",
         "            .order_by(Scan.created_at.desc(), Scan.id.desc())"),
    ], [T + "test_nothing_crosses_project_boundaries"]),
    ("10 leak another project's finding counts", [
        (REPO, '''                Target.project_id.in_(project_ids),
                Scan.status == ScanStatus.COMPLETED,''', '''                Scan.status == ScanStatus.COMPLETED,'''),
    ], [T + "test_nothing_crosses_project_boundaries"]),
    ("11 remove the project authorization descriptor", [
        (ROUTER, 'Depends(authorize(P.PROJECT_READ, R.PROJECT, "project_id"))',
         "Depends(require_global(P.CATALOG_READ))"),
        (ROUTER, "from app.api.authz import authenticated, authorize",
         "from app.api.authz import authenticated, authorize, require_global"),
        (ROUTER, "    if project is None or access.role is None:", "    if project is None:"),
        (ROUTER, "project.name, access.role)", "project.name, access.role or 'viewer')"),
    ], [T + "test_project_posture_follows_project_visibility", INV + "test_every_route_is_classified_exactly_once"]),
    ("12 trust a client project id for the overview", [
        (ROUTER, '''    limit: Limit = 50,
    offset: Offset = 0,
) -> list[dict[str, Any]]:''', '''    limit: Limit = 50,
    offset: Offset = 0,
    project_id: uuid.UUID | None = None,
) -> list[dict[str, Any]]:'''),
        (ROUTER, '''    return PostureService(PostureRepository(session)).overview(
        principal.user_id, limit=limit, offset=offset
    )''', '''    service = PostureService(PostureRepository(session))
    if project_id is not None:
        from app.repositories.posture import VisibleProject
        from app.models.enums import ProjectRole
        mine = service.repo.visible_projects(principal.user_id, limit=limit, offset=offset)
        service.repo.visible_projects = lambda *a, **k: [*mine, VisibleProject(project_id, "?", ProjectRole.VIEWER)]  # type: ignore[method-assign]
    return service.overview(principal.user_id, limit=limit, offset=offset)'''),
    ], [T + "test_nothing_crosses_project_boundaries"]),
    ("13 return unbounded scan history", [
        (REPO, "            .limit(RECENT_SCANS)\n", ""),
    ], [T + "test_recent_scan_history_is_bounded"]),
    ("14 count comparison records of comparisons outside the request", [
        (REPO, "            .where(ComparisonRecord.comparison_id.in_(comparison_ids))\n", ""),
    ], [T + "test_nothing_crosses_project_boundaries",
        T + "test_retest_outcome_and_reports_follow_persisted_records"]),
]

if __name__ == "__main__":
    h.MUTATIONS = MUTATIONS
    sys.exit(h.main())
