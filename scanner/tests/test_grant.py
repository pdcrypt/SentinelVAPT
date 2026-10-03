"""The scanner must never operate without a valid grant: active assessment,
active authorization, lab environment, valid scope. Refusals happen before
any network I/O."""

from datetime import timedelta
from typing import Any

import pytest
from tests.conftest import NOW, FakeTime, LabServer, SpyConnector, lab_resolver, make_grant

from sentinel_scanner import GrantRejected, ScanGrant, run_discovery
from sentinel_scanner.grant import validate_grant


def test_valid_grant_returns_policy(lab: LabServer) -> None:
    policy = validate_grant(make_grant(lab), NOW)
    assert policy.hosts == {"lab.test"}


@pytest.mark.parametrize("status", ["planned", "completed", "cancelled", "IN_PROGRESS", ""])
def test_assessment_must_be_in_progress(lab: LabServer, status: str) -> None:
    with pytest.raises(GrantRejected) as exc:
        validate_grant(make_grant(lab, assessment_status=status), NOW)
    assert exc.value.code == "assessment_not_active"


@pytest.mark.parametrize(
    ("valid_from", "valid_until"),
    [
        (NOW + timedelta(seconds=1), NOW + timedelta(hours=1)),  # not yet active
        (NOW - timedelta(hours=2), NOW - timedelta(seconds=1)),  # expired
        (NOW - timedelta(hours=2), NOW),  # ends exactly now
    ],
)
def test_authorization_window_must_be_active(
    lab: LabServer, valid_from: Any, valid_until: Any
) -> None:
    grant = make_grant(lab, valid_from=valid_from, valid_until=valid_until)
    with pytest.raises(GrantRejected) as exc:
        validate_grant(grant, NOW)
    assert exc.value.code == "authorization_not_active"


def test_naive_datetimes_rejected(lab: LabServer) -> None:
    grant = make_grant(lab, valid_from=NOW.replace(tzinfo=None) - timedelta(hours=1))
    with pytest.raises(GrantRejected, match="timezone"):
        validate_grant(grant, NOW)
    with pytest.raises(GrantRejected, match="timezone"):
        validate_grant(make_grant(lab), NOW.replace(tzinfo=None))


def test_external_targets_are_not_supported_in_phase_2(lab: LabServer) -> None:
    grant = make_grant(lab, scope={"environment": "authorized_external"})
    with pytest.raises(GrantRejected) as exc:
        validate_grant(grant, NOW)
    assert exc.value.code == "environment_not_supported"


@pytest.mark.parametrize(
    "scope",
    [
        {"in_scope_hosts": ("example.com",), "base_url": "http://example.com/"},
        {"in_scope_hosts": ("8.8.8.8",), "base_url": "http://8.8.8.8/"},
        {"in_scope_hosts": ("169.254.169.254",), "base_url": "http://169.254.169.254/"},
        {"in_scope_hosts": ("0xa9fea9fe",), "base_url": "http://0xa9fea9fe/"},
        {"in_scope_hosts": ("*.test",)},
        {"in_scope_hosts": ()},
        {"allowed_ports": ()},
        {"allowed_ports": (0,)},
        {"in_scope_path_prefixes": ()},
        {"base_url": "http://other.test/"},  # base host not in scope
        {"base_url": "http://user:pw@lab.test/"},
        {"excluded_paths": ("/",)},  # base path excluded
    ],
)
def test_invalid_scope_is_rejected(lab: LabServer, scope: dict[str, Any]) -> None:
    with pytest.raises(GrantRejected) as exc:
        validate_grant(make_grant(lab, scope=scope), NOW)
    assert exc.value.code == "invalid_scope"


@pytest.mark.parametrize(
    "overrides",
    [
        {"assessment_status": "planned"},
        {"valid_until": NOW - timedelta(minutes=1), "valid_from": NOW - timedelta(hours=1)},
        {"scope": {"environment": "authorized_external"}},
        {"scope": {"in_scope_hosts": ("8.8.8.8",), "base_url": "http://8.8.8.8/"}},
    ],
)
def test_rejected_grant_sends_nothing(
    lab: LabServer, spy: SpyConnector, fake_time: FakeTime, overrides: dict[str, Any]
) -> None:
    with pytest.raises(GrantRejected):
        run_discovery(
            make_grant(lab, **overrides),
            resolver=lab_resolver(),
            connector=spy,
            now=fake_time.now,
            monotonic=fake_time.monotonic,
            sleep=fake_time.sleep,
        )
    assert spy.opened == []
    assert lab.requests == []


def test_grant_round_trips_through_plain_dicts(lab: LabServer) -> None:
    grant = make_grant(lab)
    data = {
        "target_id": str(grant.target_id),
        "assessment_id": str(grant.assessment_id),
        "authorization_id": str(grant.authorization_id),
        "authorization_version": 1,
        "assessment_status": "in_progress",
        "valid_from": grant.valid_from.isoformat(),
        "valid_until": grant.valid_until.isoformat(),
        "scope": {
            "base_url": grant.scope.base_url,
            "environment": "local_lab",
            "in_scope_hosts": ["lab.test"],
            "allowed_ports": [lab.port],
            "in_scope_path_prefixes": ["/"],
        },
    }
    assert ScanGrant.from_dict(data) == grant
