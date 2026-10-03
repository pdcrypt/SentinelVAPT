"""Grant construction from (transient) ORM rows: no database needed."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.core.errors import ScanNotAllowedError
from app.models import Assessment, Target, TargetAuthorization
from app.models.enums import AssessmentStatus, TargetEnvironment
from app.services.scan_grants import (
    build_scan_grant,
    discovery_config,
    grant_snapshot,
    scan_config_record,
)
from sentinel_scanner import ScanLimits

NOW = datetime(2026, 10, 4, 12, tzinfo=UTC)


def rows(**overrides: Any) -> tuple[Assessment, Target, TargetAuthorization]:
    target_id, auth_id = uuid.uuid4(), uuid.uuid4()
    auth = TargetAuthorization(
        id=auth_id,
        target_id=target_id,
        version=3,
        base_url="http://lab.test:8080/app/",
        environment=TargetEnvironment.LOCAL_LAB,
        in_scope_hosts=["lab.test"],
        allowed_ports=[8080],
        in_scope_path_prefixes=["/app"],
        excluded_paths=["/app/admin"],
        authorized_by="o",
        reference="r",
        valid_from=NOW - timedelta(hours=1),
        valid_until=NOW + timedelta(hours=1),
        acknowledged_by="a",
        acknowledged_at=NOW,
    )
    target = Target(
        id=target_id, project_id=uuid.uuid4(), name="t", current_authorization_id=auth_id
    )
    assessment = Assessment(
        id=uuid.uuid4(),
        target_id=target_id,
        authorization_id=auth_id,
        name="a",
        status=AssessmentStatus.IN_PROGRESS,
    )
    for key, value in overrides.items():
        obj, attr = key.split("__")
        setattr({"auth": auth, "target": target, "assessment": assessment}[obj], attr, value)
    return assessment, target, auth


def test_grant_comes_from_the_authorization_record() -> None:
    assessment, target, auth = rows()
    grant = build_scan_grant(assessment, target, auth, NOW)
    assert grant.target_id == target.id
    assert grant.assessment_id == assessment.id
    assert grant.authorization_id == auth.id
    assert grant.authorization_version == 3
    assert grant.assessment_status == "in_progress"
    assert (grant.valid_from, grant.valid_until) == (auth.valid_from, auth.valid_until)
    assert grant.scope.base_url == "http://lab.test:8080/app/"
    assert grant.scope.environment == "local_lab"
    assert grant.scope.in_scope_hosts == ("lab.test",)
    assert grant.scope.allowed_ports == (8080,)
    assert grant.scope.in_scope_path_prefixes == ("/app",)
    assert grant.scope.excluded_paths == ("/app/admin",)


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"assessment__status": AssessmentStatus.PLANNED}, "assessment_not_in_progress"),
        ({"assessment__status": AssessmentStatus.COMPLETED}, "assessment_not_in_progress"),
        ({"assessment__status": AssessmentStatus.CANCELLED}, "assessment_not_in_progress"),
        ({"target__current_authorization_id": uuid.uuid4()}, "authorization_superseded"),
        ({"assessment__authorization_id": uuid.uuid4()}, "authorization_superseded"),
        ({"auth__valid_until": NOW}, "authorization_not_active"),
        ({"auth__valid_from": NOW + timedelta(seconds=1)}, "authorization_not_active"),
        ({"auth__environment": TargetEnvironment.AUTHORIZED_EXTERNAL}, "environment_not_supported"),
        ({"auth__target_id": uuid.uuid4()}, "inconsistent_state"),
        # Rules only the scanner applies are enforced through its own check.
        ({"auth__base_url": "http://lab.test:8080/app/%61dmin/"}, "grant_invalid_scope"),
        (
            {
                "auth__in_scope_hosts": ["2002:a00:1::1"],
                "auth__base_url": "http://[2002:a00:1::1]:8080/app/",
            },
            "grant_invalid_scope",
        ),
    ],
)
def test_refusals(overrides: dict[str, Any], reason: str) -> None:
    assessment, target, auth = rows(**overrides)
    with pytest.raises(ScanNotAllowedError) as exc:
        build_scan_grant(assessment, target, auth, NOW)
    assert exc.value.reason == reason


def test_snapshot_is_json_ready() -> None:
    import json

    assessment, target, auth = rows()
    snapshot = grant_snapshot(build_scan_grant(assessment, target, auth, NOW))
    assert json.loads(json.dumps(snapshot)) == snapshot
    assert snapshot["scope"]["in_scope_hosts"] == ["lab.test"]


def test_config_only_honours_the_tls_flag() -> None:
    record = scan_config_record(allow_untrusted_tls=True)
    assert discovery_config(record).verify_tls is False
    assert discovery_config(scan_config_record(allow_untrusted_tls=False)).verify_tls is True
    tampered = {**record, "limits": {"max_requests": 10**6}, "allow_untrusted_tls": "yes"}
    config = discovery_config(tampered)
    assert config.limits == ScanLimits()
    assert config.verify_tls is True  # only a real boolean true disables verification
