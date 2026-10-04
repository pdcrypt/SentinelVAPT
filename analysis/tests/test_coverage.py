import importlib
import random
from dataclasses import replace

import pytest
from sentinel_analysis import analyze
from sentinel_analysis.coverage import COVERAGE_FUNCTIONS, coverage
from sentinel_analysis.observations import REDACTED, ScanObservations
from sentinel_analysis.rules import REGISTRY
from sentinel_analysis.rules.base import Rule

from tests.builders import SECURE_HEADERS, Page, build, cookie, tls_event

H = "http://127.0.0.1:8080"
S = "https://127.0.0.1:8443"


def keys_for(observations: ScanObservations, rule_id: str) -> set[tuple[str, str]]:
    return {(k[1], k[2]) for k in coverage(observations).keys if k[0] == rule_id}


def test_every_rule_version_has_a_coverage_function() -> None:
    """A rule whose version changes needs a coverage function written for the
    new version; until then its absences are not comparable (never FIXED)."""
    for rule in REGISTRY:
        assert rule.meta.id in COVERAGE_FUNCTIONS, rule.meta.id
        assert COVERAGE_FUNCTIONS[rule.meta.id][0] == rule.meta.version, rule.meta.id
    assert set(COVERAGE_FUNCTIONS) == {r.meta.id for r in REGISTRY}


def test_a_rule_version_without_coverage_is_uncovered() -> None:
    obs = build([Page(f"{H}/")])
    bumped = [
        Rule(replace(r.meta, version=r.meta.version + 1), r.evaluate)
        if r.meta.id == "SV-HDR-002"
        else r
        for r in REGISTRY
    ]
    result = coverage(obs, bumped)
    assert "SV-HDR-002" not in result.rules
    assert not any(k[0] == "SV-HDR-002" for k in result.keys)
    assert result.rules["SV-HDR-003"] == 1


def _random_observations(seed: int) -> ScanObservations:
    rng = random.Random(seed)  # noqa: S311  # test input generation, not cryptographic
    origins = [H, S, "http://lab.test:80", "https://lab.test:443"]
    header_pool = [
        ("Server", "nginx/1.25"),
        ("Server", "nginx"),
        ("X-Powered-By", "PHP/8.2.1"),
        ("X-Powered-By", REDACTED),
        ("Content-Security-Policy", "default-src 'self'"),
        ("Content-Security-Policy", "frame-ancestors 'none'"),
        ("Content-Security-Policy", REDACTED),
        ("X-Frame-Options", "DENY"),
        ("X-Frame-Options", "ALLOWALL"),
        ("X-Frame-Options", REDACTED),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Content-Type-Options", REDACTED),
        ("Strict-Transport-Security", "max-age=0"),
        ("Strict-Transport-Security", "max-age=31536000"),
        ("Strict-Transport-Security", REDACTED),
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Origin", REDACTED),
        ("Allow", "GET, PUT, DELETE"),
        ("Allow", "GET, HEAD"),
    ]
    bodies = ["", "hello", "Traceback (most recent call last):", "<title>Index of /x</title>"]
    names = ["sessionid", "theme", "auth_token", "PHPSESSID", "pref"]
    pages = []
    for i in range(rng.randint(1, 12)):
        origin = rng.choice(origins)
        cookies = [
            cookie(
                rng.choice(names),
                secure=rng.random() < 0.5,
                http_only=rng.random() < 0.5,
                same_site=rng.choice([None, "Lax"]),
            )
            for _ in range(rng.randint(0, 2))
        ]
        pages.append(
            Page(
                f"{origin}/p{i}/",
                method=rng.choice(["GET", "GET", "GET", "OPTIONS"]),
                status=rng.choice([200, 200, 204, 301, 404, 500]),
                headers=rng.sample(header_pool, rng.randint(0, 6)),
                body=rng.choice(bodies),
                title=rng.choice([None, "Index of /files", "Home"]),
                html=rng.random() < 0.7,
                cookies=cookies,
            )
        )
    events = [tls_event(f"{S}/x")] if rng.random() < 0.3 else []
    return build(pages, events=events, allow_untrusted_tls=rng.random() < 0.2)


@pytest.mark.parametrize("seed", range(300))
def test_every_match_subject_is_within_its_rules_coverage(seed: int) -> None:
    observations = _random_observations(seed)
    result = analyze(observations)
    cov = coverage(observations)
    assert result.rule_errors == ()
    for candidate in result.candidates:
        key = (candidate.rule_id, candidate.subject_key, candidate.discriminator)
        assert key in cov.keys, key


def test_trn_002_coverage_requires_a_verified_https_response() -> None:
    verified = build([Page(f"{S}/")])
    assert keys_for(verified, "SV-TRN-002") == {(S, "")}
    assert coverage(verified).keys[("SV-TRN-002", S, "")]  # backed by evidence
    # A recorded certificate failure was examined (and is reported by the rule),
    # with no response evidence; other TLS errors were not examined.
    failed = build([], events=[tls_event(f"{S}/")])
    assert coverage(failed).keys[("SV-TRN-002", S, "")] == ()
    other = build([], events=[tls_event(f"{S}/", reason="WRONG_VERSION_NUMBER")])
    assert keys_for(other, "SV-TRN-002") == set()
    untrusted = build([Page(f"{S}/")], allow_untrusted_tls=True)
    assert keys_for(untrusted, "SV-TRN-002") == set()


def test_redacted_headers_do_not_count_as_examined() -> None:
    obs = build([Page(f"{H}/", headers=[("Content-Security-Policy", REDACTED)])])
    assert keys_for(obs, "SV-HDR-002") == set()
    assert keys_for(obs, "SV-HDR-003") == set()
    assert keys_for(obs, "SV-HDR-004") == {(H, "")}
    obs = build([Page(f"{H}/", headers=[("Server", REDACTED)])])
    assert ("SV-INF-001", H, "server") not in {(k[0], k[1], k[2]) for k in coverage(obs).keys}
    assert keys_for(obs, "SV-INF-001") >= {(H, "x-powered-by")}


def test_rules_are_not_covered_without_applicable_input() -> None:
    json_only = build([Page(f"{H}/api", html=False)])
    assert keys_for(json_only, "SV-HDR-002") == set()
    assert keys_for(json_only, "SV-HDR-004") == {(H, "")}
    redirect = build([Page(f"{H}/", status=301)])
    assert keys_for(redirect, "SV-HDR-004") == set()
    assert keys_for(redirect, "SV-INF-003") == set()
    assert keys_for(redirect, "SV-HDR-001") == set()  # no HTTPS response
    no_cookies = build([Page(f"{S}/", headers=SECURE_HEADERS)])
    assert keys_for(no_cookies, "SV-CKE-003") == set()
    get_only = build([Page(f"{H}/x")])
    assert keys_for(get_only, "SV-MTH-001") == set()
    empty_body = build([Page(f"{H}/x", body="")])
    assert keys_for(empty_body, "SV-INF-002") == set()


def test_cookie_coverage_is_per_origin_and_name() -> None:
    obs = build(
        [
            Page(f"{S}/", cookies=[cookie("sessionid", secure=True, http_only=True)]),
            Page(f"{H}/", cookies=[cookie("theme")]),
        ]
    )
    assert keys_for(obs, "SV-CKE-001") == {(S, "sessionid")}  # session-like names only
    assert keys_for(obs, "SV-CKE-002") == {(S, "sessionid")}  # HTTPS only
    assert keys_for(obs, "SV-CKE-003") == {(S, "sessionid"), (H, "theme")}


def test_endpoint_coverage_uses_the_endpoint_subject_key() -> None:
    obs = build(
        [
            Page(f"{H}/error", status=500, body="Traceback (most recent call last):"),
            Page(f"{H}/", method="OPTIONS", headers=[("Allow", "GET")]),
        ]
    )
    # The OPTIONS response has no body excerpt, so INF-002 did not examine it.
    assert keys_for(obs, "SV-INF-002") == {(f"GET {H}/error", "")}
    assert keys_for(obs, "SV-MTH-001") == {(f"OPTIONS {H}/", "")}


def test_coverage_evidence_belongs_to_the_scan_and_is_sorted() -> None:
    obs = _random_observations(7)
    ids = {r.evidence_id for r in obs.responses}
    for evidence in coverage(obs).keys.values():
        assert list(evidence) == sorted(set(evidence))
        assert set(evidence) <= ids


@pytest.mark.parametrize("seed", range(20))
def test_coverage_does_not_depend_on_input_order(seed: int) -> None:
    obs = _random_observations(seed)
    rng = random.Random(seed)  # noqa: S311  # test shuffling
    shuffled = replace(
        obs,
        endpoints=tuple(rng.sample(obs.endpoints, len(obs.endpoints))),
        responses=tuple(rng.sample(obs.responses, len(obs.responses))),
        cookies=tuple(rng.sample(obs.cookies, len(obs.cookies))),
    )
    assert coverage(obs) == coverage(shuffled)


def test_a_failing_coverage_function_leaves_only_its_rule_uncovered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The package exports the coverage() function under the module's name.
    module = importlib.import_module("sentinel_analysis.coverage")

    def boom(ctx: object) -> list[tuple[str, str, tuple[str, ...]]]:
        raise RuntimeError("boom")

    monkeypatch.setitem(module.COVERAGE_FUNCTIONS, "SV-HDR-002", (1, boom))
    result = coverage(build([Page(f"{H}/")]))
    assert "SV-HDR-002" not in result.rules
    assert "SV-HDR-003" in result.rules
