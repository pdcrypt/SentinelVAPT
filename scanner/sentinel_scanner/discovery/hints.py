"""Technology hints: what a response says about the software behind it.

Descriptive only. A hint records where the information came from; it is not a
version claim and not a finding (detection rules are a later phase).
"""

from collections.abc import Sequence

from sentinel_scanner.models import CookieObservation, TechHint

MAX_HINT_LENGTH = 200

_HINT_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-varnish",
    "via",
)

_COOKIE_TECHNOLOGIES = {
    "phpsessid": "PHP",
    "jsessionid": "Java servlet container",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "connect.sid": "Express (Node.js)",
    "rack.session": "Ruby / Rack",
    "csrftoken": "Django (likely)",
    "django_language": "Django",
}


def collect_hints(
    headers: Sequence[tuple[str, str]],
    cookies: Sequence[CookieObservation],
    generator: str | None,
) -> list[TechHint]:
    hints: list[TechHint] = []
    for name, value in headers:
        lowered = name.lower()
        if lowered in _HINT_HEADERS and value.strip():
            hints.append(TechHint(f"header:{lowered}", value.strip()[:MAX_HINT_LENGTH]))
    if generator:
        hints.append(TechHint("meta:generator", generator.strip()[:MAX_HINT_LENGTH]))
    for cookie in cookies:
        technology = _COOKIE_TECHNOLOGIES.get(cookie.name.lower())
        if technology:
            hints.append(TechHint(f"cookie:{cookie.name}", technology))
    return hints
