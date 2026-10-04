# Taxonomy mappings

Findings reference three external taxonomies. Every identifier a rule uses is
listed in `analysis/sentinel_analysis/taxonomy.py`, and tests reject any other.
The per-rule mappings are in the generated [rule catalog](rules.md).

## Sources and editions

| Taxonomy | Edition | Source | Verified |
| -------- | ------- | ------ | -------- |
| OWASP Top 10 | 2025 | <https://top10.owasp.org/2025/> | 2026-10-04 |
| OWASP Web Security Testing Guide | v4.2 | <https://wstg.owasp.org/v4.2/> | 2026-10-04 |
| MITRE CWE | 4.20 | <https://cwe.mitre.org/> | 2026-10-04 |

Each identifier was checked on its own primary page (the individual WSTG test
page, the CWE definition page and the Top 10 category page), not on index
pages or secondary sources.

## Mapping policy

1. **WSTG test or CWE:** only if the source page covers the condition the rule
   observes. A related-sounding identifier is not enough.
2. **OWASP Top 10:2025 category:** only if one of the rule's CWEs is in that
   category's official "List of Mapped CWEs". A rule without a CWE has no Top 10
   category.
3. **Anything that cannot be verified stays empty.** Identifiers are never
   inferred from similar ones. An empty mapping is a correct answer, not a gap
   to fill.
4. **A mapping change changes the rule's metadata**, so it needs a new rule
   version (enforced by `rule_metadata.lock.json` and its test).

## Identifiers in use

**OWASP Top 10:2025:**

- A02:2025 Security Misconfiguration (mapped CWEs used: 614, 1004);
- A04:2025 Cryptographic Failures (319);
- A10:2025 Mishandling of Exceptional Conditions (209).

**WSTG v4.2:**

- INFO-02 Fingerprint Web Server;
- CONF-06 Test HTTP Methods;
- CONF-07 Test HTTP Strict Transport Security;
- SESS-02 Testing for Cookies Attributes;
- ERRH-01 Testing for Improper Error Handling;
- CRYP-01 Testing for Weak Transport Layer Security;
- CRYP-03 Testing for Sensitive Information Sent via Unencrypted Channels;
- CLNT-07 Testing Cross Origin Resource Sharing;
- CLNT-09 Testing for Clickjacking.

**CWE 4.20:** 209, 319, 497, 548, 614, 1004, 1021, 1275.

## Deliberate exclusions

| Identifier | Why it is not used |
| ---------- | ------------------ |
| CWE-693 Protection Mechanism Failure | MITRE marks it DISCOURAGED for vulnerability mapping (Pillar). Missing-header rules therefore have no CWE. |
| CWE-942 | Its page covers Flash/Silverlight cross-domain policy files, not CORS response headers. SV-COR-001 therefore has no CWE (and no Top 10 category). |
| WSTG-ERRH-02 | Merged into WSTG-ERRH-01 in v4.2. |
| A Content-Security-Policy WSTG test | WSTG v4.2 has no dedicated CSP test, so SV-HDR-002 has no WSTG mapping. |

## Updating

1. Re-read the primary pages.
2. Update `taxonomy.py` and this file, including the verification date.
3. Bump the version of every rule whose mappings change.
4. Run `python -m sentinel_analysis.catalog lock` and
   `python -m sentinel_analysis.catalog docs > ../docs/rules.md`.
