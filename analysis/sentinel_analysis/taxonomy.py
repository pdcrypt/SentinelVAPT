"""Controlled vocabularies for rule mappings, verified against primary sources.

Verified on 2026-10-04 by reading each primary page (see docs/taxonomy.md).
Only identifiers listed here may be used by rules; tests enforce it.

Mapping policy:
- A rule maps to a WSTG test or CWE only if the source page covers the rule's
  observation.
- A rule maps to an OWASP Top 10:2025 category only if one of its CWEs appears
  in that category's official "List of Mapped CWEs".
- Anything not verifiable is left empty. Nothing is inferred from similar ids.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class TaxonomyEntry:
    title: str
    source: str


# --- OWASP Top 10:2025 --------------------------------------------------------------
OWASP_TOP10_EDITION = "OWASP Top 10:2025"
OWASP_TOP10_SOURCE = "https://top10.owasp.org/2025/"

OWASP_TOP10_2025: dict[str, str] = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

# "List of Mapped CWEs" of the categories rules may use, copied from each
# category page.
OWASP_TOP10_2025_MAPPED_CWES: dict[str, frozenset[int]] = {
    # https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/
    "A02:2025": frozenset(
        {5, 11, 13, 15, 16, 260, 315, 489, 526, 547, 611, 614, 776, 942, 1004, 1174}
    ),
    # https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/
    "A04:2025": frozenset(
        {
            261,
            296,
            319,
            320,
            321,
            322,
            323,
            324,
            325,
            326,
            327,
            328,
            329,
            330,
            331,
            332,
            334,
            335,
            336,
            337,
            338,
            340,
            342,
            347,
            523,
            757,
            759,
            760,
            780,
            916,
            1240,
            1241,
        }
    ),
    # https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/
    "A10:2025": frozenset(
        {
            209,
            215,
            234,
            235,
            248,
            252,
            274,
            280,
            369,
            390,
            391,
            394,
            396,
            397,
            460,
            476,
            478,
            484,
            550,
            636,
            703,
            754,
            755,
            756,
        }
    ),
}

# --- OWASP Web Security Testing Guide v4.2 -------------------------------------------
WSTG_EDITION = "OWASP WSTG v4.2"
_WSTG = "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/"

WSTG_V42: dict[str, TaxonomyEntry] = {
    "WSTG-INFO-02": TaxonomyEntry(
        "Fingerprint Web Server", _WSTG + "01-Information_Gathering/02-Fingerprint_Web_Server"
    ),
    "WSTG-CONF-06": TaxonomyEntry(
        "Test HTTP Methods",
        _WSTG + "02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
    ),
    "WSTG-CONF-07": TaxonomyEntry(
        "Test HTTP Strict Transport Security",
        _WSTG
        + "02-Configuration_and_Deployment_Management_Testing/"
        + "07-Test_HTTP_Strict_Transport_Security",
    ),
    "WSTG-SESS-02": TaxonomyEntry(
        "Testing for Cookies Attributes",
        _WSTG + "06-Session_Management_Testing/02-Testing_for_Cookies_Attributes",
    ),
    "WSTG-ERRH-01": TaxonomyEntry(
        "Testing for Improper Error Handling",
        _WSTG + "08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling",
    ),
    "WSTG-CRYP-01": TaxonomyEntry(
        "Testing for Weak Transport Layer Security",
        _WSTG + "09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
    ),
    "WSTG-CRYP-03": TaxonomyEntry(
        "Testing for Sensitive Information Sent via Unencrypted Channels",
        _WSTG
        + "09-Testing_for_Weak_Cryptography/"
        + "03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels",
    ),
    "WSTG-CLNT-07": TaxonomyEntry(
        "Testing Cross Origin Resource Sharing",
        _WSTG + "11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
    ),
    "WSTG-CLNT-09": TaxonomyEntry(
        "Testing for Clickjacking", _WSTG + "11-Client-side_Testing/09-Testing_for_Clickjacking"
    ),
}

# --- MITRE CWE 4.20 --------------------------------------------------------------------
CWE_VERSION = "CWE 4.20"

CWE: dict[int, TaxonomyEntry] = {
    cwe_id: TaxonomyEntry(title, f"https://cwe.mitre.org/data/definitions/{cwe_id}.html")
    for cwe_id, title in {
        209: "Generation of Error Message Containing Sensitive Information",
        319: "Cleartext Transmission of Sensitive Information",
        497: "Exposure of Sensitive System Information to an Unauthorized Control Sphere",
        548: "Exposure of Information Through Directory Listing",
        614: "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        1004: "Sensitive Cookie Without 'HttpOnly' Flag",
        1021: "Improper Restriction of Rendered UI Layers or Frames",
        1275: "Sensitive Cookie with Improper SameSite Attribute",
    }.items()
}

# Deliberately not used, with the source's reason.
EXCLUDED_CWES: dict[int, str] = {
    693: "MITRE marks CWE-693 'Protection Mechanism Failure' DISCOURAGED for "
    "vulnerability mapping (Pillar-level).",
    942: "CWE-942 page content addresses Flash/Silverlight cross-domain policy "
    "files, not CORS response headers.",
}
EXCLUDED_WSTG: dict[str, str] = {
    "WSTG-ERRH-02": "Merged into WSTG-ERRH-01 in v4.2.",
}
