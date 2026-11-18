"""Static knowledge about ModSecurity, the OWASP CRS and rule ID ranges."""
from __future__ import annotations

# Rule ID reservations published by the OWASP ModSecurity project
# (https://waf.owasp.org/rule-id-ranges). 1-99,999 is for local use and is
# where Tamiz allocates the IDs of the rules it generates.
LOCAL_RANGE = (1, 99_999)

RESERVED_RANGES: list[tuple[int, int, str]] = [
    (100_000, 199_999, "Oracle"),
    (200_000, 299_999, "Comodo"),
    (300_000, 399_999, "gotroot.com"),
    (420_000, 429_999, "ScallyWhack"),
    (430_000, 439_999, "Flameeye"),
    (600_000, 699_999, "Akamai"),
    (700_000, 799_999, "Ivan Ristic"),
    (900_000, 999_999, "OWASP CRS"),
    (1_000_000, 1_009_999, "Red Hat Security Team"),
    (2_000_000, 2_999_999, "Trustwave SpiderLabs"),
    (3_000_000, 3_999_999, "Akamai"),
    (4_000_000, 4_099_999, "AviNetworks"),
    (4_100_000, 4_199_999, "Fastly"),
    (8_000_000, 8_999_999, "Yandex"),
    (9_000_000, 9_999_999, "OWASP CRS"),
    (99_000_000, 99_099_999, "Microsoft"),
]


def reserved_owner(rule_id: int) -> str | None:
    """Who the ID range belongs to, or None if it is free or local."""
    for lo, hi, owner in RESERVED_RANGES:
        if lo <= rule_id <= hi:
            return owner
    return None


# CRS files are numbered by category; a rule's ID is 9<file>xxx.
CRS_CATEGORIES: dict[int, str] = {
    901: "initialization",
    905: "common-exceptions",
    911: "method-enforcement",
    913: "scanner-detection",
    920: "protocol-enforcement",
    921: "protocol-attack",
    922: "multipart-attack",
    930: "lfi",
    931: "rfi",
    932: "rce",
    933: "php",
    934: "generic",
    941: "xss",
    942: "sqli",
    943: "session-fixation",
    944: "java",
    949: "inbound-blocking",
    950: "data-leakages",
    951: "sql-leakage",
    952: "java-leakage",
    953: "php-leakage",
    954: "iis-leakage",
    955: "web-shells",
    956: "ruby-leakage",
    959: "outbound-blocking",
    980: "correlation",
}


def crs_category(rule_id: int) -> str | None:
    if 900_000 <= rule_id <= 999_999:
        return CRS_CATEGORIES.get(rule_id // 1000)
    return None


def is_scoring_rule(rule_id: int) -> bool:
    """Rules that evaluate the anomaly score instead of detecting attacks.

    Excluding them disables blocking altogether, so the analyzer never
    suggests them and the linter warns when someone targets them.
    """
    return rule_id // 1000 in (949, 959, 980)


# Rules known to run in phase 1. An exclusion that needs phase 2 (because it
# looks at the body) cannot remove them. Kept deliberately short: only rules
# whose phase is certain across CRS 3.x and 4.x.
PHASE1_RULES = {911100}

# Variables available in phase 1 (request headers). Anything else (ARGS,
# body variables) needs phase 2.
PHASE1_VARIABLES = {
    "REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_FILENAME", "REQUEST_BASENAME",
    "REQUEST_LINE", "REQUEST_METHOD", "REQUEST_PROTOCOL", "QUERY_STRING",
    "REMOTE_ADDR", "REMOTE_HOST", "REMOTE_PORT", "REMOTE_USER",
    "SERVER_NAME", "SERVER_PORT", "SERVER_ADDR", "REQUEST_HEADERS",
    "REQUEST_HEADERS_NAMES", "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES",
    "ARGS_GET", "ARGS_GET_NAMES", "TX", "ENV", "GEO", "UNIQUE_ID",
    "TIME", "TIME_DAY", "TIME_HOUR", "TIME_MIN", "TIME_MON", "TIME_SEC",
    "TIME_WDAY", "TIME_YEAR", "TIME_EPOCH", "AUTH_TYPE",
}

# Operators Tamiz can generate and recognise in exclusion conditions.
OPERATORS = [
    "beginsWith", "endsWith", "streq", "contains", "containsWord", "within",
    "rx", "pm", "ipMatch", "eq", "ge", "gt", "le", "lt", "strmatch",
]
OPERATORS_LOWER = {op.lower(): op for op in OPERATORS}

# Actions that only carry metadata; kept verbatim when importing a rule.
METADATA_ACTIONS = {"msg", "tag", "ver", "severity", "logdata", "rev", "maturity", "accuracy"}
LOG_ACTIONS = {"log", "nolog", "auditlog", "noauditlog"}

CTL_KINDS = {
    "ruleremovebyid": ("remove_rule", "id"),
    "ruleremovebytag": ("remove_rule", "tag"),
    "ruleremovetargetbyid": ("remove_target", "id"),
    "ruleremovetargetbytag": ("remove_target", "tag"),
    "ruleengine": ("engine_mode", None),
}

CTL_NAMES = {
    ("remove_rule", "id"): "ruleRemoveById",
    ("remove_rule", "tag"): "ruleRemoveByTag",
    ("remove_target", "id"): "ruleRemoveTargetById",
    ("remove_target", "tag"): "ruleRemoveTargetByTag",
}

ENGINE_MODES = ("DetectionOnly", "Off")

# Suggestions shown in the exclusion form.
COMMON_VARIABLES = [
    "REQUEST_FILENAME", "REQUEST_URI", "REQUEST_METHOD", "REQUEST_HEADERS:Host",
    "REMOTE_ADDR", "REQUEST_BASENAME", "QUERY_STRING",
    "REQUEST_HEADERS:User-Agent", "REQUEST_HEADERS:Content-Type", "ARGS:",
]


def variable_base(variable: str) -> str:
    """'REQUEST_HEADERS:Host' -> 'REQUEST_HEADERS'; '&ARGS' -> 'ARGS'."""
    v = variable.lstrip("!&")
    return v.split(":", 1)[0].upper()


def needs_phase2(variables: list[str]) -> bool:
    for full in variables:
        for part in full.split("|"):
            if variable_base(part) not in PHASE1_VARIABLES:
                return True
    return False
