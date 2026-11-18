"""Platform presets: sensible defaults for common ModSecurity deployments.

A preset only fills the target form; every value can be changed afterwards.
Paths vary between distributions and installation methods, so the UI always
shows them for review before saving.

``include_snippet`` is what the administrator adds once to the WAF
configuration so that the files Tamiz writes are loaded at the right point:
runtime exclusions before the CRS rules, configure-time exclusions after.
"""
from __future__ import annotations

PRESETS: dict[str, dict] = {
    "nginx": {
        "label": "nginx + libmodsecurity (v3)",
        "engine": "v3",
        "transport": "ssh",
        "commands": {
            "validate": "nginx -t",
            "reload": "nginx -s reload",
            "discover": "nginx -T",
            "sudo_mode": "commands",
        },
        "layout": {
            "mode": "per_group",
            "before": "/etc/nginx/modsec/tamiz/before/{block}-{group}.conf",
            "after": "/etc/nginx/modsec/tamiz/after/{block}-{group}.conf",
            "mkdirs": True,
        },
        "logs": {"audit_log": "/var/log/modsec_audit.log", "error_log": "/var/log/nginx/error.log"},
        "include_base": "file",
        "include_snippet": (
            "# In the file loaded by modsecurity_rules_file (often /etc/nginx/modsec/main.conf):\n"
            "Include /etc/nginx/modsec/modsecurity.conf\n"
            "Include /etc/nginx/modsec/tamiz/before/*.conf     # <- add, before the CRS\n"
            "Include /etc/nginx/modsec/coreruleset/crs-setup.conf\n"
            "Include /etc/nginx/modsec/coreruleset/rules/*.conf\n"
            "Include /etc/nginx/modsec/tamiz/after/*.conf      # <- add, after the CRS\n"
        ),
    },
    "apache": {
        "label": "Apache httpd + mod_security2",
        "engine": "v2",
        "transport": "ssh",
        "commands": {
            "validate": "apachectl -t",
            "reload": "apachectl graceful",
            "discover": "apachectl -t -D DUMP_INCLUDES",
            "sudo_mode": "commands",
        },
        "layout": {
            "mode": "per_group",
            "before": "/etc/modsecurity/tamiz/before/{block}-{group}.conf",
            "after": "/etc/modsecurity/tamiz/after/{block}-{group}.conf",
            "mkdirs": True,
        },
        "logs": {"audit_log": "/var/log/apache2/modsec_audit.log", "error_log": "/var/log/apache2/error.log"},
        "include_base": "server_root",
        "include_snippet": (
            "# In the file that loads the CRS (Debian: /etc/apache2/mods-enabled/security2.conf;\n"
            "# RHEL: /etc/httpd/conf.d/mod_security.conf):\n"
            "IncludeOptional /etc/modsecurity/tamiz/before/*.conf     # <- add, before the CRS\n"
            "IncludeOptional /usr/share/modsecurity-crs/crs-setup.conf\n"
            "IncludeOptional /usr/share/modsecurity-crs/rules/*.conf\n"
            "IncludeOptional /etc/modsecurity/tamiz/after/*.conf      # <- add, after the CRS\n"
        ),
    },
    "crs-docker": {
        "label": "OWASP CRS container image (owasp/modsecurity-crs)",
        "engine": "v3",
        "transport": "docker",
        "commands": {
            "validate": "nginx -t",
            "reload": "nginx -s reload",
            "discover": "",
            "sudo_mode": "none",
        },
        "conn": {"container": "waf", "exec_user": "root"},
        "layout": {
            # The image already includes plugins/*-before.conf before the CRS
            # rules and plugins/*-after.conf after them, so Tamiz's files can
            # live there without editing the image configuration.
            "mode": "per_group",
            "before": "/etc/modsecurity.d/owasp-crs/plugins/tamiz-{block}-{group}-before.conf",
            "after": "/etc/modsecurity.d/owasp-crs/plugins/tamiz-{block}-{group}-after.conf",
            "mkdirs": False,
        },
        "entry_files": ["/etc/modsecurity.d/setup.conf"],
        "logs": {"audit_log": "@stdout", "error_log": ""},
        "include_base": "file",
        "include_snippet": (
            "# Nothing to add: the image loads owasp-crs/plugins/*-before.conf and\n"
            "# *-after.conf around the CRS rules. Mount that directory as a volume so\n"
            "# the files survive when the container is recreated, e.g.:\n"
            "#   volumes:\n"
            "#     - ./tamiz-plugins:/etc/modsecurity.d/owasp-crs/plugins\n"
        ),
    },
    "coraza-caddy": {
        "label": "Caddy + Coraza",
        "engine": "coraza",
        "transport": "ssh",
        "commands": {
            "validate": "caddy validate --config /etc/caddy/Caddyfile",
            "reload": "caddy reload --config /etc/caddy/Caddyfile",
            "discover": "",
            "sudo_mode": "commands",
        },
        "layout": {
            "mode": "per_group",
            "before": "/etc/caddy/coraza/tamiz/before/{block}-{group}.conf",
            "after": "/etc/caddy/coraza/tamiz/after/{block}-{group}.conf",
            "mkdirs": True,
        },
        "logs": {"audit_log": "/var/log/coraza/audit.log", "error_log": ""},
        "include_base": "file",
        "include_snippet": (
            "# In the Coraza directives of your Caddyfile:\n"
            "Include @coraza.conf-recommended\n"
            "Include /etc/caddy/coraza/tamiz/before/*.conf\n"
            "Include @crs-setup.conf.example\n"
            "Include @owasp_crs/*.conf\n"
            "Include /etc/caddy/coraza/tamiz/after/*.conf\n"
        ),
    },
    "shared-file": {
        "label": "Existing exclusion files (REQUEST-900 / RESPONSE-999)",
        "engine": "v3",
        "transport": "ssh",
        "commands": {
            "validate": "nginx -t",
            "reload": "nginx -s reload",
            "discover": "nginx -T",
            "sudo_mode": "all",
        },
        "layout": {
            # Tamiz edits only its own marked blocks inside these files.
            "mode": "shared",
            "before": "/etc/nginx/modsec/coreruleset/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf",
            "after": "/etc/nginx/modsec/coreruleset/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf",
            "mkdirs": False,
        },
        "logs": {"audit_log": "/var/log/modsec_audit.log", "error_log": "/var/log/nginx/error.log"},
        "include_base": "file",
        "include_snippet": (
            "# Nothing to add if the CRS rules are loaded with rules/*.conf: the CRS\n"
            "# already loads REQUEST-900-... before its rules and RESPONSE-999-... after.\n"
        ),
    },
    "custom": {
        "label": "Custom",
        "engine": "v3",
        "transport": "ssh",
        "commands": {"validate": "", "reload": "", "discover": "", "sudo_mode": "none"},
        "layout": {"mode": "per_group", "before": "", "after": "", "mkdirs": False},
        "logs": {"audit_log": "", "error_log": ""},
        "include_base": "file",
        "include_snippet": "",
    },
}


def public() -> list[dict]:
    return [{"key": k, **v} for k, v in PRESETS.items()]


def get(key: str) -> dict:
    return PRESETS.get(key) or PRESETS["custom"]
