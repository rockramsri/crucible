"""ZAP JSON adapter.

Reads an OWASP ZAP JSON report and emits one `Finding` per alert instance,
keeping only the target site (ZAP reports also include external domains the
browser touched, e.g. GitHub CDNs -- we drop those).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..models import Finding, Target, VulnClass

# ZAP plugin id -> our vulnerability class. Anything not here becomes UNKNOWN
# (still counted, just not validated). Extend freely.
PLUGIN_MAP: dict[str, VulnClass] = {
    # SQL injection family
    "40018": VulnClass.SQLI,   # SQL Injection
    "40019": VulnClass.SQLI,   # SQLi - MySQL
    "40020": VulnClass.SQLI,   # SQLi - Hypersonic
    "40021": VulnClass.SQLI,   # SQLi - Oracle
    "40022": VulnClass.SQLI,   # SQLi - PostgreSQL
    "40024": VulnClass.SQLI,   # SQLi - SQLite
    # Cross-site scripting family
    "40012": VulnClass.XSS,    # Reflected XSS
    "40014": VulnClass.XSS,    # Persistent XSS
    "40016": VulnClass.XSS,    # Persistent XSS (prime)
    "40017": VulnClass.XSS,    # Persistent XSS (spider)
    "40026": VulnClass.XSS,    # DOM XSS
    # Redirects
    "20019": VulnClass.OPEN_REDIRECT,   # External Redirect
    "10028": VulnClass.OPEN_REDIRECT,   # Off-site redirect (passive; may lack a param)
    # File / path disclosure
    "10095": VulnClass.FILE_DISCLOSURE,  # Backup File Disclosure
    # Access-control bypass
    "40038": VulnClass.ACL_BYPASS,       # Bypassing 403
    # CORS
    "40040": VulnClass.CORS,             # CORS Misconfiguration
}

# ZAP riskcode -> human severity.
_RISK = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High"}
# ZAP confidence -> human confidence.
_CONF = {"0": "False Positive", "1": "Low", "2": "Medium", "3": "High", "4": "Confirmed"}


def _host(uri: str) -> str:
    return urlsplit(uri).netloc


class ZapAdapter:
    """Adapter for OWASP ZAP JSON reports."""

    source_name = "zap"

    def parse(self, raw_report: dict, target_base: str) -> list[Finding]:
        target_host = _host(target_base)
        findings: list[Finding] = []

        for site in raw_report.get("site", []):
            # Keep only the site we are actually testing; skip external domains.
            if target_host and _host(site.get("@name", "")) != target_host:
                continue

            for alert in site.get("alerts", []):
                plugin_id = str(alert.get("pluginid", ""))
                vuln_class = PLUGIN_MAP.get(plugin_id, VulnClass.UNKNOWN)
                severity = _RISK.get(str(alert.get("riskcode", "")), "Medium")
                confidence = _CONF.get(str(alert.get("confidence", "")), "Medium")
                cwe = alert.get("cweid")
                cwe = int(cwe) if str(cwe).isdigit() else None
                alert_ref = str(alert.get("alertRef") or plugin_id)

                for idx, inst in enumerate(alert.get("instances", [])):
                    findings.append(
                        Finding(
                            id=f"{alert_ref}:{idx}",
                            source=self.source_name,
                            vuln_class=vuln_class,
                            name=alert.get("name", plugin_id),
                            cwe=cwe,
                            severity=severity,
                            scanner_confidence=confidence,
                            target=Target(
                                uri=inst.get("uri", ""),
                                method=(inst.get("method") or "GET").upper(),
                                param=inst.get("param") or None,
                            ),
                            signal={
                                "attack": inst.get("attack", ""),
                                "evidence": inst.get("evidence", ""),
                            },
                            raw={
                                "pluginid": plugin_id,
                                "alertRef": alert.get("alertRef"),
                                "otherinfo": inst.get("otherinfo", ""),
                            },
                        )
                    )
        return findings
