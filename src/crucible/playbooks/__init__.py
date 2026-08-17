"""Playbook registry: map a vulnerability class to its module.

Each module exposes two functions:

    build_steps(finding, target_base) -> list[Step]     # how to re-test it
    oracle(finding, results)          -> OracleOutcome   # did it actually work

Add a new class by writing a module and registering it here -- nothing else in
the pipeline changes.
"""

from __future__ import annotations

from ..models import VulnClass
from . import acl_bypass, cors, file_disclosure, open_redirect, sqli, xss

PLAYBOOKS = {
    VulnClass.SQLI: sqli,
    VulnClass.OPEN_REDIRECT: open_redirect,
    VulnClass.FILE_DISCLOSURE: file_disclosure,
    VulnClass.ACL_BYPASS: acl_bypass,
    VulnClass.CORS: cors,
    VulnClass.XSS: xss,
}


def get_playbook(vuln_class: VulnClass):
    """Return the playbook module for a class, or None if we have none."""
    return PLAYBOOKS.get(vuln_class)
