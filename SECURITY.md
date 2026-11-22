# Security scope and checks

This is an educational scanner, not a replacement for endpoint protection. It
matches known hashes and limited heuristics; a clean result does not establish
that a file is safe. Incomplete scan scope is included in CLI, GUI and HTML
reports.

Quarantine tests exercise interrupted copies, flush failures, altered sources,
existing destinations, missing journals and orphaned payloads. Recovery retains
the payload until a destination has been durably written. Filesystem durability
and concurrent access depend on the operating system and filesystem; tests on
one platform do not establish behavior on the others.

The Security workflow audits runtime, development and packaging dependencies
with pip-audit, scans Python with CodeQL security-extended queries and scans Git
history with Gitleaks. Dependency findings fail the job without an allowlist.
Check the latest commit's Actions results before release; adding a workflow is
not evidence that its remote checks have passed.

A local Bandit review on 2026-11-06 found subprocess warnings for explicit argv
calls to platform schedulers/file managers (no shell), plus temporary-directory
warnings for the **read-only scan roots** in `targets.py`. Those roots do not
create temporary files. The subprocess helpers assume a trusted user environment,
including PATH. They must not be used as a privileged service accepting commands
from an untrusted caller. No global Bandit exclusions have been added.

Report suspected vulnerabilities privately through GitHub's security reporting
feature when available. Do not attach private files, credentials or real malware
to public issues; use harmless minimal reproductions.
