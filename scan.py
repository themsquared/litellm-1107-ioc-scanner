#!/usr/bin/env python3
"""
IOC scanner for the LiteLLM 1.107.0 PyPI/Docker supply-chain compromise
(2026-10-21). Stdlib only, no network calls, no dependencies.

Detects the documented filesystem and process markers from the public
incident writeups (StepSecurity, Wiz, Chainguard, SafeDep) without
reproducing or bundling any of the actual malicious code. See README.md
for sources and the full IOC list.

Usage:
    python3 scan.py                        # scan this interpreter's site-packages + /tmp
    python3 scan.py --path /path/to/venv/lib/python3.x/site-packages
    python3 scan.py --path a --path b      # scan multiple extra paths
"""
import argparse
import glob
import importlib.metadata
import os
import site
import sys
import sysconfig

BAD_VERSION = "1.107.0"
SAFE_PIN = "1.106.2"

PLANTED_FILES = ["cook.pth", "cook.py"]
SUSPECT_FILES = ["sitecustomize.py"]  # legitimate uses exist; flagged only as corroborating evidence
TMP_LOCK = "remote_code_loader.lock"
TMP_MARKER_GLOBS = [".pc_once_*", ".pc_sq_*", ".pc_e_*"]
ENV_MARKER = "PRIVCOLLECT_ACTIVE"


def candidate_site_packages(extra_paths):
    paths = set()
    try:
        paths.add(sysconfig.get_paths()["purelib"])
    except Exception:
        pass
    for p in site.getsitepackages() if hasattr(site, "getsitepackages") else []:
        paths.add(p)
    user_site = site.getusersitepackages() if hasattr(site, "getusersitepackages") else None
    if user_site:
        paths.add(user_site)
    for p in extra_paths:
        paths.add(os.path.abspath(p))
    return sorted(p for p in paths if p and os.path.isdir(p))


def scan_site_packages(path):
    findings = []
    for fname in PLANTED_FILES:
        fpath = os.path.join(path, fname)
        if os.path.isfile(fpath):
            findings.append(("CRITICAL", f"planted file present: {fpath}"))
    for fname in SUSPECT_FILES:
        fpath = os.path.join(path, fname)
        if os.path.isfile(fpath):
            findings.append(("WARN", f"sitecustomize.py present (corroborating, not conclusive): {fpath}"))
    return findings


def scan_tmp():
    findings = []
    lock = os.path.join("/tmp", TMP_LOCK)
    if os.path.exists(lock):
        findings.append(("CRITICAL", f"dead-drop poll lock present: {lock}"))
    for pattern in TMP_MARKER_GLOBS:
        for match in glob.glob(os.path.join("/tmp", pattern)):
            findings.append(("CRITICAL", f"exfiltration/stage marker present: {match}"))
    return findings


def scan_env():
    findings = []
    if os.environ.get(ENV_MARKER):
        findings.append(("CRITICAL", f"environment variable set: {ENV_MARKER}={os.environ[ENV_MARKER]}"))
    return findings


def scan_litellm_version():
    try:
        version = importlib.metadata.version("litellm")
    except importlib.metadata.PackageNotFoundError:
        return []
    if version == BAD_VERSION:
        return [("CRITICAL", f"litellm {version} installed (the compromised release). Pin to {SAFE_PIN}.")]
    return [("INFO", f"litellm {version} installed (not the flagged {BAD_VERSION} release)")]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--path", action="append", default=[], help="extra site-packages dir to scan (repeatable)")
    args = parser.parse_args()

    all_findings = []
    sp_dirs = candidate_site_packages(args.path)
    print(f"Scanning {len(sp_dirs)} site-packages director{'y' if len(sp_dirs)==1 else 'ies'}:")
    for d in sp_dirs:
        print(f"  - {d}")
        all_findings.extend((sev, msg) for sev, msg in scan_site_packages(d))

    all_findings.extend(scan_tmp())
    all_findings.extend(scan_env())
    all_findings.extend(scan_litellm_version())

    print()
    if not all_findings:
        print("CLEAN: no known IOCs from the 2026-10-21 litellm 1.107.0 compromise found.")
        return 0

    critical = [f for f in all_findings if f[0] == "CRITICAL"]
    warn = [f for f in all_findings if f[0] == "WARN"]
    info = [f for f in all_findings if f[0] == "INFO"]

    for sev, msg in critical + warn + info:
        print(f"[{sev}] {msg}")

    if critical:
        print()
        print("COMPROMISED: treat this environment as breached. Do not clean in place.")
        print(f"  1. Kill any process holding /tmp/{TMP_LOCK} before touching pip.")
        print(f"  2. Rebuild the environment/image from scratch. Pin litellm=={SAFE_PIN} or that image by digest.")
        print("  3. Rotate every credential reachable from this host: cloud keys, SSH/GPG keys,")
        print("     registry tokens, CI secrets, DATABASE_URL, and any LiteLLM proxy virtual keys.")
        print("  4. Check egress logs for requests to litellm.dev and any path ending in /codepy.")
        return 2
    if warn:
        print()
        print("SUSPICIOUS: corroborating evidence only. Investigate before ruling this out.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
