# litellm-1107-ioc-scanner

> 📖 **Read the write-up:** [LiteLLM 1.107.0: Why Image Signing Didn't Stop the Backdoor](https://webofmike.com/litellm-pypi-backdoor/)

A stdlib-only Python scanner for the documented indicators of compromise
from the LiteLLM 1.107.0 PyPI/Docker supply-chain attack (2026-10-21). No
dependencies, no network calls, and no reproduction of the actual malware:
it checks for the planted filenames and runtime markers that public
incident writeups already disclosed.

> I work at Solo.io, which makes [agentgateway](https://agentgateway.dev), an
> AI gateway that competes with LiteLLM's proxy mode. This repo and the
> write-up it supports are about a public security incident, not a product
> comparison, and the scanner only checks for the documented IOCs below.

## What happened (short version)

On 2026-10-21, an attacker used three stolen developer OAuth tokens
(reportedly leaked through an AI coding tool logging response bodies into
deployment logs) to override branch protection on BerriAI/litellm's release
workflow. Between 11:39 and 11:54 UTC, that modified workflow built and
published seven backdoored `1.107.0` wheels to PyPI, plus matching images to
Docker Hub and GHCR under the `latest`/`main-latest`/`main-stable` tags.
Every one of those artifacts was correctly signed by the project's own
Trusted Publishing / cosign pipeline, the same pipeline hardened after an
earlier 2026 incident. The signing step worked exactly as designed. It
signed the wrong build, because the attacker had already changed what the
pipeline would build.

The planted code runs on every Python interpreter start on an infected
host, not just when `litellm` is imported, and targets browser passwords,
SSH/GPG keys, cloud and CI credentials, and (on LiteLLM proxies with
`DATABASE_URL` set) the provider API keys sitting in the proxy's own
database.

Full technical writeups, which this repo's IOC list is sourced from:

- [StepSecurity: litellm 1.107.0 Compromised on PyPI](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer)
- [Wiz: LiteLLM Compromised, Steals Credentials](https://www.wiz.io/blog/litellm-compromised-steals-credentials)
- [Chainguard: LiteLLM attacked again](https://www.chainguard.dev/unchained/litellm-attacked-again-malicious-1-107-0-wheels-on-pypi-and-docker-hub-october-2026)
- [SafeDep: Compromised LiteLLM 1.107.0 on PyPI](https://safedep.io/litellm-pypi-compromise-credential-stealer-backdoor/)

## The value proposition this maps to

Artifact signing proves "this specific CI run produced this artifact." It
does not prove the CI run's own instructions were the ones anyone reviewed.
If an attacker can get a change into the workflow file that builds and
signs your release, cosign or Trusted Publishing will sign whatever that
modified workflow built, with no indication anything is wrong. That is
true of any project whose signing step trusts its own repository's workflow files,
agentgateway's release pipeline included: it also signs container images
with cosign via GitHub OIDC. The defense this incident argues for is not
"sign your artifacts" (LiteLLM already did), it is restricting who can
change `.github/workflows/**` at all, independent of who can approve a
normal code change, plus verifying provenance against a pinned builder
identity rather than trusting a repo to vouch for its own workflow.

## Quickstart

```bash
git clone https://github.com/themsquared/litellm-1107-ioc-scanner.git
cd litellm-1107-ioc-scanner
./scripts/demo.sh
```

This runs the scanner three times:

1. Against `fixtures/clean_site_packages/` (empty) — expect `CLEAN`, exit 0.
2. Against `fixtures/compromised_site_packages/`, which contains inert stub
   files using the real incident's filenames (`cook.pth`, `cook.py`,
   `sitecustomize.py`) with no functional payload — expect `COMPROMISED`,
   exit 2.
3. Against this machine's real site-packages, informationally.

Or run it directly against any environment:

```bash
python3 scan.py                                  # this interpreter's site-packages + /tmp
python3 scan.py --path /path/to/venv/site-packages
python3 scan.py --path a/site-packages --path b/site-packages
```

Exit codes: `0` clean, `1` suspicious (corroborating evidence only), `2`
confirmed IOC present.

## What it checks

From the public writeups' documented artifacts:

- **Planted files** in site-packages: `cook.pth` (the `.pth` loader that runs
  on every interpreter start) and `cook.py` (the stealer module).
- **`sitecustomize.py`** presence, flagged as corroborating evidence only
  (legitimate uses of this filename exist; it is not proof by itself).
- **Filesystem markers** under `/tmp`: `remote_code_loader.lock` (the
  second-stage dead-drop poller's lock file) and the `.pc_once_*` /
  `.pc_sq_*` / `.pc_e_*` marker patterns written during and after a
  successful exfiltration attempt.
- **The `PRIVCOLLECT_ACTIVE` environment variable** in the current process.
- **Installed `litellm` version**, flagging exactly `1.107.0` and noting the
  `1.106.2` safe pin otherwise.

## What it does not check

This is a point-in-time filesystem/process scan, not an EDR agent. It will
not catch a variant that renames the planted files, and it cannot see
`/tmp` markers or environment variables in other containers or hosts
without being run there directly. It also cannot tell you whether
exfiltration already succeeded before you ran it; if any of the CRITICAL
markers are present, assume it did and follow the remediation steps the
scanner prints, which mirror the incident writeups: rebuild rather than
clean in place, and rotate every credential reachable from the host.

## Architecture notes

`scan.py` is a single stdlib file on purpose, matching the demo scope: a
tool someone can `curl` and run during an incident without trusting a new
dependency during an active supply-chain scare. It discovers candidate
site-packages directories via `sysconfig` and `site`, plus any `--path`
arguments, then runs independent checks (planted files, `/tmp` markers,
environment, installed version) and aggregates the worst severity into the
process exit code so it is scriptable in CI or a fleet-wide sweep.

## License

Apache-2.0. See [LICENSE](LICENSE).

Topics: `supply-chain-security`, `pypi`, `python`, `incident-response`,
`ai-gateways`, `llm`, `ioc-scanner`
