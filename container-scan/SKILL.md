---
name: container-scan
description: >
  CONTAINER SECURITY SCANNER. You MUST use this skill whenever the user mentions:
  "scan containers", "container security", "docker vulnerabilities", "check docker images",
  "container scan", "trivy scan", "docker cve", "image vulnerabilities", or any request
  about scanning Docker images or running containers for CVEs, misconfigurations, or
  security issues. This skill uses trivy and docker inspect to audit container images
  and runtime configurations. Read this SKILL.md FIRST before running any docker or
  trivy commands yourself.
metadata:
  {
    "openclaw":
      {
        "emoji": "📦",
        "os": ["linux"],
        "requires": { "bins": ["docker", "trivy", "python3"] },
        "install":
          [
            {
              "id": "apt-docker",
              "kind": "apt",
              "package": "docker.io",
              "bins": ["docker"],
              "label": "Install docker (apt)",
            },
            {
              "id": "script-trivy",
              "kind": "script",
              "command": "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin",
              "bins": ["trivy"],
              "label": "Install trivy (script)",
            },
          ],
      },
  }
---

# Container Security Scan

Scan Docker images and running containers for CVEs, misconfigurations, and security issues using trivy and docker inspect.

## Safety Constraints

- **Read-only scanning only**: Never modify, stop, or delete containers or images.
- **Local Docker daemon only**: No connections to remote Docker hosts.
- **No container exec or shell access**: Never run commands inside containers.
- **No image pulling unless requested**: Do not pull images from registries unless the user explicitly asks.
- **Scan results stay local**: No uploads to external services or registries.

## Quick Workflow (default)

Follow the instructions in TOOLS.md — they tell you exactly what to do.
The scanner prints a human-readable summary. Reply to the user with that summary.
Do NOT read analyst-prompt.md or report-template.md — those are for the full workflow below.

## Full Workflow (only if user asks for a "full report" or "detailed audit")

Execute these three phases in order:

### Phase 1 — Scan

Run the container scanner (use images from the user, output to /tmp/container-scan-latest):

```bash
python3 {baseDir}/scripts/container_scan.py \
  --images "nginx:latest,python:3.11" \
  --output /tmp/container-scan-latest
```

Or to scan only running containers' images:

```bash
python3 {baseDir}/scripts/container_scan.py \
  --running-only \
  --output /tmp/container-scan-latest
```

Read the `scan-summary.txt` from the output directory.

### Phase 2 — Analyze

Read `{baseDir}/references/analyst-prompt.md` and follow its instructions to analyze
the scan results. Produce structured findings in the specified format.

### Phase 3 — Report

Read `{baseDir}/assets/report-template.md` and fill in the template.
Save the final report to the output directory as `container-scan-report.md`.
Present a concise summary to the user with the key findings and the report path.
