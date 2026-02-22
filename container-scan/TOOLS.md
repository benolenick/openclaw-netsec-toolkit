# Container Security Scan — Tool Instructions

When the user asks to scan Docker images or containers for vulnerabilities, run this command:
```bash
python3 {baseDir}/scripts/container_scan.py \
  --output /tmp/container-scan-latest
```

If the user specifies particular images to scan, pass them with `--images`:
```bash
python3 {baseDir}/scripts/container_scan.py \
  --images "nginx:latest,python:3.11" \
  --output /tmp/container-scan-latest
```

If the user only wants to scan images used by running containers, add `--running-only`:
```bash
python3 {baseDir}/scripts/container_scan.py \
  --running-only \
  --output /tmp/container-scan-latest
```

Replace image names with the actual image(s) the user wants to scan. Multiple images should be comma-separated with no spaces around the commas.

After the scan completes, read the summary:
```bash
cat /tmp/container-scan-latest/scan-summary.txt
```

Present the findings to the user in a clear, structured format highlighting:
- Number of images scanned and running containers inspected
- Vulnerability counts by severity (CRITICAL, HIGH, MEDIUM) per image
- Top CVEs with package name, installed version, and fixed version
- Container configuration issues (running as root, privileged mode, docker.sock mounted, etc.)
- Specific recommendations for remediation (base image updates, Dockerfile fixes)
- Overall risk assessment

If the scan fails, check that docker is installed and accessible (`which docker` and `docker info`), that trivy is installed (`which trivy`), and that the user has permission to access the Docker daemon (membership in the `docker` group).
