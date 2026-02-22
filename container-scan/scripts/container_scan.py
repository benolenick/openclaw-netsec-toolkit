#!/usr/bin/env python3
"""
Container Security Scanner — OpenClaw Skill
Scans Docker images for CVEs using trivy and inspects running container
configurations for security misconfigurations.

Exit codes: 0 = success, 1 = error, 2 = usage error
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TRIVY_TIMEOUT = 300  # 5 minutes per image
DOCKER_TIMEOUT = 30  # 30 seconds for docker commands
MAX_CVES_IN_SUMMARY = 20  # top N CVEs per image in the summary

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

DANGEROUS_CAPABILITIES = [
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_RAWIO",
    "DAC_READ_SEARCH", "NET_RAW", "SYS_MODULE", "MKNOD",
]

SENSITIVE_MOUNT_PATHS = [
    "/var/run/docker.sock",
    "/etc",
    "/proc",
    "/sys",
    "/root",
    "/",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(msg):
    """Progress message to stdout."""
    print(f"[*] {msg}", flush=True)


def warn(msg):
    """Warning to stderr."""
    print(f"WARNING: {msg}", file=sys.stderr, flush=True)


def error(msg):
    """Error to stderr."""
    print(f"ERROR: {msg}", file=sys.stderr, flush=True)


def abort(msg, code=1):
    """Fatal error — print and exit."""
    print(f"ABORT: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def run_cmd(cmd, timeout=DOCKER_TIMEOUT, capture=True):
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as exc:
        return -1, "", str(exc)


def check_binary(name):
    """Return True if binary is on PATH."""
    return shutil.which(name) is not None


def check_docker_access():
    """Verify the Docker daemon is accessible. Return (ok, error_msg)."""
    rc, out, err = run_cmd(["docker", "info", "--format", "{{.ServerVersion}}"])
    if rc == 0:
        return True, out.strip()
    if "permission denied" in err.lower() or "connect" in err.lower():
        return False, (
            "Cannot connect to Docker daemon. "
            "Ensure the current user is in the 'docker' group or run with sudo."
        )
    return False, f"Docker daemon error: {err.strip()}"


# ---------------------------------------------------------------------------
# Docker queries
# ---------------------------------------------------------------------------

def list_running_containers():
    """Return list of dicts from 'docker ps --format json'."""
    rc, out, err = run_cmd(["docker", "ps", "--format", "{{json .}}"])
    if rc != 0:
        warn(f"Failed to list running containers: {err.strip()}")
        return []
    containers = []
    for line in out.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            containers.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return containers


def list_local_images():
    """Return list of dicts from 'docker images --format json'."""
    rc, out, err = run_cmd(["docker", "images", "--format", "{{json .}}"])
    if rc != 0:
        warn(f"Failed to list local images: {err.strip()}")
        return []
    images = []
    for line in out.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            images.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return images


def inspect_container(container_id):
    """Return parsed JSON from 'docker inspect'."""
    rc, out, err = run_cmd(["docker", "inspect", container_id])
    if rc != 0:
        warn(f"Failed to inspect container {container_id}: {err.strip()}")
        return None
    try:
        data = json.loads(out)
        return data[0] if data else None
    except (json.JSONDecodeError, IndexError):
        return None


# ---------------------------------------------------------------------------
# Trivy scanning
# ---------------------------------------------------------------------------

def trivy_scan_image(image_name):
    """
    Run trivy against an image, return parsed results dict or None on failure.
    """
    log(f"Scanning image: {image_name}")
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--severity", "CRITICAL,HIGH,MEDIUM",
        "--quiet",
        image_name,
    ]
    rc, out, err = run_cmd(cmd, timeout=TRIVY_TIMEOUT)

    if rc == -1:
        warn(f"Trivy scan failed for {image_name}: {err}")
        return None
    if rc != 0 and not out.strip():
        # trivy returns non-zero when vulnerabilities are found, but still
        # produces JSON output — only treat as error when there is no output.
        warn(f"Trivy returned exit code {rc} for {image_name}: {err.strip()}")
        return None

    # Trivy may print warnings to stderr but still produce valid JSON on stdout
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        warn(f"Could not parse trivy JSON output for {image_name}")
        return None


def parse_trivy_results(trivy_json):
    """
    Extract vulnerability records from trivy JSON output.
    Returns a list of dicts with normalized fields.
    """
    vulns = []
    if not trivy_json:
        return vulns

    results = trivy_json.get("Results", [])
    for result in results:
        target = result.get("Target", "unknown")
        target_type = result.get("Type", "unknown")
        for v in result.get("Vulnerabilities", []):
            vulns.append({
                "cve_id": v.get("VulnerabilityID", "N/A"),
                "severity": v.get("Severity", "UNKNOWN"),
                "package": v.get("PkgName", "unknown"),
                "installed_version": v.get("InstalledVersion", "N/A"),
                "fixed_version": v.get("FixedVersion", ""),
                "title": v.get("Title", ""),
                "description": v.get("Description", "")[:300],
                "target": target,
                "target_type": target_type,
            })
    return vulns


def group_by_severity(vulns):
    """Group vulnerability list by severity, return dict."""
    groups = {s: [] for s in SEVERITY_ORDER}
    for v in vulns:
        sev = v.get("severity", "UNKNOWN")
        if sev not in groups:
            groups[sev] = []
        groups[sev].append(v)
    return groups


# ---------------------------------------------------------------------------
# Configuration checks on running containers
# ---------------------------------------------------------------------------

def check_container_config(inspect_data, container_name):
    """
    Analyze a container's inspect data for security misconfigurations.
    Returns a list of finding dicts: {severity, issue, detail}.
    """
    findings = []
    if not inspect_data:
        return findings

    config = inspect_data.get("Config", {})
    host_config = inspect_data.get("HostConfig", {})
    network_settings = inspect_data.get("NetworkSettings", {})

    # --- Running as root ---
    user = config.get("User", "")
    if user == "" or user == "root" or user == "0":
        findings.append({
            "severity": "HIGH",
            "issue": f'Container "{container_name}" running as root',
            "detail": "No USER directive set or explicitly set to root/0.",
        })

    # --- Privileged mode ---
    if host_config.get("Privileged", False):
        findings.append({
            "severity": "CRITICAL",
            "issue": f'Container "{container_name}" running in privileged mode',
            "detail": "Full host access — equivalent to running on the host.",
        })

    # --- Host network mode ---
    network_mode = host_config.get("NetworkMode", "")
    if network_mode == "host":
        findings.append({
            "severity": "HIGH",
            "issue": f'Container "{container_name}" using host network mode',
            "detail": "Container shares the host network namespace.",
        })

    # --- Sensitive mounts ---
    mounts = inspect_data.get("Mounts", [])
    for mount in mounts:
        source = mount.get("Source", "")
        destination = mount.get("Destination", "")
        # docker.sock
        if "docker.sock" in source or "docker.sock" in destination:
            findings.append({
                "severity": "CRITICAL",
                "issue": f'Container "{container_name}" has docker.sock mounted',
                "detail": f"Mount: {source} -> {destination}",
            })
        # Root filesystem
        elif source == "/":
            findings.append({
                "severity": "MEDIUM",
                "issue": f'Container "{container_name}" has host root filesystem mounted',
                "detail": f"Mount: {source} -> {destination}",
            })
        # Other sensitive paths
        elif any(source == p or source.startswith(p + "/") for p in ["/etc", "/proc", "/sys", "/root"]):
            findings.append({
                "severity": "MEDIUM",
                "issue": f'Container "{container_name}" mounts sensitive host path',
                "detail": f"Mount: {source} -> {destination}",
            })

    # --- Dangerous capabilities ---
    cap_add = host_config.get("CapAdd") or []
    for cap in cap_add:
        if cap in DANGEROUS_CAPABILITIES:
            sev = "HIGH" if cap in ("SYS_ADMIN", "NET_ADMIN") else "MEDIUM"
            findings.append({
                "severity": sev,
                "issue": f'Container "{container_name}" has {cap} capability',
                "detail": f"Capability {cap} added via --cap-add.",
            })

    # --- No resource limits ---
    memory = host_config.get("Memory", 0)
    nano_cpus = host_config.get("NanoCpus", 0)
    cpu_shares = host_config.get("CpuShares", 0)
    if memory == 0 and nano_cpus == 0 and cpu_shares == 0:
        findings.append({
            "severity": "MEDIUM",
            "issue": f'Container "{container_name}" has no resource limits',
            "detail": "No memory or CPU limits configured.",
        })

    # --- Missing healthcheck ---
    healthcheck = config.get("Healthcheck")
    if not healthcheck or healthcheck.get("Test") in (None, [], ["NONE"]):
        findings.append({
            "severity": "LOW",
            "issue": f'Container "{container_name}" has no healthcheck',
            "detail": "No HEALTHCHECK instruction defined.",
        })

    return findings


# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------

def build_scan_results(image_scans, config_findings, running_containers):
    """Assemble the full structured results dict."""
    return {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "images_scanned": len(image_scans),
        "running_containers": len(running_containers),
        "image_results": image_scans,
        "configuration_findings": config_findings,
    }


def write_scan_results_json(results, output_dir):
    """Write scan-results.json."""
    path = os.path.join(output_dir, "scan-results.json")
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    log(f"Wrote {path}")


def write_image_configs_json(configs, output_dir):
    """Write image-configs.json with docker inspect data."""
    path = os.path.join(output_dir, "image-configs.json")
    with open(path, "w") as f:
        json.dump(configs, f, indent=2)
    log(f"Wrote {path}")


def write_summary(results, output_dir):
    """Write scan-summary.txt — human-readable report."""
    lines = []
    sep = "=" * 70

    lines.append(sep)
    lines.append("CONTAINER SECURITY SCAN SUMMARY")
    lines.append(f"Timestamp: {results['scan_timestamp']}")
    lines.append(
        f"Images Scanned: {results['images_scanned']} | "
        f"Running Containers: {results['running_containers']}"
    )
    lines.append(sep)

    # ---- Vulnerability overview per image ----
    lines.append("")
    lines.append("VULNERABILITY OVERVIEW:")
    lines.append("-" * 40)

    total_crit = 0
    total_high = 0
    total_med = 0

    for img_result in results["image_results"]:
        image = img_result["image"]
        vulns = img_result.get("vulnerabilities", [])
        grouped = group_by_severity(vulns)

        n_crit = len(grouped.get("CRITICAL", []))
        n_high = len(grouped.get("HIGH", []))
        n_med = len(grouped.get("MEDIUM", []))
        total_crit += n_crit
        total_high += n_high
        total_med += n_med

        if img_result.get("scan_error"):
            lines.append(f"  Image: {image}")
            lines.append(f"    SCAN ERROR: {img_result['scan_error']}")
            lines.append("")
            continue

        lines.append(f"  Image: {image}")
        if n_crit == 0 and n_high == 0 and n_med == 0:
            lines.append("    No vulnerabilities found (CLEAN)")
        else:
            lines.append(
                f"    CRITICAL: {n_crit} | HIGH: {n_high} | MEDIUM: {n_med}"
            )
            # Top issues
            sorted_vulns = sorted(
                vulns,
                key=lambda v: SEVERITY_ORDER.index(v["severity"])
                    if v["severity"] in SEVERITY_ORDER else 99,
            )
            top_n = sorted_vulns[:MAX_CVES_IN_SUMMARY]
            if top_n:
                lines.append("    Top Issues:")
                for v in top_n:
                    fix = f" -> {v['fixed_version']}" if v["fixed_version"] else " (no fix available)"
                    lines.append(
                        f"      {v['cve_id']} ({v['severity']}) "
                        f"{v['package']} {v['installed_version']}{fix}"
                    )
        lines.append("")

    lines.append(
        f"  TOTALS: CRITICAL={total_crit}  HIGH={total_high}  MEDIUM={total_med}"
    )

    # ---- Configuration issues ----
    config_findings = results.get("configuration_findings", [])
    lines.append("")
    lines.append("CONFIGURATION ISSUES:")
    lines.append("-" * 40)

    if not config_findings:
        lines.append("  No running containers to inspect, or no issues found.")
    else:
        for f in sorted(
            config_findings,
            key=lambda x: SEVERITY_ORDER.index(x["severity"])
                if x["severity"] in SEVERITY_ORDER else 99,
        ):
            lines.append(f"  [{f['severity']}] {f['issue']}")

    # ---- Recommendations ----
    lines.append("")
    lines.append("RECOMMENDATIONS:")
    lines.append("-" * 40)
    recommendations = _build_recommendations(results)
    if not recommendations:
        lines.append("  No actionable recommendations at this time.")
    else:
        for rec in recommendations:
            lines.append(f"  -> {rec}")

    lines.append("")
    lines.append(sep)
    lines.append(f"Full results: {output_dir}/scan-results.json")
    lines.append(f"Config data:  {output_dir}/image-configs.json")
    lines.append(sep)

    path = os.path.join(output_dir, "scan-summary.txt")
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    log(f"Wrote {path}")
    # Also print summary to stdout
    print("\n".join(lines))


def _build_recommendations(results):
    """Generate actionable recommendation strings."""
    recs = []
    seen = set()

    for img_result in results["image_results"]:
        image = img_result["image"]
        vulns = img_result.get("vulnerabilities", [])
        grouped = group_by_severity(vulns)

        n_crit = len(grouped.get("CRITICAL", []))
        n_high = len(grouped.get("HIGH", []))

        # Fixable critical/high
        fixable_crit = [v for v in grouped.get("CRITICAL", []) if v["fixed_version"]]
        fixable_high = [v for v in grouped.get("HIGH", []) if v["fixed_version"]]

        if fixable_crit:
            key = f"update-{image}-critical"
            if key not in seen:
                seen.add(key)
                recs.append(
                    f"Update base image for {image} "
                    f"({len(fixable_crit)} critical fix(es) available)"
                )
        if fixable_high:
            key = f"update-{image}-high"
            if key not in seen:
                seen.add(key)
                recs.append(
                    f"Update packages in {image} "
                    f"({len(fixable_high)} high-severity fix(es) available)"
                )

    for f in results.get("configuration_findings", []):
        issue = f["issue"]
        if "running as root" in issue.lower():
            name = issue.split('"')[1] if '"' in issue else "container"
            key = f"user-{name}"
            if key not in seen:
                seen.add(key)
                recs.append(f"Add USER directive to {name} Dockerfile")
        elif "docker.sock" in issue.lower():
            name = issue.split('"')[1] if '"' in issue else "container"
            key = f"sock-{name}"
            if key not in seen:
                seen.add(key)
                recs.append(
                    f"Remove docker.sock mount from {name} or use Docker socket proxy"
                )
        elif "privileged" in issue.lower():
            name = issue.split('"')[1] if '"' in issue else "container"
            key = f"priv-{name}"
            if key not in seen:
                seen.add(key)
                recs.append(
                    f"Remove --privileged flag from {name} — "
                    f"use specific capabilities instead"
                )
        elif "no resource limits" in issue.lower():
            name = issue.split('"')[1] if '"' in issue else "container"
            key = f"limits-{name}"
            if key not in seen:
                seen.add(key)
                recs.append(
                    f"Set memory and CPU limits for {name} "
                    f"(--memory, --cpus)"
                )

    return recs


# ---------------------------------------------------------------------------
# Main workflow
# ---------------------------------------------------------------------------

def resolve_images(args):
    """
    Determine which images to scan based on CLI arguments.
    Returns (image_list, running_containers_list).
    """
    running = list_running_containers()

    if args.images:
        # User explicitly specified images
        images = [i.strip() for i in args.images.split(",") if i.strip()]
        log(f"User-specified images: {images}")
        return images, running

    if args.running_only or not running:
        # --running-only flag, or fallback when nothing else specified
        if not running:
            log("No running containers found.")
            # Fall back to local images
            local = list_local_images()
            if not local:
                log("No local images found either.")
                return [], []
            images = []
            for img in local:
                repo = img.get("Repository", "<none>")
                tag = img.get("Tag", "<none>")
                if repo != "<none>":
                    name = f"{repo}:{tag}" if tag != "<none>" else repo
                    if name not in images:
                        images.append(name)
            log(f"Falling back to local images: {images}")
            return images, running
        else:
            images = []
            for c in running:
                img = c.get("Image", "")
                if img and img not in images:
                    images.append(img)
            log(f"Scanning running containers' images: {images}")
            return images, running

    # Default: scan running containers' images
    images = []
    for c in running:
        img = c.get("Image", "")
        if img and img not in images:
            images.append(img)
    if images:
        log(f"Defaulting to running containers' images: {images}")
    else:
        # No running containers have parseable image names; try local images
        local = list_local_images()
        for img in local:
            repo = img.get("Repository", "<none>")
            tag = img.get("Tag", "<none>")
            if repo != "<none>":
                name = f"{repo}:{tag}" if tag != "<none>" else repo
                if name not in images:
                    images.append(name)
        log(f"No running containers; using local images: {images}")

    return images, running


def main():
    parser = argparse.ArgumentParser(
        description="Container Security Scanner — scan images for CVEs and check configs."
    )
    parser.add_argument(
        "--output", required=True,
        help="Output directory for results (will be created if needed).",
    )
    parser.add_argument(
        "--images",
        help="Comma-separated list of images to scan (e.g. nginx:latest,python:3.11).",
    )
    parser.add_argument(
        "--running-only", action="store_true",
        help="Only scan images used by currently running containers.",
    )
    args = parser.parse_args()

    # --- Preflight checks ---
    log("Container Security Scanner starting")

    if not check_binary("docker"):
        abort("docker is not installed or not on PATH. Install with: sudo apt install docker.io")

    if not check_binary("trivy"):
        abort(
            "trivy is not installed or not on PATH. Install with:\n"
            "  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh "
            "| sh -s -- -b /usr/local/bin"
        )

    ok, docker_info = check_docker_access()
    if not ok:
        abort(docker_info)
    log(f"Docker daemon OK (server version: {docker_info})")

    # --- Prepare output directory ---
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    # --- Resolve images ---
    images, running_containers = resolve_images(args)

    if not images:
        log("Nothing to scan. Provide --images or start some containers.")
        # Still write empty results
        empty_results = build_scan_results([], [], running_containers)
        write_scan_results_json(empty_results, output_dir)
        write_image_configs_json([], output_dir)
        write_summary(empty_results, output_dir)
        sys.exit(0)

    # --- Scan each image with trivy ---
    image_scans = []
    for image in images:
        trivy_raw = trivy_scan_image(image)
        if trivy_raw is None:
            image_scans.append({
                "image": image,
                "vulnerabilities": [],
                "scan_error": f"Trivy scan failed for {image}. Image may not exist locally.",
            })
            continue
        vulns = parse_trivy_results(trivy_raw)
        log(f"  {image}: found {len(vulns)} vulnerabilities")
        image_scans.append({
            "image": image,
            "vulnerabilities": vulns,
            "scan_error": None,
        })

    # --- Inspect running containers ---
    config_findings = []
    inspect_data_all = []

    for container in running_containers:
        cid = container.get("ID", container.get("Id", ""))
        cname = container.get("Names", container.get("Name", cid))
        # docker ps JSON uses "Names" with possible comma-separated names
        if isinstance(cname, str):
            cname = cname.strip().split(",")[0].strip()
        if not cid:
            continue
        log(f"Inspecting container: {cname} ({cid[:12]})")
        inspect_data = inspect_container(cid)
        if inspect_data:
            inspect_data_all.append(inspect_data)
            findings = check_container_config(inspect_data, cname)
            config_findings.extend(findings)

    # --- Assemble and write results ---
    results = build_scan_results(image_scans, config_findings, running_containers)
    write_scan_results_json(results, output_dir)
    write_image_configs_json(inspect_data_all, output_dir)
    write_summary(results, output_dir)

    log("Scan complete.")
    sys.exit(0)


if __name__ == "__main__":
    main()
