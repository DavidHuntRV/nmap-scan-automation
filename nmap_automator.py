#!/usr/bin/env python3
"""
nmap_automator.py
Advanced Nmap Scan Automation for personal learning/lab use.

Features:
- YAML-defined scan profiles (fast, stealth, full, vuln, custom)
- Parallel scanning of multiple targets
- JSON, CSV, and basic HTML summary reports
- NSE script groups (default & customizable)
- Resume support (keeps track of completed targets)
- Safe-use legal disclaimer printed on run
Requires: Python 3.8+, nmap binary installed
"""

import argparse
import concurrent.futures
import csv
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    import yaml
except Exception:
    print("Missing dependency 'PyYAML'. Install with: pip install pyyaml")
    sys.exit(1)

# ---------- Config ----------
REPO_ROOT = Path(__file__).parent
REPORTS_DIR = REPO_ROOT / "reports"
STATE_FILE = REPO_ROOT / ".scan_state.json"
DEFAULT_PROFILES = REPO_ROOT / "profiles.yaml"
TIMEOUT = 60 * 60  # 1 hour default per scan

# ---------- Helpers ----------


def load_profiles(path: Path) -> Dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def ensure_reports_dir():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def save_state(state: Dict):
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)


def load_state() -> Dict:
    if STATE_FILE.exists():
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {"completed": []}


def run_cmd(cmd: List[str], timeout: int = TIMEOUT) -> Dict:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout, text=True)
        return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except subprocess.TimeoutExpired as e:
        return {"returncode": -1, "stdout": e.stdout or "", "stderr": f"Timeout after {timeout}s"}


def build_nmap_cmd(target: str, profile: Dict, out_prefix: str) -> List[str]:
    """
    Build an nmap command list based on a profile entry.
    Profile example:
      scans:
        - name: full_tcp
          flags: -sS -p- -T4
          scripts: default
    """
    flags = profile.get("flags", "")
    scripts = profile.get("scripts")
    extra = profile.get("extra", "")
    cmd = ["nmap"]
    if profile.get("sudo", False):
        # Note: user should run script with sudo separately if needed
        pass
    cmd += shlex.split(flags) if flags else []
    if scripts:
        # allow `default`, a comma separated, or a script category like vuln
        cmd += ["--script", scripts]
    if profile.get("output", "all") in ("all", "xml"):
        cmd += ["-oX", str(REPORTS_DIR / f"{out_prefix}.xml")]
    if profile.get("output", "all") in ("all", "normal"):
        cmd += ["-oN", str(REPORTS_DIR / f"{out_prefix}.nmap")]
    # JSON output using nmap's -oJ available via Nmap 7.80+? if not available will be blank. Fallback using parsing.
    if profile.get("output", "all") in ("all", "json"):
        cmd += ["-oJ", str(REPORTS_DIR / f"{out_prefix}.json")]
    if extra:
        cmd += shlex.split(extra)
    cmd += [target]
    return cmd


def parse_basic_from_nmap_normal(nmap_text: str) -> Dict:
    # Lightweight parser to extract open ports lines; not exhaustive
    lines = nmap_text.splitlines()
    ports = []
    capture = False
    for ln in lines:
        if ln.strip().startswith("PORT"):
            capture = True
            continue
        if capture:
            if ln.strip() == "" or ln.startswith("Nmap done:"):
                break
            parts = ln.split()
            if len(parts) >= 3:
                ports.append(
                    {"port_proto": parts[0], "state": parts[1], "service": parts[2]})
    return {"ports": ports}


def write_json_report(prefix: str, target: str, result: Dict):
    fname = REPORTS_DIR / f"{prefix}.scan.report.json"
    payload = {
        "target": target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "nmap_returncode": result.get("returncode"),
        "stdout": result.get("stdout"),
        "stderr": result.get("stderr"),
        "parsed": parse_basic_from_nmap_normal(result.get("stdout", ""))
    }
    with open(fname, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return fname


def write_csv_summary(rows: List[Dict], csv_path: Path):
    keys = ["target", "port_proto", "state", "service"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=keys)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def generate_html_summary(prefix: str, target: str, parsed: Dict, out_path: Path):
    html = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>Scan report: {target}</title></head>
<body>
  <h1>Scan report for {target}</h1>
  <p>Generated: {datetime.utcnow().isoformat()}Z</p>
  <h2>Open ports</h2>
  <table border="1" cellpadding="4">
    <thead><tr><th>Port/Proto</th><th>State</th><th>Service</th></tr></thead>
    <tbody>
"""
    for p in parsed.get("ports", []):
        html += f"<tr><td>{p.get('port_proto')}</td><td>{p.get('state')}</td><td>{p.get('service')}</td></tr>\n"
    html += """
    </tbody>
  </table>
</body>
</html>
"""
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return out_path

# ---------- Scan worker ----------


def scan_target(target: str, profile_name: str, profiles: Dict, state: Dict, force: bool = False) -> Optional[Dict]:
    if target in state.get("completed", []) and not force:
        print(f"[SKIP] {target} already completed (use --force to re-scan).")
        return None
    prof = profiles.get("scans", {}).get(profile_name)
    if not prof:
        raise ValueError(
            f"Profile '{profile_name}' not found in profiles.yaml")
    out_prefix = f"{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}_{target.replace(':', '_')}_{profile_name}"
    cmd = build_nmap_cmd(target, prof, out_prefix)
    print(f"[RUN] {' '.join(cmd)}")
    result = run_cmd(cmd, timeout=prof.get("timeout", TIMEOUT))
    json_path = write_json_report(out_prefix, target, result)
    parsed = json.loads(json_path.read_text())["parsed"]
    # CSV summarization
    rows = []
    for p in parsed.get("ports", []):
        rows.append({"target": target, "port_proto": p.get(
            "port_proto"), "state": p.get("state"), "service": p.get("service")})
    csv_path = REPORTS_DIR / f"{out_prefix}.summary.csv"
    write_csv_summary(rows, csv_path)
    # HTML
    html_path = REPORTS_DIR / f"{out_prefix}.summary.html"
    generate_html_summary(out_prefix, target, parsed, html_path)
    # Add to completed
    state.setdefault("completed", []).append(target)
    save_state(state)
    print(
        f"[DONE] {target} -> reports: {json_path.name}, {csv_path.name}, {html_path.name}")
    return {"target": target, "json": str(json_path), "csv": str(csv_path), "html": str(html_path)}

# ---------- CLI ----------


def parse_args():
    p = argparse.ArgumentParser(
        description="nmap scan automator (lab use only)")
    p.add_argument("-t", "--targets", nargs="+", required=True,
                   help="Targets (IPs/hosts) to scan")
    p.add_argument("-p", "--profile", default="quick",
                   help="Scan profile name from profiles.yaml")
    p.add_argument("-c", "--concurrency", type=int,
                   default=2, help="Number of parallel scans")
    p.add_argument("--profiles-file", default=str(DEFAULT_PROFILES),
                   help="Path to profiles.yaml")
    p.add_argument("--force", action="store_true",
                   help="Force re-scan even if target is recorded as completed")
    return p.parse_args()


def main():
    print("nmap-scan-automation - for authorized lab use only.")
    print("Ensure you have permission to scan your target(s).")
    args = parse_args()
    ensure_reports_dir()
    profiles = load_profiles(Path(args.profiles_file))
    state = load_state()

    # Simple ctrl-c handler to save state gracefully
    def handle_sig(signum, frame):
        print("Received interrupt - saving state and exiting...")
        save_state(state)
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    targets = args.targets
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = {ex.submit(scan_target, tgt, args.profile,
                             profiles, state, args.force): tgt for tgt in targets}
        for fut in concurrent.futures.as_completed(futures):
            try:
                r = fut.result()
                if r:
                    results.append(r)
            except Exception as e:
                print(f"[ERROR] scanning {futures[fut]} -> {e}")

    # final summary JSON
    summary = {
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "profile": args.profile,
        "results": results
    }
    summary_path = REPORTS_DIR / \
        f"summary_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(f"All done. Summary saved to {summary_path}")


if __name__ == "__main__":
    main()
