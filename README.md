# nmap-scan-automation

**Personal/learning-focused Nmap automation toolkit**  
Designed to be used by *you* in labs, CTFs, or owned networks. Includes profiles, parallel scanning, JSON/CSV/HTML report generation, and resume support.

> ⚠️ **LEGAL / ETHICAL NOTICE**  
> Use this tool **only** on systems you own or where you have explicit written permission to test. Unauthorized scanning may be illegal. The author is not responsible for misuse.

---

## Features
- YAML-driven scan profiles (`profiles.yaml`) for quick, stealth, vuln, web, and custom scans
- Runs multiple targets in parallel
- Saves outputs to `reports/` (XML/Nmap normal, JSON, plus a custom `.scan.report.json`)
- Creates CSV summaries and simple HTML summaries for quick review
- Keeps `.scan_state.json` to avoid re-scanning targets (use `--force` to ignore)
- Lightweight parsing of nmap `.nmap` output for quick summaries
- Easy to extend with new profiles and script groups

---

## Requirements
- `nmap` installed and on PATH (https://nmap.org/download.html)
- Python 3.8+
- Python dependencies:
```bash
pip install pyyaml
