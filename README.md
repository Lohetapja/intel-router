## Design Principles

intel-router is intentionally narrow and conservative.

It is designed to support human SOC decision-making, not replace it.

Key principles:

- **Action-oriented**: Outputs recommendations (Block / Hunt / Awareness / Ignored), not raw intel.
- **Time-aware**: Indicator relevance decays over time; stale intel is de-prioritized.
- **Explainable**: Every routing decision includes a human-readable reason.
- **Noise-resistant**: Obvious non-actionable indicators (e.g., private IPs, localhost) are ignored early.
- **Non-automated**: No auto-blocking or enforcement is performed.
- **Opinionated**: Defaults are intentionally conservative and not endlessly configurable.

This tool favors clarity and restraint over completeness.

## Quick Start (Step-by-step)

This is a small, offline CLI tool. You put indicators into `intel.json`, run the script, and it writes `report.json`.

### 1) Download the project
- Click **Code → Download ZIP** on GitHub
- Unzip the folder
- Open the folder so you can see files like:
  - `router.py`
  - `intel.json`
  - `README.md`

### 2) Install Python (only if you don't have it)
- Install Python 3.10+ from the official Python website
- During install, make sure **"Add Python to PATH"** is checked

Quick check (Windows):
- Open PowerShell in the folder
- Run:
  ```powershell
  python --version

You should see something like Python 3.x.x.

3) Put your indicators into intel.json

Open intel.json and replace its contents with something like this:

<img width="337" height="401" alt="image" src="https://github.com/user-attachments/assets/ca9e5fd0-6d6b-4e25-b6ce-00edd7ee4184" />

Rules for each entry:
indicator: the thing you want to check (IP or domain)
type: "ip" or "domain"
source: where you got it (example: otx, abuse_ch, internal-alert)
last_seen: date in YYYY-MM-DD format

4) Run the tool
Open a terminal inside the folder and run:
python router.py

You should see:
intel-router started
Loaded X indicators
Wrote report.json

5) Read the results
Open the file report.json.
It contains four sections:
ignored
Obvious noise (example: private IPs like 192.168.x.x, localhost)
awareness
Old indicators (usually not worth hunting)
hunt_packages
Recent indicators you should search for in logs
Includes simple hunt queries (Splunk/KQL templates)
block_candidates
Very strict candidates (still manual; nothing is auto-blocked)

6) Where do I get indicators from?
Common sources:
Threat reports and advisories (IOCs listed in blogs, PDFs)
Public intel feeds (example: abuse.ch, OTX)
Internal alerts/tickets (suspicious IP/domain from your SOC tools)
Copy a few IOCs you care about into intel.json. Don’t paste thousands.

7) Important notes
This tool does not auto-block anything.
This tool does not pull feeds automatically.
It is meant to help with daily triage and decision-making.

Troubleshooting
If python router.py doesn’t work:
Make sure you are in the correct folder (the one with router.py)
Check Python:
python --version
Make sure intel.json is valid JSON (commas and quotes matter)


