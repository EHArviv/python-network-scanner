# Python Network Scanner

A Python TCP network scanner for authorized lab environments that checks selected ports, identifies basic service hints, and generates CSV, TXT, JSON, NDJSON, findings, and HTML reports.

This project is designed for Security Engineer, SOC, IT Security, and network security automation portfolio workflows.

## Safety Notice

This tool is read-only and intended for authorized environments only.

Use it only on systems you own, lab machines, localhost, or targets where you have clear permission.

It does not perform exploitation, brute force, password attacks, or vulnerability exploitation.

## Features

- Scan a single target
- Scan multiple targets from a file
- Check selected TCP ports
- Support comma-separated ports
- Support port ranges
- Detect open or closed/filtered TCP ports
- Provide basic service hints
- Assign severity based on exposed port
- Provide security recommendations
- Generate CSV report
- Generate TXT summary
- Generate JSON report
- Generate findings.json
- Generate events.ndjson
- Generate HTML report
- Include unit tests
- Include GitHub Actions workflow

## Project Structure

    python-network-scanner/
    ├── .github/
    │   └── workflows/
    │       └── python-check.yml
    ├── docs/
    │   ├── project-notes.md
    │   └── scanning-scope.md
    ├── reports/
    │   └── .gitkeep
    ├── sample_outputs/
    ├── sample_targets/
    │   └── targets.txt
    ├── src/
    │   └── network_scanner.py
    ├── tests/
    │   └── test_risk_logic.py
    ├── README.md
    ├── requirements.txt
    └── .gitignore

## Usage

Scan localhost:

    python src/network_scanner.py --target 127.0.0.1 --ports 22,80,443 --output reports --format all

Scan targets from a file:

    python src/network_scanner.py --file sample_targets/targets.txt --ports 22,80,443 --timeout 0.5 --output reports --format all

Scan a port range:

    python src/network_scanner.py --target 127.0.0.1 --ports 20-25 --output reports --format all

Generate only HTML:

    python src/network_scanner.py --target 127.0.0.1 --ports 22,80,443 --output reports --format html

## Generated Reports

The tool generates reports locally inside the reports folder:

- network_scan_report.csv
- network_scan_summary.txt
- network_scan_report.json
- findings.json
- events.ndjson
- network_scan_report.html

Generated report files are ignored by Git and should not be committed.

## Output Formats

### CSV

Used for spreadsheet-based review and filtering.

### TXT

Used for human-readable summaries.

### JSON

Used for automation, dashboards, APIs, and structured reporting.

### findings.json

Used for security finding workflows.

### events.ndjson

Used for SIEM-style ingestion.

### HTML

Used for readable reports that can be opened in a browser.

## Severity Logic

Open ports are assigned severity based on common exposure risk.

| Port Type | Severity |
|---|---|
| High-risk open ports such as Telnet, SMB, RDP, Redis | High |
| Common service ports such as SSH, HTTP, HTTPS, DNS, database ports | Medium |
| Other open ports | Low |
| Closed or filtered ports | Info |

## Example High-Risk Ports

- 23 Telnet
- 445 SMB
- 3389 RDP
- 6379 Redis

## GitHub Actions

This project includes a GitHub Actions workflow that runs automated checks on every push and pull request.

The workflow:

- Checks Python syntax
- Runs unit tests
- Runs a localhost demo scan
- Verifies that reports can be generated successfully

Workflow file:

    .github/workflows/python-check.yml

## Requirements

No external dependencies are required.

This project uses only Python standard library modules.

## Run Tests

    python -m unittest discover -s tests

## Privacy

Sample targets use localhost and documentation-safe IP ranges.

No real personal, internal, customer, or production targets should be committed.

## Skills Demonstrated

- Python automation
- TCP socket programming
- Network security basics
- Authorized network discovery
- Port exposure review
- Security reporting
- Risk classification
- CSV report generation
- TXT summary generation
- JSON report generation
- NDJSON event generation
- HTML report generation
- Unit testing
- GitHub Actions
- SOC/SIEM-style output formats
- Security Engineer workflow

## Example Resume Description

Built a Python network scanner for authorized lab environments that checks TCP ports, identifies basic service hints, assigns risk severity, and generates CSV/TXT/JSON/NDJSON/HTML reports with unit tests and GitHub Actions.
