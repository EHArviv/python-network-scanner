from pathlib import Path
from datetime import datetime, timezone
import argparse
import csv
import html
import json
import socket


DEFAULT_TIMEOUT = 1.0

PORT_RECOMMENDATIONS = {
    21: "FTP is open. Verify whether it is required and prefer secure alternatives.",
    22: "SSH is open. Restrict access to trusted networks and enforce strong authentication.",
    23: "Telnet is open. Disable Telnet and use SSH instead.",
    25: "SMTP is open. Verify mail relay restrictions and exposure.",
    53: "DNS is open. Verify recursion settings and exposure.",
    80: "HTTP is open. Verify web server hardening and redirect to HTTPS where appropriate.",
    110: "POP3 is open. Verify whether legacy mail protocols are required.",
    139: "NetBIOS is open. Restrict exposure to trusted internal networks.",
    143: "IMAP is open. Verify secure configuration and encryption.",
    443: "HTTPS is open. Verify TLS configuration and certificate validity.",
    445: "SMB is open. Restrict exposure and avoid internet-facing SMB.",
    3389: "RDP is open. Restrict access using VPN, firewall rules, and MFA.",
}


def parse_ports(ports_text: str) -> list[int]:
    ports = []

    for item in ports_text.split(","):
        item = item.strip()

        if not item:
            continue

        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start_port = int(start_text)
            end_port = int(end_text)

            for port in range(start_port, end_port + 1):
                ports.append(port)
        else:
            ports.append(int(item))

    return sorted(set(ports))


def validate_port(port: int) -> bool:
    return 1 <= port <= 65535


def check_tcp_port(target: str, port: int, timeout: float) -> dict:
    if not validate_port(port):
        return {
            "target": target,
            "port": port,
            "status": "invalid",
            "service_hint": "unknown",
            "severity": "Info",
            "recommendation": "Use a valid TCP port between 1 and 65535.",
        }

    try:
        with socket.create_connection((target, port), timeout=timeout):
            status = "open"

    except socket.timeout:
        status = "closed_or_filtered"

    except OSError:
        status = "closed_or_filtered"

    service_hint = get_service_hint(port)
    severity = calculate_port_severity(port, status)
    recommendation = get_port_recommendation(port, status)

    return {
        "target": target,
        "port": port,
        "status": status,
        "service_hint": service_hint,
        "severity": severity,
        "recommendation": recommendation,
    }


def get_service_hint(port: int) -> str:
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Alt",
    }

    return common_ports.get(port, "unknown")


def calculate_port_severity(port: int, status: str) -> str:
    if status != "open":
        return "Info"

    high_risk_ports = {21, 23, 445, 3389, 6379}
    medium_risk_ports = {22, 25, 53, 80, 110, 139, 143, 3306, 5432, 8080}

    if port in high_risk_ports:
        return "High"

    if port in medium_risk_ports:
        return "Medium"

    return "Low"


def get_port_recommendation(port: int, status: str) -> str:
    if status != "open":
        return "No action required based on this basic TCP check."

    return PORT_RECOMMENDATIONS.get(
        port,
        "Review whether this open port is required and restrict access where appropriate.",
    )


def load_targets_from_file(file_path: Path) -> list[str]:
    targets = []

    with file_path.open("r", encoding="utf-8") as file:
        for line in file:
            target = line.strip()

            if not target or target.startswith("#"):
                continue

            targets.append(target)

    return targets


def scan_targets(targets: list[str], ports: list[int], timeout: float) -> list[dict]:
    results = []

    for target in targets:
        for port in ports:
            results.append(check_tcp_port(target, port, timeout))

    return results


def build_report(results: list[dict]) -> dict:
    generated_at = datetime.now(timezone.utc).isoformat()

    open_ports = [item for item in results if item["status"] == "open"]
    high_findings = [item for item in open_ports if item["severity"] == "High"]
    medium_findings = [item for item in open_ports if item["severity"] == "Medium"]
    low_findings = [item for item in open_ports if item["severity"] == "Low"]

    return {
        "tool_name": "Python Network Scanner",
        "generated_at": generated_at,
        "summary": {
            "total_checks": len(results),
            "open_ports": len(open_ports),
            "high": len(high_findings),
            "medium": len(medium_findings),
            "low": len(low_findings),
        },
        "results": results,
    }


def write_csv_report(report: dict, output_dir: Path) -> None:
    output_file = output_dir / "network_scan_report.csv"

    with output_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            "Target",
            "Port",
            "Status",
            "Service Hint",
            "Severity",
            "Recommendation",
        ])

        for result in report["results"]:
            writer.writerow([
                result["target"],
                result["port"],
                result["status"],
                result["service_hint"],
                result["severity"],
                result["recommendation"],
            ])


def write_json_report(report: dict, output_dir: Path) -> None:
    output_file = output_dir / "network_scan_report.json"

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)


def write_findings_json(report: dict, output_dir: Path) -> None:
    output_file = output_dir / "findings.json"
    findings = []

    finding_id = 1

    for result in report["results"]:
        if result["status"] == "open":
            findings.append({
                "id": f"FINDING-{finding_id:03}",
                "name": f"Open TCP Port {result['port']}",
                "target": result["target"],
                "port": result["port"],
                "service_hint": result["service_hint"],
                "severity": result["severity"],
                "details": f"TCP port {result['port']} appears open on {result['target']}.",
                "recommendation": result["recommendation"],
                "status": "Open",
            })
            finding_id += 1

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(findings, file, indent=2)


def write_ndjson_events(report: dict, output_dir: Path) -> None:
    output_file = output_dir / "events.ndjson"

    with output_file.open("w", encoding="utf-8") as file:
        for result in report["results"]:
            event = {
                "timestamp": report["generated_at"],
                "event_type": "tcp_port_check",
                "target": result["target"],
                "port": result["port"],
                "status": result["status"],
                "service_hint": result["service_hint"],
                "severity": result["severity"],
                "message": f"TCP port {result['port']} on {result['target']} returned {result['status']}.",
                "recommendation": result["recommendation"],
            }
            file.write(json.dumps(event) + "\n")


def write_txt_summary(report: dict, output_dir: Path) -> None:
    output_file = output_dir / "network_scan_summary.txt"
    summary = report["summary"]

    lines = [
        "Python Network Scanner Summary",
        "==============================",
        "",
        f"Generated At: {report['generated_at']}",
        f"Total Checks: {summary['total_checks']}",
        f"Open Ports: {summary['open_ports']}",
        f"High Findings: {summary['high']}",
        f"Medium Findings: {summary['medium']}",
        f"Low Findings: {summary['low']}",
        "",
        "Results",
        "-------",
    ]

    for result in report["results"]:
        lines.extend([
            "",
            f"Target: {result['target']}",
            f"Port: {result['port']}",
            f"Status: {result['status']}",
            f"Service Hint: {result['service_hint']}",
            f"Severity: {result['severity']}",
            f"Recommendation: {result['recommendation']}",
        ])

    output_file.write_text("\n".join(lines), encoding="utf-8")


def write_html_report(report: dict, output_dir: Path) -> None:
    output_file = output_dir / "network_scan_report.html"

    def esc(value: object) -> str:
        return html.escape(str(value))

    rows = ""

    for result in report["results"]:
        rows += f"""
        <tr>
          <td>{esc(result["target"])}</td>
          <td>{esc(result["port"])}</td>
          <td>{esc(result["status"])}</td>
          <td>{esc(result["service_hint"])}</td>
          <td>{esc(result["severity"])}</td>
          <td>{esc(result["recommendation"])}</td>
        </tr>
        """

    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Python Network Scanner Report</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      margin: 40px;
      background: #f7f7f7;
      color: #222;
    }}
    .container {{
      max-width: 1200px;
      margin: auto;
      background: #fff;
      padding: 32px;
      border-radius: 12px;
      border: 1px solid #ddd;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
    }}
    th, td {{
      border: 1px solid #ddd;
      padding: 10px;
      vertical-align: top;
      text-align: left;
    }}
    th {{
      background: #f0f0f0;
    }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Python Network Scanner Report</h1>

    <p><strong>Generated At:</strong> {esc(report["generated_at"])}</p>
    <p><strong>Total Checks:</strong> {esc(report["summary"]["total_checks"])}</p>
    <p><strong>Open Ports:</strong> {esc(report["summary"]["open_ports"])}</p>
    <p><strong>High Findings:</strong> {esc(report["summary"]["high"])}</p>
    <p><strong>Medium Findings:</strong> {esc(report["summary"]["medium"])}</p>
    <p><strong>Low Findings:</strong> {esc(report["summary"]["low"])}</p>

    <h2>Results</h2>
    <table>
      <tr>
        <th>Target</th>
        <th>Port</th>
        <th>Status</th>
        <th>Service Hint</th>
        <th>Severity</th>
        <th>Recommendation</th>
      </tr>
      {rows}
    </table>
  </div>
</body>
</html>
"""

    output_file.write_text(content, encoding="utf-8")


def write_reports(report: dict, output_dir: Path, output_format: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    if output_format in ["all", "csv"]:
        write_csv_report(report, output_dir)

    if output_format in ["all", "json"]:
        write_json_report(report, output_dir)
        write_findings_json(report, output_dir)

    if output_format in ["all", "ndjson"]:
        write_ndjson_events(report, output_dir)

    if output_format in ["all", "txt"]:
        write_txt_summary(report, output_dir)

    if output_format in ["all", "html"]:
        write_html_report(report, output_dir)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Authorized TCP network scanner for lab and security assessment workflows."
    )

    parser.add_argument(
        "--target",
        help="Single target to scan. Use only systems you own or are authorized to test.",
    )

    parser.add_argument(
        "--file",
        help="File containing targets to scan.",
    )

    parser.add_argument(
        "--ports",
        default="22,80,443",
        help="Comma-separated ports or ranges. Example: 22,80,443 or 20-25.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="TCP connection timeout in seconds.",
    )

    parser.add_argument(
        "--format",
        choices=["all", "csv", "txt", "json", "ndjson", "html"],
        default="all",
        help="Output format.",
    )

    parser.add_argument(
        "--output",
        default="reports",
        help="Output directory.",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    if not args.target and not args.file:
        print("Please provide --target or --file.")
        return

    if args.target:
        targets = [args.target]
    else:
        targets = load_targets_from_file(Path(args.file))

    ports = parse_ports(args.ports)
    results = scan_targets(targets, ports, args.timeout)
    report = build_report(results)

    output_dir = Path(args.output)
    write_reports(report, output_dir, args.format)

    print("Network scan completed.")
    print(f"Targets scanned: {len(targets)}")
    print(f"Ports checked: {len(ports)}")
    print(f"Open ports: {report['summary']['open_ports']}")
    print(f"Output directory: {output_dir}")


if __name__ == "__main__":
    main()
