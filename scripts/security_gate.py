import json
import sys
from pathlib import Path


# Security policy:
# HIGH and CRITICAL findings will fail the pipeline.
BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}


def load_json(file_path):
    """Load a JSON report from a file."""

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)

    except json.JSONDecodeError as error:
        print(f"ERROR: Invalid JSON in {file_path}: {error}")
        return None

    except OSError as error:
        print(f"ERROR: Could not read {file_path}: {error}")
        return None


def normalize_severity(severity):
    """Convert scanner-specific severity values into common values."""

    if not severity:
        return "UNKNOWN"

    severity = str(severity).upper()

    mapping = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }

    return mapping.get(severity, severity)


def parse_bandit(data):
    """Parse findings from a Bandit JSON report."""

    findings = []

    for result in data.get("results", []):
        findings.append(
            {
                "tool": "Bandit",
                "severity": normalize_severity(
                    result.get("issue_severity")
                ),
                "id": result.get("test_id"),
                "message": result.get("issue_text"),
                "file": result.get("filename"),
                "line": result.get("line_number"),
            }
        )

    return findings


def parse_semgrep(data):
    """Parse findings from a Semgrep JSON report."""

    findings = []

    for result in data.get("results", []):
        extra = result.get("extra", {})
        start = result.get("start", {})

        findings.append(
            {
                "tool": "Semgrep",
                "severity": normalize_severity(
                    extra.get("severity")
                ),
                "id": result.get("check_id"),
                "message": extra.get("message"),
                "file": result.get("path"),
                "line": start.get("line"),
            }
        )

    return findings


def parse_trivy(data):
    """Parse vulnerabilities from a Trivy JSON report."""

    findings = []

    for result in data.get("Results", []):

        vulnerabilities = result.get("Vulnerabilities", [])

        for vulnerability in vulnerabilities:
            findings.append(
                {
                    "tool": "Trivy",
                    "severity": normalize_severity(
                        vulnerability.get("Severity")
                    ),
                    "id": vulnerability.get("VulnerabilityID"),
                    "message": vulnerability.get("Title"),
                    "file": result.get("Target"),
                    "line": None,
                }
            )

    return findings


def parse_checkov(data):
    """Parse failed checks from a Checkov JSON report."""

    findings = []

    results = data.get("results", {})

    for check in results.get("failed_checks", []):

        severity = check.get("severity")

        findings.append(
            {
                "tool": "Checkov",
                "severity": normalize_severity(severity),
                "id": check.get("check_id"),
                "message": check.get("check_name"),
                "file": check.get("file_path"),
                "line": check.get("file_line_range"),
            }
        )

    return findings


def parse_report(file_path):
    """Identify the scanner based on the report filename."""

    data = load_json(file_path)

    if data is None:
        return []

    filename = file_path.name.lower()

    if "bandit" in filename:
        return parse_bandit(data)

    if "semgrep" in filename:
        return parse_semgrep(data)

    if "trivy" in filename:
        return parse_trivy(data)

    if "checkov" in filename:
        return parse_checkov(data)

    print(f"WARNING: Unknown report format: {file_path}")

    return []


def print_summary(findings):
    """Print security findings summary."""

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    tool_counts = {}

    for finding in findings:

        severity = finding["severity"]
        tool = finding["tool"]

        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts["UNKNOWN"] += 1

        if tool not in tool_counts:
            tool_counts[tool] = 0

        tool_counts[tool] += 1

    print()
    print("========================================")
    print("Security Gate Summary")
    print("========================================")

    print()
    print("Findings by tool:")

    for tool, count in tool_counts.items():
        print(f"  {tool}: {count}")

    print()
    print("Findings by severity:")

    for severity, count in severity_counts.items():
        print(f"  {severity}: {count}")

    return severity_counts


def main():
    """Main Security Gate execution."""

    reports_directory = Path("reports")

    print("========================================")
    print("Python Security Gate")
    print("========================================")

    if not reports_directory.exists():
        print("ERROR: reports directory does not exist.")
        sys.exit(1)

    report_files = list(
        reports_directory.rglob("*.json")
    )

    if not report_files:
        print("ERROR: No JSON security reports found.")
        sys.exit(1)

    print()
    print("Reports found:")

    for report_file in report_files:
        print(f"  - {report_file}")

    all_findings = []

    print()
    print("Processing reports...")

    for report_file in report_files:

        print(f"  Processing: {report_file}")

        findings = parse_report(report_file)

        all_findings.extend(findings)

    severity_counts = print_summary(all_findings)

    blocking_findings = [
        finding
        for finding in all_findings
        if finding["severity"] in BLOCKING_SEVERITIES
    ]

    print()
    print("========================================")

    if blocking_findings:

        print("SECURITY GATE: FAILED")

        print()
        print("Blocking findings:")

        for finding in blocking_findings:

            print(
                f"  [{finding['severity']}] "
                f"{finding['tool']} "
                f"{finding['id']} "
                f"- {finding['file']}"
            )

        print()
        print(
            "Pipeline blocked because HIGH or CRITICAL "
            "findings were detected."
        )

        sys.exit(1)

    print("SECURITY GATE: PASSED")

    print()
    print(
        "No HIGH or CRITICAL findings were detected."
    )

    sys.exit(0)


if __name__ == "__main__":
    main()