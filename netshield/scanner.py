import re
import json
import os

# Load vulnerability patterns from config file
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../config/vulnerabilities.json")

def load_vulnerability_patterns():
    """Loads vulnerability patterns from the configuration file."""
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError("⚠️ Config file not found! Ensure 'config/vulnerabilities.json' exists.")
    except json.JSONDecodeError:
        raise ValueError("⚠️ Error parsing 'vulnerabilities.json'. Check for syntax errors.")

VULNERABILITY_PATTERNS = load_vulnerability_patterns()

def scan_code(code, severity_filter=None):
    """
    Scans code for security vulnerabilities based on loaded patterns.

    Parameters:
        code (str): The source code to scan.
        severity_filter (list, optional): List of severity levels to filter (e.g., ["Critical", "High"]).

    Returns:
        list: List of detected issues or a success message.
    """
    issues = []
    lines = code.split("\n")

    for line_num, line in enumerate(lines, start=1):
        for vuln in VULNERABILITY_PATTERNS:
            if re.search(vuln["pattern"], line):
                if severity_filter and vuln["severity"] not in severity_filter:
                    continue  # Skip if severity filter is applied
                issues.append({
                    "line": line_num,
                    "severity": vuln["severity"],
                    "message": vuln["message"],
                    "code": line.strip()
                })

    return issues if issues else [{"message": "✅ No security vulnerabilities detected!"}]

def generate_scan_report(code, output_file=None, severity_filter=None):
    """
    Runs a scan and returns the results, optionally saving to a JSON report.

    Parameters:
        code (str): Source code to analyze.
        output_file (str, optional): File path for saving the report (default: None).
        severity_filter (list, optional): Filter by severity level.

    Returns:
        list: List of scan results.
    """
    results = scan_code(code, severity_filter)

    if output_file:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        print(f"🔍 Security scan completed! Report saved to {output_file}")

    return results
