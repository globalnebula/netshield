import re

def scan_code(code):
    """Scans code for security vulnerabilities like hardcoded secrets and SQL injections."""
    issues = []

    # Check for hardcoded credentials
    if re.search(r'password\s*=\s*[\'"].+[\'"]', code, re.IGNORECASE):
        issues.append("⚠️ Hardcoded password detected!")

    # Check for SQL Injection vulnerabilities
    if re.search(r"(SELECT|INSERT|DELETE|UPDATE)\s+.*\s+FROM\s+.*\s+WHERE\s+.*=.*['\"].*['\"]", code, re.IGNORECASE):
        issues.append("🚨 Potential SQL Injection vulnerability detected!")

    return issues if issues else ["✅ No security issues found!"]

