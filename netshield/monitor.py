import re

def monitor_api(log_file):
    """Monitors API logs for malicious requests like SQL injections."""
    threats = []
    
    with open(log_file, 'r') as logs:
        for line in logs:
            if re.search(r"(SELECT|INSERT|DELETE|UPDATE)\s+.*\s+FROM\s+.*\s+WHERE\s+.*=.*['\"].*['\"]", line, re.IGNORECASE):
                threats.append(f"🚨 SQL injection attempt detected: {line.strip()}")
    
    return threats if threats else ["✅ No threats detected in API logs."]
