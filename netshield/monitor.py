# netshield/monitor.py
import re
import logging
import argparse
from datetime import datetime
import time
import sys

# Configure logging for threat alerts
logging.basicConfig(
    filename='threats.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

THREAT_PATTERNS = [
    # SQL Injection
    {
        'name': 'SQL Injection',
        'pattern': r"(SELECT|INSERT|DELETE|UPDATE)\s+.*\s+FROM\s+.*\s+WHERE\s+.*=.*['\"].*['\"]",
        'severity': 'ERROR'
    },
    # Cross-Site Scripting (XSS)
    {
        'name': 'XSS Attack',
        'pattern': r"<(script|iframe).*>|alert\(|onerror\s*=",
        'severity': 'ERROR'
    },
    # Path Traversal
    {
        'name': 'Path Traversal',
        'pattern': r"(\.\./|\.\.\\)|(/etc/passwd|/bin/sh)",
        'severity': 'WARNING'
    },
    # Unauthorized Access (401/403 status codes)
    {
        'name': 'Unauthorized Access',
        'pattern': r'\s403\s|\s401\s',
        'severity': 'WARNING'
    },
    # Sensitive Data Exposure (Credit Cards/API Keys)
    {
        'name': 'Data Exposure',
        'pattern': r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b|(api|bearer)_?key[\w:]*=([\'\"]?[\w]{32,}[\'\"]?)",
        'severity': 'CRITICAL'
    },
    # Command Injection
    {
        'name': 'Command Injection',
        'pattern': r";\s*(rm|wget|curl)|\\\|\s*(\||<)",
        'severity': 'ERROR'
    }
]

def monitor_api(log_file: str, last_position: int = 0) -> dict:
    """
    Monitors API logs for security threats with enhanced detection capabilities.
    Returns threats and new file position for continuous monitoring.
    """
    threats = []
    current_position = last_position

    try:
        with open(log_file, 'r') as logs:
            logs.seek(last_position)
            
            for line in logs:
                for threat in THREAT_PATTERNS:
                    if re.search(threat['pattern'], line, re.IGNORECASE):
                        alert = f"[{threat['severity']}] {threat['name']}: {line.strip()}"
                        threats.append(alert)
                        logging.log(
                            getattr(logging, threat['severity']),
                            alert
                        )
            
            current_position = logs.tell()

        # Generate report if threats found
        report_path = None
        if threats:
            report_path = generate_report(threats)
            threats.append(f"📄 Full report: {report_path}")
        else:
            threats.append("✅ No threats detected")
        
        return {
            'threats': threats,
            'new_position': current_position,
            'report': report_path
        }

    except FileNotFoundError:
        error = "❌ Error: Log file not found"
        logging.error(error)
        return {
            'threats': [error],
            'new_position': current_position,
            'report': None
        }

def generate_report(threats: list) -> str:
    """Generates timestamped threat report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"threat_report_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write(f"NetShield Threat Report ({timestamp})\n")
        f.write("="*40 + "\n")
        f.write("\n".join(threat for threat in threats if not threat.startswith("📄")))
    
    return filename

def view_threat_logs(severity: str = None):
    """View threat logs with optional severity filtering"""
    try:
        with open('threats.log', 'r') as log_file:
            for line in log_file:
                if not severity or severity.upper() in line:
                    print(line.strip())
    except FileNotFoundError:
        print("No threat logs found. Monitoring must be run first.")

def continuous_monitoring(log_file: str, interval: int = 10):
    """Continuous monitoring with configurable check interval"""
    last_position = 0
    print(f"🚀 Starting NetShield monitoring on {log_file} (Ctrl+C to stop)")
    
    try:
        while True:
            result = monitor_api(log_file, last_position)
            last_position = result['new_position']
            
            print("\n" + "="*40)
            print(f"🕒 Check at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            for threat in result['threats']:
                print(threat)
            
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n🔴 Monitoring stopped")

def main():
    """Command-line interface for NetShield"""
    parser = argparse.ArgumentParser(description="NetShield Cybersecurity Monitor")
    group = parser.add_mutually_exclusive_group()
    
    group.add_argument('--monitor', action='store_true',
                      help='Start continuous monitoring')
    group.add_argument('--view-logs', action='store_true',
                      help='View threat logs')
    
    parser.add_argument('--log', type=str,
                      help='Log file to monitor')
    parser.add_argument('--interval', type=int, default=10,
                      help='Monitoring interval in seconds (default: 10)')
    parser.add_argument('--severity', type=str,
                      choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO'],
                      help='Filter logs by severity level')
    
    args = parser.parse_args()

    if args.monitor:
        if not args.log:
            print("Error: Must specify --log for monitoring")
            sys.exit(1)
        continuous_monitoring(args.log, args.interval)
    elif args.view_logs:
        view_threat_logs(args.severity)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

# Detects 6+ threat types using regex patterns

# To run use these commands

# Start monitoring (use correct --log argument)
# Check every 1 second
# python monitor.py --monitor --log /var/logs/api.log --interval 1

# View critical threat logs
# python monitor.py --view-logs --severity CRITICAL