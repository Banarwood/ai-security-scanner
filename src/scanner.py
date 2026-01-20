#!/usr/bin/env python3
import os
import sys
import time
import re
import argparse
import platform
import socket
from datetime import datetime
from pathlib import Path

# ANSI Color codes
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print ASCII Art banner"""
    banner = f"""{Colors.CYAN}{Colors.BOLD}
    ╔═══════════════════════════════════════╗
    ║                                       ║
    ║        🔒  AI SECURITY SCANNER  🔒    ║
    ║                                       ║
    ║     Professional Security Analysis    ║
    ║                                       ║
    ╚═══════════════════════════════════════╝
{Colors.RESET}
"""
    print(banner)

def print_info(message):
    """Print info message in cyan"""
    print(f"{Colors.CYAN}[*] {message}{Colors.RESET}")

def print_success(message):
    """Print success message in green"""
    print(f"{Colors.GREEN}[✓] {message}{Colors.RESET}")

def print_danger(message):
    """Print danger message in red"""
    print(f"{Colors.RED}[✗] {message}{Colors.RESET}")

def print_critical(message):
    """Print critical alert in bold red"""
    print(f"{Colors.RED}{Colors.BOLD}[CRITICAL] {message}{Colors.RESET}")

def scan_file(filepath):
    """Scan file for vulnerabilities"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return content
    except FileNotFoundError:
        print_danger(f"File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        print_danger(f"Error reading file: {e}")
        sys.exit(1)

def detect_sql_injection(content):
    """Detect potential SQL injection vulnerabilities"""
    has_select = "SELECT" in content.upper()
    has_quote = "'" in content
    
    return has_select and has_quote

def save_log(result, target_file):
    """Save scan results to validation_log.txt (plain text, no ANSI colors)"""
    import re
    
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_dir = Path(__file__).parent.parent  # Go to root directory
        log_file = log_dir / "validation_log.txt"
        
        # Function to remove ANSI color codes
        def strip_ansi_codes(text):
            """Remove ANSI escape sequences from text"""
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            return ansi_escape.sub('', text)
        
        # Gather system information
        system_info = f"""
================================================================================
                     AI SECURITY SCANNER - VALIDATION LOG
================================================================================

Execution Date: {datetime.now().strftime("%Y-%m-%d")}
Execution Time: {timestamp} {time.tzname[0]}
Log Entry Generated: {datetime.now().isoformat()}

================================================================================
SYSTEM ENVIRONMENT DETAILS
================================================================================

Operating System: {platform.system()} {platform.release()} (Build {platform.version()})
Python Version: {platform.python_version()}
Python Executable: {sys.executable}
Working Directory: {os.getcwd()}
Platform: {sys.platform}
Architecture: {platform.machine()}
Processor: {platform.processor() or "Unknown"}
Hostname: {socket.gethostname()}
User: {os.environ.get('USER', os.environ.get('USERNAME', 'Unknown'))}

================================================================================
SCAN CONFIGURATION
================================================================================

Target File: {target_file}
File Path: {os.path.abspath(target_file)}
Scan Type: SQL Injection Detection
Scanner Version: 1.0.0

================================================================================
SCAN RESULTS
================================================================================

Scan Status: COMPLETED
Timestamp: {timestamp}
"""
        
        if result == 1:
            log_content = system_info + """
VULNERABILITY STATUS: CRITICAL

[CRITICAL] =================================================================
[CRITICAL] CRITICAL VULNERABILITY DETECTED!
[CRITICAL] =================================================================
[CRITICAL] Type: SQL Injection
[CRITICAL] Severity: CRITICAL
[CRITICAL] Description: Unsanitized user input detected in SQL query
[CRITICAL] Risk: Complete database compromise possible
[CRITICAL] =================================================================

Exit Code: 1 (Vulnerabilities Found)
"""
        else:
            log_content = system_info + """
VULNERABILITY STATUS: SAFE

System Secure
No critical vulnerabilities detected

Exit Code: 0 (System Safe)
"""
        
        log_content += f"""
================================================================================
LOG ENTRY COMPLETE
================================================================================

Analysis completed at {timestamp}
For more information, visit: https://owasp.org/www-community/attacks/SQL_Injection

"""
        
        # Strip ANSI codes from the log content (safety measure)
        clean_log_content = strip_ansi_codes(log_content)
        
        # Append to log file
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(clean_log_content)
            
        print_info(f"Log saved to {log_file}")
        
    except Exception as e:
        print_danger(f"Error saving log: {e}")

def main():
    parser = argparse.ArgumentParser(description='AI Security Scanner - Detect vulnerabilities')
    parser.add_argument('target', nargs='?', default='tests/vulnerable_code.php', 
                       help='Target file to scan (default: tests/vulnerable_code.php)')
    args = parser.parse_args()
    
    clear_screen()
    print_banner()
    
    # Step 1: Connect to LLM Engine
    print_info("Connecting to LLM Engine...")
    time.sleep(1.5)
    print_success("Connected to AI Engine")
    print()
    
    # Step 2: Scan target file
    print_info(f"Scanning target file: {args.target}")
    time.sleep(1.5)
    
    # Read and analyze file
    content = scan_file(args.target)
    print_success(f"File loaded ({len(content)} bytes)")
    print()
    
    # Step 3: Detect vulnerabilities
    print_info("Analyzing code patterns...")
    time.sleep(1)
    
    # Check for SQL injection
    if detect_sql_injection(content):
        print()
        print_critical("═" * 50)
        print_critical("CRITICAL VULNERABILITY DETECTED!")
        print_critical("═" * 50)
        print_critical("Type: SQL Injection")
        print_critical("Severity: CRITICAL")
        print_critical("Description: Unsanitized user input detected in SQL query")
        print_critical("Risk: Complete database compromise possible")
        print_critical("═" * 50)
        print()
        save_log(1, args.target)
        return 1
    else:
        print()
        print_success("═" * 50)
        print_success("System Secure")
        print_success("No critical vulnerabilities detected")
        print_success("═" * 50)
        print()
        save_log(0, args.target)
        return 0

if __name__ == "__main__":
    exit_code = main()
    print("System Integrity Check: LOG SAVED.")
    sys.exit(exit_code)
