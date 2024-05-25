# "These are examples of basic functions you can implement. 
# I won't provide a complete script to prevent misuse by script kiddies.
# But so you can see how it works!
import subprocess
import requests

def check_open_ports(domain):
    print("[*] Checking open ports with Nmap...")
    result = subprocess.run(["sudo", "nmap", "-sS", domain], capture_output=True, text=True)
    print(result.stdout)

def check_web_server(domain):
    print("[*] Scanning web server with Nikto...")
    result = subprocess.run(["nikto", "-h", f"http://{domain}"], capture_output=True, text=True)
    print(result.stdout)

def check_ssl(domain):
    print("[*] Checking SSL configuration...")
    result = subprocess.run(["sslscan", domain], capture_output=True, text=True)
    print(result.stdout)

def check_vulnerabilities(domain):
    print("[*] Checking vulnerabilities with OpenVAS...")
    result = subprocess.run(["openvas-cli", "--scan", domain], capture_output=True, text=True)
    print(result.stdout)

def main(domain):
    check_open_ports(domain)
    check_web_server(domain)
    check_ssl(domain)
    check_vulnerabilities(domain)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 server_security_check.py <domain>")
        sys.exit(1)
    domain = sys.argv[1]
    main(domain)
