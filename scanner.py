import requests
import socket
import threading
import argparse
from colorama import Fore, init
init()

print("\n=== Website Security Scanner ===")

report = open("scan_report.txt", "w")

results = []


# Get website from user
parser = argparse.ArgumentParser(description="Website Security Scanner")

parser.add_argument(
    "--target",
    help="Target website domain (example.com)"
)

args = parser.parse_args()

if args.target:
    target = args.target
else:
    target = input("Enter website (example.com): ").strip()


print("\nTarget:", target)

# Convert domain to IP
try:
    target_ip = socket.gethostbyname(target)
except:
    print("Invalid website or unable to resolve domain.")
    exit()

print("\nTarget:", target)
print("IP Address:", target_ip)

# Check HTTPS support
print("\nChecking HTTPS support...")
try:
    response = requests.get("https://" + target, timeout=5)
    print(Fore.GREEN + "✓ HTTPS supported")
    results.append("HTTPS supported")
    report.write("HTTPS supported\n")

except:
    print(Fore.RED + "✗ HTTPS not supported")
    report.write("HTTPS not supported\n")


# Check security headers
print("\nChecking security headers...")

try:
    headers = response.headers

    if "X-Frame-Options" in headers:
        print("✓ X-Frame-Options present")
    else:
        print("✗ Missing X-Frame-Options")

    if "Content-Security-Policy" in headers:
        print("✓ Content-Security-Policy present")
    else:
        print("✗ Missing Content-Security-Policy")

    if "Strict-Transport-Security" in headers:
        print("✓ Strict-Transport-Security present")
    else:
        print("✗ Missing Strict-Transport-Security")

except:
    print("Header check failed")

# Scan common ports
print("\nScanning common ports...")

for port in [80, 443]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)

# Subdomain discovery
print("\nScanning common subdomains...")

subdomains = [
    "www",
    "mail",
    "admin",
    "blog",
    "test",
    "dev",
    "api",
    "shop"
]

for sub in subdomains:
    url = sub + "." + target

    try:
        socket.gethostbyname(url)
        print(Fore.GREEN + "Found subdomain: " + url)
        results.append("Subdomain found: " + url)

        report.write("Subdomain found: " + url + "\n")

    except:
        pass
# Directory discovery
print("\nScanning common directories...")

directories = [
    "admin",
    "login",
    "dashboard",
    "api",
    "uploads",
    "test",
    "dev"
]

def scan_directory(directory):
     url = "https://" + target + "/" + directory

     try:
        r = requests.get(url, timeout=3)

        if r.status_code == 200:
            print(Fore.GREEN + "Found directory: /" + directory)
            results.append("Directory found: /" + directory)

            report.write("Directory found: /" + directory + "\n")


     except:
        pass
threads = []

for directory in directories:
    t = threading.Thread(target=scan_directory, args=(directory,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()


# Directory scanning code above here...

# Basic vulnerability testing
print("\nChecking basic vulnerabilities...")

sql_payloads = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1"
]

xss_payloads = [
    "<script>alert(1)</script>",
    "\" onmouseover=\"alert(1)"
]

# SQL Injection test
print("\nTesting for SQL injection indicators...")

for payload in sql_payloads:
    try:
        url = "https://" + target + "/?id=" + payload
        r = requests.get(url, timeout=3)

        if "sql" in r.text.lower() or "syntax" in r.text.lower():
            print("Possible SQL injection vulnerability with payload:", payload)
            results.append("Possible SQL injection indicator")

            report.write("Possible SQL injection indicator detected\n")
            break

    except:
        pass


# XSS reflection test
print("\nTesting for reflected XSS...")

for payload in xss_payloads:
    try:
        url = "https://" + target + "/?q=" + payload
        r = requests.get(url, timeout=3)

        if payload in r.text:
            print("Possible reflected XSS with payload:", payload)
            report.write("Possible XSS reflection detected\n")
            break

    except:
        pass
   

print("\nScan completed.")

report.close()
print("Report saved to scan_report.txt")

# Generate HTML report
html = "<html><head><title>Security Scan Report</title></head><body>"
html += "<h1>Website Security Scan Report</h1>"
html += "<h2>Target: " + target + "</h2>"
html += "<ul>"

for item in results:
    html += "<li>" + item + "</li>"

html += "</ul>"
html += "</body></html>"

with open("scan_report.html", "w") as f:
    f.write(html)

print("HTML report saved to scan_report.html")

