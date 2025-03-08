import dns.resolver
import dns.reversename
import dns.query
import dns.zone
import argparse
import datetime
import os
import threading
import requests
import json
import whois
import random
import queue
import time
from colorama import init, Fore
from tabulate import tabulate
from string import Template
from pathlib import Path  # Use pathlib for cross-platform file paths

# Initialize colorama
init(autoreset=True)
API_KEY = ""

# Stylish Hacker Banner
BANNER = """
 ██████╗ ███╗   ██╗███████╗     █████╗ ██████╗ ██╗
██╔═══██╗████╗  ██║██╔════╝    ██╔══██╗██╔══██╗██║
██║   ██║██╔██╗ ██║█████╗      ███████║██║  ██║██║
██║   ██║██║╚██╗██║██╔══╝      ██╔══██║██║  ██║██║
╚██████╔╝██║ ╚████║███████╗    ██║  ██║██████╔╝███████╗
 ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═╝  ╚═╝╚═════╝ ╚══════╝
=======================================================
   🔥 Multi-threaded DNS Lookup & Reverse Lookup Tool 🔥
       Coded by: Mr. Sami | Stay Anonymous 🕶️
=======================================================
"""

# Folder for storing reports
REPORTS_FOLDER = Path("dns_reports")
REPORTS_FOLDER.mkdir(exist_ok=True)  # Create folder if it doesn't exist

# DNS Record Types
DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "TXT", "SRV", "CAA", "DS", "NSEC", "TLSA", "NAPTR"]

# HTML template for report (UPDATED - Using string.Template)
HTML_TEMPLATE_STRING = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Report - $domain</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #1a1a1a;
            color: #e0e0e0;
            padding: 30px;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            max-width: 1000px;
            width: 95%;
            background: #252525;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.5);
            animation: fadeIn 1s ease-in-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        h1 {
            text-align: center;
            color: #00ff80;
            margin-bottom: 20px;
            text-shadow: 0 0 10px #00ff80;
            letter-spacing: 1px;
            animation: glow 2s infinite alternate;
        }
        @keyframes glow {
            from { text-shadow: 0 0 10px #00ff80; }
            to { text-shadow: 0 0 20px #00ff80, 0 0 30px #00ff80; }
        }
        h2 {
            color: #00bcd4;
            margin-top: 30px;
            border-bottom: 2px solid #00bcd4;
            padding-bottom: 5px;
        }
        p {
            text-align: center;
            color: #ccc;
            margin-bottom: 15px;
        }
        strong {
            color: #fff;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: #333;
            border-radius: 8px;
            overflow: hidden;
            animation: slideIn 1s ease-in-out;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        th, td {
            border: 1px solid #555;
            padding: 12px;
            text-align: left;
            font-size: 0.95em;
        }
        th {
            background: #00ff80;
            color: #222;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        tr:nth-child(even) {
            background: #3a3a3a;
        }
        pre {
            background-color: #333;
            color: #fff;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            white-space: pre-wrap;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            animation: fadeIn 1.5s ease-in-out;
        }
        .report-footer {
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #555;
            color: #888;
            font-size: 0.85em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>DNS Report for $domain</h1>
        <p><strong>Generated on:</strong> $timestamp</p>
        <p><strong>Generated by:</strong> Mr. Sami 🕶️</p>

        <h2>DNS Records</h2>
        <table>
            <tr>
                <th>Record Type</th>
                <th>Value</th>
            </tr>
            $table_rows
        </table>

        <h2>Subdomains</h2>
        <table>
            <tr>
                <th>Subdomain</th>
            </tr>
            $subdomain_rows
        </table>

        <h2>WHOIS Information</h2>
        <pre>$whois_info</pre>

        <div class="report-footer">
            <p>Report generated by DNS Lookup Tool</p>
        </div>
    </div>
</body>
</html>"""

HTML_TEMPLATE = Template(HTML_TEMPLATE_STRING)

# Login Page HTML
LOGIN_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #1a1a1a;
            color: #e0e0e0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background: #252525;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.5);
            animation: fadeIn 1s ease-in-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        h1 {
            text-align: center;
            color: #00ff80;
            margin-bottom: 20px;
            text-shadow: 0 0 10px #00ff80;
            letter-spacing: 1px;
            animation: glow 2s infinite alternate;
        }
        @keyframes glow {
            from { text-shadow: 0 0 10px #00ff80; }
            to { text-shadow: 0 0 20px #00ff80, 0 0 30px #00ff80; }
        }
        input {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            border: 1px solid #555;
            background: #333;
            color: #fff;
        }
        button {
            width: 100%;
            padding: 10px;
            border-radius: 5px;
            border: none;
            background: #00ff80;
            color: #222;
            font-weight: bold;
            cursor: pointer;
        }
        button:hover {
            background: #00cc66;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Login</h1>
        <form id="loginForm">
            <input type="text" id="username" placeholder="Username" required>
            <input type="password" id="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', function(event) {
            event.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            if (username === 'sami' && password === 'hisamad') {
                window.location.href = '$report_file';
            } else {
                alert('Invalid username or password');
            }
        });
    </script>
</body>
</html>"""


def generate_login_page(report_file):
    login_path = REPORTS_FOLDER / "login.html"
    login_content = Template(LOGIN_PAGE_HTML).substitute(report_file=report_file)
    with open(login_path, "w", encoding="utf-8") as file:
        file.write(login_content)
    print(Fore.MAGENTA + f"\n[✔] Login Page saved at: {login_path}")


def generate_html_report(domain, records_queue):
    records_list = list(records_queue.queue)
    if not records_list:
        print(Fore.YELLOW + "\n[!] No valid records to generate report.")
        return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    table_rows_html = "".join(f"<tr><td>{record_type}</td><td>{value}</td></tr>\n" for record_type, value in records_list if record_type not in ["Subdomain", "Brute Subdomain", "WHOIS"])  # Exclude subdomain and whois from main table
    subdomain_rows_html = "".join(f"<tr><td>{value}</td></tr>\n" for record_type, value in records_list if record_type in ["Subdomain", "Brute Subdomain"])
    whois_info_text = next((value for record_type, value in records_list if record_type == "WHOIS"), "No WHOIS information found.")

    template_vars = {
        'domain': domain,
        'timestamp': timestamp,
        'table_rows': table_rows_html,
        'subdomain_rows': subdomain_rows_html,
        'whois_info': whois_info_text,
    }

    report_path = REPORTS_FOLDER / f"{domain}_dns_report.html"
    try:
        html_content = HTML_TEMPLATE.substitute(template_vars)
        with open(report_path, "w", encoding="utf-8") as file:
            file.write(html_content)
        print(Fore.MAGENTA + f"\n[✔] HTML Report saved at: {report_path}")
        generate_login_page(f"{domain}_dns_report.html")
    except KeyError as e:
        print(Fore.RED + f"[-] Error generating HTML report due to KeyError in template: {e}")
    except Exception as e:
        print(Fore.RED + f"[-] Error saving HTML report: {e}")


def load_proxies(proxy_file):
    if not proxy_file:
        return None
    try:
        with open(proxy_file, "r") as f:
            proxies = [line.strip() for line in f if line.strip()]
        if proxies:
            print(Fore.CYAN + f"[*] Loaded {len(proxies)} proxies from {proxy_file}")
            return proxies
        else:
            print(Fore.YELLOW + "[-] Proxy file is empty.")
            return None
    except FileNotFoundError:
        print(Fore.RED + f"[-] Proxy file not found: {proxy_file}")
        return None
    except Exception as e:
        print(Fore.RED + f"[-] Error loading proxies: {e}")
        return None


def get_proxy(proxies):
    if proxies:
        proxy = random.choice(proxies)
        print(Fore.CYAN + f"[*] Using proxy: {proxy}")
        return {"http": proxy, "https": proxy}
    return None


# Function to get all DNS records
def get_dns_records(domain, records_queue):
    print(Fore.CYAN + f"\n[*] Starting DNS Record Fetching for {domain}...")
    resolver = dns.resolver.Resolver()  # Create resolver instance here, each thread gets its own
    for record_type in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type)  # Use the local resolver
            for answer in answers:
                print(Fore.GREEN + f"[+] {record_type}: {answer}")
                records_queue.put((record_type, str(answer)))
        except dns.resolver.NoAnswer:
            print(Fore.YELLOW + f"[-] No {record_type} record found for {domain}")
        except dns.resolver.NXDOMAIN:
            print(Fore.YELLOW + f"[-] Domain {domain} does not exist.")
            return  # Exit if domain doesn't exist, no point in continuing other lookups
        except Exception as e:
            print(Fore.RED + f"[-] Error fetching {record_type} record: {e}")


# Reverse DNS Lookup
def reverse_lookup(ip, records_queue):
    print(Fore.CYAN + f"\n[*] Starting Reverse DNS Lookup for IP: {ip}...")
    try:
        rev_name = dns.reversename.from_address(ip)
        answer = dns.resolver.resolve(rev_name, "PTR")
        for ans in answer:
            print(Fore.GREEN + f"[+] PTR: {ans}")
            records_queue.put(("PTR", str(ans)))
    except dns.resolver.NXDOMAIN:
        print(Fore.YELLOW + f"[-] No PTR record found for {ip}")
    except Exception as e:
        print(Fore.RED + f"[-] Reverse lookup failed for {ip}: {e}")


# Reverse IP Domain Check using viewdns.info
def reverse_ip_lookup(ip, records_queue, proxies=None):
    print(Fore.CYAN + f"\n[*] Starting Reverse IP Domain Check (viewdns.info) for IP: {ip}...")
    try:
        url = f"https://api.viewdns.info/reverseip/?host={ip}&apikey={API_KEY}&output=json"
        response = requests.get(url, proxies=get_proxy(proxies), timeout=10)  # Added timeout
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        # Check if the response contains valid data
        if 'response' in data and 'domain_count' in data['response']:
            domain_count = int(data['response']['domain_count'])
            if domain_count > 0:
                for domain_data in data['response']['domains']:  # Correctly iterate through the domains list
                    if isinstance(domain_data, dict) and 'name' in domain_data:  # Check if domain_data is a dict and has 'name' key
                        domain_name = domain_data['name']
                        print(Fore.GREEN + f"[+] Reverse IP Domain (viewdns.info): {domain_name}")
                        records_queue.put(("Reverse IP Domain", domain_name))
                    else:
                        print(Fore.YELLOW + "[-] Unexpected data format in viewdns.info response for domains.")
            else:
                print(Fore.RED + "[-] No domains found for this IP via viewdns.info.")
        else:
            print(Fore.RED + "[-] Invalid response format from viewdns.info API.")
    except requests.exceptions.HTTPError as e:
        print(Fore.RED + f"[-] HTTP error during Reverse IP Domain Check (viewdns.info): {e}")
    except requests.exceptions.ConnectionError as e:
        print(Fore.RED + f"[-] Connection error during Reverse IP Domain Check (viewdns.info): {e}")
    except requests.exceptions.Timeout as e:
        print(Fore.RED + f"[-] Timeout error during Reverse IP Domain Check (viewdns.info): {e}")
    except json.JSONDecodeError as e:
        print(Fore.RED + f"[-] JSON decode error from viewdns.info: {e}")
    except Exception as e:
        print(Fore.RED + f"[-] Error during Reverse IP Domain Check (viewdns.info): {e}")


# Subdomain Enumeration using crt.sh
def enumerate_subdomains(domain, records_queue, proxies=None):
    print(Fore.CYAN + f"\n[*] Starting Subdomain Enumeration using crt.sh for {domain}...")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, proxies=get_proxy(proxies), timeout=10)  # Added timeout
        response.raise_for_status()  # Raise HTTPError for bad responses
        if response.status_code == 200:
            try:
                subdomains_data = response.json()
                if isinstance(subdomains_data, list):
                    unique_subdomains = set()
                    for entry in subdomains_data:
                        if isinstance(entry, dict) and 'name_value' in entry and isinstance(entry['name_value'], str):
                            subdomain = entry['name_value'].lower()  # Normalize subdomain to lowercase
                            if subdomain.endswith(domain):  # Ensure it's really a subdomain
                                unique_subdomains.add(subdomain)
                    for sub in sorted(list(unique_subdomains)):  # Sort subdomains for better readability
                        print(Fore.GREEN + f"[+] crt.sh Subdomain Found: {sub}")
                        records_queue.put(("Subdomain", sub))
                else:
                    print(Fore.YELLOW + "[-] No subdomains found or invalid response format from crt.sh.")

            except json.JSONDecodeError:
                print(Fore.RED + "[-] Failed to decode JSON response from crt.sh. Invalid JSON format.")

        else:
            print(Fore.RED + f"[-] Failed to fetch subdomains from crt.sh! Status code: {response.status_code}")
    except requests.exceptions.HTTPError as e:
        print(Fore.RED + f"[-] HTTP error during crt.sh subdomain enumeration: {e}")
    except requests.exceptions.ConnectionError as e:
        print(Fore.RED + f"[-] Connection error during crt.sh subdomain enumeration: {e}")
    except requests.exceptions.Timeout as e:
        print(Fore.RED + f"[-] Timeout error during crt.sh subdomain enumeration: {e}")
    except Exception as e:
        print(Fore.RED + f"[-] Error fetching subdomains from crt.sh: {e}")


# Brute Force Subdomain Enumeration with Multi-threading
def brute_force_subdomains(domain, records_queue, num_threads=100):
    print(Fore.CYAN + f"\n[*] Starting Brute-Force Subdomain Enumeration for {domain} with {num_threads} threads...")
    wordlist_path = Path("wordlist/wordlist.txt")
    if not wordlist_path.exists():
        print(Fore.RED + "[-] Wordlist file not found: wordlist/wordlist.txt. Please ensure 'wordlist' folder and 'wordlist.txt' exist in the same directory as the script.")
        return

    try:
        with open(wordlist_path, "r") as f:
            wordlist = f.read().splitlines()
    except Exception as e:
        print(Fore.RED + f"[-] Error reading wordlist file: {e}")
        return

    total_subdomains = len(wordlist)
    subdomains_per_thread = total_subdomains // num_threads + (1 if total_subdomains % num_threads else 0)
    threads = []

    def check_subdomains_chunk(subdomains_chunk, domain_name, record_q):  # Pass domain_name and record_q
        resolver = dns.resolver.Resolver()
        for sub in subdomains_chunk:
            subdomain = f"{sub}.{domain_name}"  # Use domain_name from args
            try:
                resolver.resolve(subdomain, "A")
                print(Fore.GREEN + f"[+] Brute-Force Subdomain Found: {subdomain}")
                record_q.put(("Brute Subdomain", subdomain))  # Use record_q from args
            except dns.resolver.NXDOMAIN:
                pass  # Expected for many subdomains
            except Exception as e:
                print(Fore.YELLOW + f"[-] Error resolving {subdomain}: {e}")  # Log errors, but continue brute-forcing

    for i in range(num_threads):
        start_index = i * subdomains_per_thread
        end_index = min((i + 1) * subdomains_per_thread, total_subdomains)
        subdomains_chunk = wordlist[start_index:end_index]
        if subdomains_chunk:
            thread = threading.Thread(target=check_subdomains_chunk, args=(subdomains_chunk, domain, records_queue))  # Pass domain and records_queue
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()


# WHOIS Lookup
def get_whois_info(domain, records_queue, proxies=None):
    print(Fore.CYAN + f"\n[*] Starting WHOIS Lookup for {domain}...")
    try:
        w = whois.whois(domain)
        records_queue.put(("WHOIS", str(w)))
        print(Fore.GREEN + "[+] WHOIS lookup completed.")
    except whois.parser.PywhoisError as e:  # Catch specific whois parsing errors
        print(Fore.YELLOW + f"[-] WHOIS lookup might be limited or failed due to WHOIS service error: {e}")
        records_queue.put(("WHOIS", f"Lookup failed or limited: {e}"))  # Still add something to report
    except Exception as e:
        print(Fore.RED + f"[-] WHOIS lookup failed: {e}")
        records_queue.put(("WHOIS", f"Lookup failed: {e}"))  # Add failure info to report


# Check DNSSEC support
def check_dnssec(domain, records_queue):
    print(Fore.CYAN + f"\n[*] Starting DNSSEC Support Check for {domain}...")
    try:
        answers = dns.resolver.resolve(domain, "DNSKEY", raise_on_no_answer=False)  # Don't raise exception if no answer
        if answers.rrset:  # Check if rrset exists instead of just answers
            print(Fore.GREEN + f"[+] {domain} supports DNSSEC")
            records_queue.put(("DNSSEC", "Supported"))
        else:
            print(Fore.RED + "[-] DNSSEC not supported!")  # Explicitly say not supported if no rrset
            records_queue.put(("DNSSEC", "Not Supported"))
    except dns.resolver.NXDOMAIN:
        print(Fore.YELLOW + f"[-] Domain {domain} does not exist, cannot check DNSSEC.")  # Informative message for NXDOMAIN
        records_queue.put(("DNSSEC", "Domain not found, cannot check"))
    except Exception as e:
        print(Fore.RED + f"[-] Error checking DNSSEC for {domain}: {e}")
        records_queue.put(("DNSSEC", f"Check failed: {e}"))


# Check for SPF record
def check_spf(domain, records_queue):
    print(Fore.CYAN + f"\n[*] Starting SPF Record Check for {domain}...")
    spf_found = False
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for answer in answers:
            txt_record = str(answer).lower()  # Normalize to lowercase for case-insensitive check
            if "v=spf1" in txt_record:
                print(Fore.GREEN + f"[+] SPF Record Found: {answer}")
                records_queue.put(("SPF", str(answer)))
                spf_found = True
                return
    except dns.resolver.NXDOMAIN:
        print(Fore.YELLOW + f"[-] Domain {domain} does not exist, cannot check SPF.")
    except dns.resolver.NoAnswer:  # Catch NoAnswer for TXT records specifically
        print(Fore.RED + "[-] No SPF record found!")
    except Exception as e:
        print(Fore.RED + f"[-] Error checking SPF record: {e}")

    if not spf_found:
        if 'dns.resolver.NoAnswer' not in str(e if 'e' in locals() else ''):  # Avoid double "No SPF record found" if NoAnswer was already handled
            print(Fore.RED + "[-] No SPF record found!")


# Check for Zone Transfer
def check_zone_transfer(domain, records_queue):
    print(Fore.CYAN + f"\n[*] Starting Zone Transfer Check for {domain}...")
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        for ns in ns_records:
            ns_server = str(ns)
            print(Fore.CYAN + f"[*] Trying Zone Transfer on NS server: {ns_server}...")
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns_server, domain, timeout=2))
                print(Fore.GREEN + f"[+] Zone Transfer Successful on {ns_server}!")
                records_queue.put(("Zone Transfer", f"Success on {ns_server}"))
                return  # Exit after successful zone transfer
            except dns.exception.Timeout:
                print(Fore.YELLOW + f"[-] Zone Transfer timed out on {ns_server}.")
            except dns.query.TransferError as e:
                print(Fore.YELLOW + f"[-] Zone Transfer failed on {ns_server}: {e}")
            except Exception as e:
                print(Fore.YELLOW + f"[-] Error checking Zone Transfer on {ns_server}: {e}")

        print(Fore.RED + "[-] Zone Transfer not allowed or failed on all NS servers!")
        records_queue.put(("Zone Transfer", "Failed on all NS servers"))  # Record failure in report
    except dns.resolver.NXDOMAIN:
        print(Fore.YELLOW + f"[-] Domain {domain} does not exist, cannot check zone transfer.")
        records_queue.put(("Zone Transfer", "Domain not found, cannot check"))
    except Exception as e:
        print(Fore.RED + f"[-] Could not check Zone Transfer: {e}")
        records_queue.put(("Zone Transfer", f"Check error: {e}"))


# Display results in terminal
def display_table(records_queue):
    records_list = list(records_queue.queue)
    if records_list:
        print(Fore.MAGENTA + f"\n{tabulate(records_list, headers=['Record Type', 'Value'], tablefmt='grid')}")
    else:
        print(Fore.RED + "\n[-] No records found!")


# Generate JSON Report
def generate_json_report(domain, records_queue):
    records_list = list(records_queue.queue)
    if not records_list:
        print(Fore.YELLOW + "\n[!] No valid records to generate report.")
        return

    report_path = REPORTS_FOLDER / f"{domain}_dns_report.json"
    try:
        with open(report_path, "w") as f:
            json.dump(records_list, f, indent=4)
        print(Fore.MAGENTA + f"\n[✔] JSON Report saved at: {report_path}")
    except Exception as e:
        print(Fore.RED + f"[-] Error saving JSON report: {e}")


# Function to process a single domain with multi-threading
def process_domain(domain, proxies=None):
    try:
        start_time = time.time()
        records_queue = queue.Queue()
        try:  # Resolve A record specifically to check domain validity upfront
            ip_answers = dns.resolver.resolve(domain, "A")
            ip = ip_answers[0] if ip_answers else None
        except dns.resolver.NXDOMAIN:
            print(Fore.RED + f"[-] Domain {domain} does not exist. Skipping IP-based lookups.")
            ip = None  # Set IP to None to skip IP-based lookups

        if ip:
            print(Fore.GREEN + f"\n[+] IP Address Found: {ip}")

            threads = [
                threading.Thread(target=get_dns_records, args=(domain, records_queue)),
                threading.Thread(target=reverse_lookup, args=(str(ip), records_queue)),
                threading.Thread(target=reverse_ip_lookup, args=(str(ip), records_queue, proxies)),
                threading.Thread(target=enumerate_subdomains, args=(domain, records_queue, proxies)),
                threading.Thread(target=brute_force_subdomains, args=(domain, records_queue, 100)),
                threading.Thread(target=get_whois_info, args=(domain, records_queue)),
                threading.Thread(target=check_dnssec, args=(domain, records_queue)),
                threading.Thread(target=check_spf, args=(domain, records_queue)),
                threading.Thread(target=check_zone_transfer, args=(domain, records_queue))
            ]
        else:  # If no IP (NXDOMAIN or other resolution error for A record)
            print(Fore.YELLOW + f"[-] Could not resolve A record for {domain}. Proceeding with non-IP lookups only.")
            records_queue = queue.Queue()  # Ensure a new queue even if domain resolution failed
            threads = [
                threading.Thread(target=get_dns_records, args=(domain, records_queue)),  # Still get other DNS records even if A fails
                threading.Thread(target=enumerate_subdomains, args=(domain, records_queue, proxies)),
                threading.Thread(target=brute_force_subdomains, args=(domain, records_queue, 100)),
                threading.Thread(target=get_whois_info, args=(domain, records_queue)),
                threading.Thread(target=check_dnssec, args=(domain, records_queue)),
                threading.Thread(target=check_spf, args=(domain, records_queue)),
                threading.Thread(target=check_zone_transfer, args=(domain, records_queue))
            ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        display_table(records_queue)
        generate_html_report(domain, records_queue)
        generate_json_report(domain, records_queue)

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(Fore.CYAN + f"\n[*] Total Scan Time: {elapsed_time:.2f} seconds")

    except Exception as e:
        print(Fore.RED + f"[-] Could not process {domain}: {e}")


# Main Function
def main():
    print(Fore.CYAN + BANNER)
    parser = argparse.ArgumentParser(description="Multi-threaded DNS Lookup & Reverse Lookup Tool")
    parser.add_argument("-t", "--target", help="Single target domain for DNS lookup")
    parser.add_argument("-m", "--multiple", help="Comma-separated multiple domains for DNS lookup")
    parser.add_argument("-p", "--proxy", help="File containing proxy list", default=None)

    args = parser.parse_args()

    domains = []
    if args.target:
        domains.append(args.target)
    if args.multiple:
        domains.extend(args.multiple.split(","))

    if not domains:
        print(Fore.RED + "[!] Please provide at least one domain using -t or -m")
        return

    proxies = load_proxies(args.proxy)
    threads = []
    for domain in domains:
        thread = threading.Thread(target=process_domain, args=(domain, proxies))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()