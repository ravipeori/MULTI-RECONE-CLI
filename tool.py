#!/usr/bin/env python3
import socket
import threading
import argparse
import requests
import json
import subprocess
import whois
import sys
from queue import Queue

# --------------------------
# Port Scanner + Banner Grab
# --------------------------
def scan_port(target, port, results, banner=False):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((target, port))
        result = f"[OPEN] {target}:{port}"
        if banner:
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner_data = s.recv(1024).decode(errors="ignore")
                result += f" | Banner: {banner_data.strip().splitlines()[0]}"
            except:
                result += " | Banner: Unknown"
        results.append(result)
        s.close()
    except:
        pass

def run_scanner(target, start_port, end_port, threads, banner):
    results = []
    queue = Queue()

    def worker():
        while not queue.empty():
            port = queue.get()
            scan_port(target, port, results, banner)
            queue.task_done()

    for port in range(start_port, end_port + 1):
        queue.put(port)

    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.start()

    queue.join()
    return results

# --------------------------
# Subdomain Finder
# --------------------------
def subdomain_finder(domain, wordlist=None):
    found = []
    subs = ["www", "mail", "ftp", "test", "dev", "api", "admin"]
    if wordlist:
        try:
            with open(wordlist, "r") as f:
                subs += [line.strip() for line in f if line.strip()]
        except:
            pass
    for sub in set(subs):
        url = f"{sub}.{domain}"
        try:
            socket.gethostbyname(url)
            found.append(url)
        except:
            pass
    return found

# --------------------------
# Reverse DNS
# --------------------------
def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Not found"

# --------------------------
# WHOIS Lookup
# --------------------------
def whois_lookup(domain):
    try:
        return str(whois.whois(domain))
    except:
        return "WHOIS lookup failed"

# --------------------------
# OS Fingerprinting (TTL)
# --------------------------
def os_fingerprint(target):
    try:
        result = subprocess.run(["ping", "-n", "1", target], capture_output=True, text=True)
        if "ttl=" in result.stdout.lower():
            ttl = int(result.stdout.lower().split("ttl=")[1].split()[0])
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Unknown OS"
    except:
        return "OS detection failed"

# --------------------------
# Traceroute
# --------------------------
def traceroute(target):
    try:
        result = subprocess.run(["tracert", target], capture_output=True, text=True)
        return result.stdout
    except:
        return "Traceroute not available"

# --------------------------
# HTTP Headers
# --------------------------
def grab_headers(target):
    try:
        url = f"http://{target}"
        r = requests.get(url, timeout=3)
        return dict(r.headers)
    except:
        return {}

# --------------------------
# Directory Bruteforcing
# --------------------------
def dir_bruteforce(target):
    found = []
    paths = ["admin", "login", "dashboard", "uploads", "images"]
    for path in paths:
        url = f"http://{target}/{path}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                found.append(url)
        except:
            pass
    return found

# --------------------------
# GeoIP Lookup
# --------------------------
def geoip_lookup(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        r = requests.get(url).json()
        return f"{r.get('country')}, {r.get('city')} | ISP: {r.get('isp')}"
    except:
        return "GeoIP lookup failed."

# --------------------------
# Save Results
# --------------------------
def save_results(data, filename):
    with open(filename + ".json", "w") as f:
        json.dump(data, f, indent=4)
    with open(filename + ".txt", "w") as f:
        for k, v in data.items():
            f.write(f"{k}:\n{v}\n\n")

# --------------------------
# Main CLI
# --------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Combined Recon & Scanning Tool")
    parser.add_argument("-t", "--target", required=True, help="Target host (IP or domain)")
    parser.add_argument("-sp", "--start-port", type=int, default=1, help="Start port")
    parser.add_argument("-ep", "--end-port", type=int, default=100, help="End port")
    parser.add_argument("-th", "--threads", type=int, default=50, help="Threads for scanning")
    parser.add_argument("-b", "--banner", action="store_true", help="Enable banner grabbing")
    parser.add_argument("-s", "--subdomains", help="Subdomain wordlist file")
    parser.add_argument("-o", "--output", help="Save results with filename prefix")
    parser.add_argument("-w", "--whois", action="store_true", help="Enable WHOIS lookup")
    parser.add_argument("-rd", "--reversedns", action="store_true", help="Enable reverse DNS lookup")
    parser.add_argument("-os", "--osdetect", action="store_true", help="Enable OS fingerprinting")
    parser.add_argument("-tr", "--traceroute", action="store_true", help="Run traceroute")
    parser.add_argument("--headers", action="store_true", help="Grab HTTP headers")
    parser.add_argument("--dirs", action="store_true", help="Directory brute force")
    parser.add_argument("--geoip", action="store_true", help="GeoIP lookup")
    parser.add_argument("--full", action="store_true", help="Run all modules")

    args = parser.parse_args()
    final_results = {}

    # Resolve domain to IP
    try:
        ip = socket.gethostbyname(args.target)
    except:
        print("[!] Could not resolve target.")
        sys.exit()

    # Port Scan
    if args.full or args.start_port or args.end_port:
        scan_results = run_scanner(args.target, args.start_port, args.end_port, args.threads, args.banner)
        final_results["Port Scan"] = scan_results
        for r in scan_results:
            print(r)

    # Subdomain Scan
    if args.full or args.subdomains:
        subs = subdomain_finder(args.target, args.subdomains)
        final_results["Subdomains"] = subs
        print("[+] Subdomains Found:", subs)

    # Reverse DNS
    if args.full or args.reversedns:
        rdns = reverse_dns(ip)
        final_results["ReverseDNS"] = rdns
        print("[+] Reverse DNS:", rdns)

    # WHOIS
    if args.full or args.whois:
        w = whois_lookup(args.target)
        final_results["WHOIS"] = w
        print("[+] WHOIS:\n", w)

    # OS Detection
    if args.full or args.osdetect:
        os_guess = os_fingerprint(args.target)
        final_results["OS Detection"] = os_guess
        print("[+] OS Guess:", os_guess)

    # Traceroute
    if args.full or args.traceroute:
        tr = traceroute(args.target)
        final_results["Traceroute"] = tr
        print("[+] Traceroute:\n", tr)

    # HTTP Headers
    if args.full or args.headers:
        headers = grab_headers(args.target)
        final_results["HTTP Headers"] = headers
        print("[+] HTTP Headers:", headers)

    # Directory Bruteforce
    if args.full or args.dirs:
        dirs = dir_bruteforce(args.target)
        final_results["Directories"] = dirs
        print("[+] Directories Found:", dirs)

    # GeoIP
    if args.full or args.geoip:
        geo = geoip_lookup(ip)
        final_results["GeoIP"] = geo
        print("[+] GeoIP:", geo)

    # Save
    if args.output:
        save_results(final_results, args.output)
        print(f"[*] Results saved as {args.output}.json and {args.output}.txt")