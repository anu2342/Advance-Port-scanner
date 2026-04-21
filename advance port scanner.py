import socket
import threading
import queue
import json
import re
import requests
import ssl
from datetime import datetime

# ==============================
# CONFIG
# ==============================
TARGET = input("Enter target IP/domain: ")
PORT_RANGE = range(1, 1025)
THREADS = 100
TIMEOUT = 2
NVD_API_KEY = ""

results = []
lock = threading.Lock()
q = queue.Queue()

# ==============================
# SERVICE PROBES
# ==============================
def send_probe(sock, port):
    try:
        if port in [80, 8080]:
            sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        elif port == 443:
            context = ssl.create_default_context()
            ssock = context.wrap_socket(sock, server_hostname=TARGET)
            ssock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            return ssock.recv(4096).decode(errors="ignore")
        elif port == 25:
            sock.send(b"EHLO test\r\n")

        return sock.recv(4096).decode(errors="ignore")

    except:
        return ""

# ==============================
# FINGERPRINTING
# ==============================
def fingerprint_service(banner, port):
    banner = banner.lower()

    patterns = [
        ("apache", "http", "apache"),
        ("nginx", "http", "nginx"),
        ("iis", "http", "iis"),
        ("openssh", "ssh", "openssh"),
        ("dropbear", "ssh", "dropbear"),
        ("vsftpd", "ftp", "vsftpd"),
        ("proftpd", "ftp", "proftpd"),
        ("mysql", "mysql", "mysql"),
        ("postgres", "postgresql", "postgresql"),
        ("smtp", "smtp", "smtp"),
    ]

    for key, service, product in patterns:
        if key in banner:
            return service, product

    fallback = {
        22: ("ssh", "openssh"),
        21: ("ftp", "ftp"),
        80: ("http", "unknown"),
        443: ("https", "unknown"),
        25: ("smtp", "smtp"),
    }

    return fallback.get(port, ("unknown", "unknown"))

# ==============================
# VERSION EXTRACTION
# ==============================
def extract_version(banner):
    patterns = [
        r"(\d+\.\d+\.\d+)",
        r"(\d+\.\d+)",
        r"v(\d+\.\d+)",
        r"version[: ]?(\d+\.\d+\.\d+)"
    ]

    for p in patterns:
        match = re.search(p, banner.lower())
        if match:
            return match.group(1)

    return "unknown"

# ==============================
# CPE GENERATION
# ==============================
def generate_cpe(product, version):
    if product == "unknown":
        return None

    version = version if version != "unknown" else "*"
    return f"cpe:2.3:a:{product}:{product}:{version}:*:*:*:*:*:*:*"

# ==============================
# CVE PARSER
# ==============================
def parse_cve(item):
    cve = item["cve"]
    metrics = cve.get("metrics", {})

    severity = "UNKNOWN"
    score = "N/A"

    if "cvssMetricV31" in metrics:
        m = metrics["cvssMetricV31"][0]["cvssData"]
        severity = m["baseSeverity"]
        score = m["baseScore"]

    elif "cvssMetricV30" in metrics:
        m = metrics["cvssMetricV30"][0]["cvssData"]
        severity = m["baseSeverity"]
        score = m["baseScore"]

    elif "cvssMetricV2" in metrics:
        m = metrics["cvssMetricV2"][0]
        severity = m["baseSeverity"]
        score = m["cvssData"]["baseScore"]

    return {
        "id": cve["id"],
        "severity": severity,
        "cvss": score
    }

# ==============================
# HYBRID CVE FETCH (FIXED)
# ==============================
def fetch_cves(product, version, cpe):
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {}

        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        cves = []

        # 1. Try CPE (accurate)
        if cpe:
            try:
                params = {
                    "cpeName": cpe,
                    "resultsPerPage": 5
                }

                res = requests.get(url, params=params, headers=headers, timeout=6)
                data = res.json()

                for item in data.get("vulnerabilities", []):
                    cves.append(parse_cve(item))
            except:
                pass

        # 2. Fallback keyword (important)
        if not cves:
            query = f"{product} {version}" if version != "unknown" else product

            params = {
                "keywordSearch": query,
                "resultsPerPage": 5
            }

            res = requests.get(url, params=params, headers=headers, timeout=6)
            data = res.json()

            for item in data.get("vulnerabilities", []):
                cves.append(parse_cve(item))

        return cves[:5]

    except:
        return []

# ==============================
# SCANNER THREAD
# ==============================
def scan():
    while not q.empty():
        port = q.get()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)

            if sock.connect_ex((TARGET, port)) == 0:
                banner = send_probe(sock, port)

                service, product = fingerprint_service(banner, port)
                version = extract_version(banner)

                cpe = generate_cpe(product, version)
                cves = fetch_cves(product, version, cpe)

                with lock:
                    results.append({
                        "port": port,
                        "service": service,
                        "product": product,
                        "version": version,
                        "cpe": cpe,
                        "banner": banner[:200],
                        "cves": cves
                    })

            sock.close()

        except:
            pass

        q.task_done()

# ==============================
# BUILD REPORT
# ==============================
def build_report():
    return {
        "target": TARGET,
        "scan_time": datetime.now().isoformat(),
        "total_open_ports": len(results),
        "results": sorted(results, key=lambda x: x["port"])
    }

# ==============================
# TERMINAL OUTPUT + JSON
# ==============================
def finalize():
    final_report = build_report()

    print("\n================ SCAN RESULTS ================\n")

    for r in final_report["results"]:
        print(f"PORT: {r['port']}")
        print(f"  Service : {r['service']}")
        print(f"  Product : {r['product']}")
        print(f"  Version : {r['version']}")
        print(f"  CPE     : {r['cpe']}")
        print(f"  Banner  : {r['banner'][:100]}")

        if r["cves"]:
            print("  CVEs:")
            for c in r["cves"]:
                print(f"    - {c['id']} | {c['severity']} | CVSS: {c['cvss']}")
        else:
            print("  CVEs: None found")

        print("-" * 50)

    print(f"\nTotal Open Ports: {final_report['total_open_ports']}")

    # Save JSON
    with open("report.json", "w") as f:
        json.dump(final_report, f, indent=4)

    print("\n✅ Report saved as report.json")

    return final_report

# ==============================
# MAIN
# ==============================
def main():
    print(f"\n🔍 Scanning {TARGET}...\n")

    for port in PORT_RANGE:
        q.put(port)

    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=scan)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return finalize()

if __name__ == "__main__":
    report_data = main()