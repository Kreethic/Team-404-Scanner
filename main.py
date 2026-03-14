"""
404 Scanner - No API Key Version
----------------------------------
A free vulnerability scanner using public APIs (no signup/key needed).
Run: python 404_scanner_free.py
"""

import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import time
from datetime import datetime

import requests

# ──────────────────────────────────────────────
# Styling / UI Helpers
# ──────────────────────────────────────────────

class Color:
    RED     = "\033[91m"
    ORANGE  = "\033[33m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

def banner():
    print(f"""
{Color.CYAN}{Color.BOLD}
  /$$   /$$    /$$$$$$    /$$   /$$                  
 | $$  | $$   /$$$_  $$  | $$  | $$                  
 | $$  | $$  | $$$$\ $$  | $$  | $$                  
 | $$$$$$$$  | $$ $$ $$  | $$$$$$$$                  
 |_____  $$  | $$\ $$$$  |_____  $$                  
       | $$  | $$ \ $$$        | $$                  
       | $$  |  $$$$$$/        | $$                  
       |__/   \______/         |__/                  

  /$$$$$$                                                                   
 /$$__  $$                                                                  
| $$  \__/  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$      
|  $$$$$$  /$$_____/ |____  $$| $$__  $$| $$__  $$ /$$__  $$ /$$__  $$     
 \____  $$| $$        /$$$$$$$| $$  \ $$| $$  \ $$| $$$$$$$$| $$  \__/     
 /$$  \ $$| $$       /$$__  $$| $$  | $$| $$  | $$| $$_____/| $$           
|  $$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$| $$  | $$|  $$$$$$$| $$           
 \______/  \_______/ \_______/|__/  |__/|__/  |__/ \_______/|__/           
{Color.RESET}
{Color.MAGENTA}              404 Scanner  |  Team 404  |  Sentry Squad {Color.RESET}
""")

def divider(char="─", length=65, color=Color.CYAN):
    print(f"{color}{char * length}{Color.RESET}")

def log_info(msg):    print(f"{Color.CYAN}[*]{Color.RESET} {msg}")
def log_success(msg): print(f"{Color.GREEN}[+]{Color.RESET} {msg}")
def log_warn(msg):    print(f"{Color.YELLOW}[!]{Color.RESET} {msg}")
def log_error(msg):   print(f"{Color.RED}[x]{Color.RESET} {msg}")


# ──────────────────────────────────────────────
# Helper Utilities
# ──────────────────────────────────────────────

def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def compute_md5(filepath: str) -> str:
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ──────────────────────────────────────────────
# Risk Assessment
# ──────────────────────────────────────────────

def assess_risk(flags: list) -> str:
    """flags is a list of threat strings found."""
    count = len(flags)
    if count >= 4:   return "CRITICAL"
    if count >= 3:   return "HIGH"
    if count >= 1:   return "MEDIUM"
    return "CLEAN"

def risk_badge(level: str) -> str:
    badges = {
        "CRITICAL": f"{Color.RED}{Color.BOLD}[CRITICAL]{Color.RESET}",
        "HIGH":     f"{Color.ORANGE}{Color.BOLD}[HIGH]{Color.RESET}",
        "MEDIUM":   f"{Color.YELLOW}{Color.BOLD}[MEDIUM]{Color.RESET}",
        "LOW":      f"{Color.YELLOW}[LOW]{Color.RESET}",
        "CLEAN":    f"{Color.GREEN}{Color.BOLD}[CLEAN]{Color.RESET}",
    }
    return badges.get(level, f"{Color.GREEN}[CLEAN]{Color.RESET}")


# ──────────────────────────────────────────────
# 1. IP Scanner — IPwho.is (no key)
# ──────────────────────────────────────────────

def scan_ip(ip: str) -> dict:
    log_info(f"Looking up IP: {ip}")
    result = {"target": ip, "type": "IP", "flags": [], "info": {}}

    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=10)
        r.raise_for_status()
        data = r.json()

        result["info"] = {
            "Country"    : data.get("country", "N/A"),
            "City"       : data.get("city", "N/A"),
            "Region"     : data.get("region", "N/A"),
            "ISP"        : data.get("connection", {}).get("isp", "N/A"),
            "ASN"        : data.get("connection", {}).get("asn", "N/A"),
            "Org"        : data.get("connection", {}).get("org", "N/A"),
            "Latitude"   : data.get("latitude", "N/A"),
            "Longitude"  : data.get("longitude", "N/A"),
            "Timezone"   : data.get("timezone", {}).get("id", "N/A"),
        }

        # Basic threat heuristics
        isp = str(data.get("connection", {}).get("isp", "")).lower()
        org = str(data.get("connection", {}).get("org", "")).lower()
        suspicious_keywords = ["tor", "vpn", "proxy", "hosting", "datacenter",
                                "anonymous", "bulletproof", "ovh", "hetzner", "digitalocean"]
        for kw in suspicious_keywords:
            if kw in isp or kw in org:
                result["flags"].append(f"Suspicious ISP/Org keyword: '{kw}'")

        log_success("IP info retrieved!")

    except requests.RequestException as e:
        log_warn(f"IPwho.is failed: {e}")

    # URLhaus IP check (no key)
    try:
        r2 = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": ip}, timeout=10
        )
        data2 = r2.json()
        if data2.get("query_status") == "is_host":
            urls = data2.get("urls", [])
            online = [u for u in urls if u.get("url_status") == "online"]
            if online:
                result["flags"].append(f"URLhaus: {len(online)} active malicious URLs hosted")
            elif urls:
                result["flags"].append(f"URLhaus: {len(urls)} historical malicious URL(s)")
    except Exception:
        pass

    result["risk"] = assess_risk(result["flags"])
    return result


# ──────────────────────────────────────────────
# 2. Domain Scanner — WHOIS + DNS + URLhaus
# ──────────────────────────────────────────────

def scan_domain(domain: str) -> dict:
    log_info(f"Scanning domain: {domain}")
    result = {"target": domain, "type": "Domain", "flags": [], "info": {}}

    # DNS resolution
    try:
        ip = socket.gethostbyname(domain)
        result["info"]["Resolved IP"] = ip
        if is_private_ip(ip):
            result["flags"].append("Resolves to private/local IP address")
    except socket.gaierror:
        result["flags"].append("Domain does not resolve (possibly inactive or fake)")
        result["info"]["Resolved IP"] = "FAILED"

    # URLhaus domain check (no key)
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain}, timeout=10
        )
        data = r.json()
        if data.get("query_status") == "is_host":
            urls = data.get("urls", [])
            online = [u for u in urls if u.get("url_status") == "online"]
            tags = set()
            for u in urls:
                tags.update(u.get("tags") or [])
            if online:
                result["flags"].append(f"URLhaus: {len(online)} active malicious URLs on this domain")
            elif urls:
                result["flags"].append(f"URLhaus: {len(urls)} historical malicious URL(s)")
            if tags:
                result["info"]["Threat Tags"] = ", ".join(tags)
        log_success("Domain check done!")
    except Exception as e:
        log_warn(f"URLhaus domain check failed: {e}")

    # Suspicious TLD heuristics
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".zip"]
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            result["flags"].append(f"Suspicious TLD detected: {tld}")

    # Suspicious keyword heuristics
    suspicious_words = ["login", "secure", "verify", "update", "account",
                        "banking", "paypal", "amazon", "apple", "microsoft"]
    domain_lower = domain.lower()
    for word in suspicious_words:
        if word in domain_lower:
            result["flags"].append(f"Phishing keyword in domain: '{word}'")

    result["risk"] = assess_risk(result["flags"])
    return result


# ──────────────────────────────────────────────
# 3. URL Scanner — URLhaus (no key)
# ──────────────────────────────────────────────

def scan_url(url: str) -> dict:
    log_info(f"Scanning URL: {url}")
    result = {"target": url, "type": "URL", "flags": [], "info": {}}

    # URLhaus URL lookup (no key)
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url}, timeout=10
        )
        data = r.json()
        status = data.get("query_status", "")

        if status == "is_host":
            result["flags"].append("URL found in URLhaus malware database")
            result["info"]["URL Status"]   = data.get("url_status", "N/A")
            result["info"]["Threat"]       = data.get("threat", "N/A")
            tags = data.get("tags") or []
            if tags:
                result["info"]["Tags"] = ", ".join(tags)
        elif status == "no_results":
            result["info"]["URLhaus"] = "Not found in database (no known threats)"

        log_success("URL check done!")
    except Exception as e:
        log_warn(f"URLhaus URL check failed: {e}")

    # Heuristic checks
    suspicious_patterns = [
        (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "Direct IP address URL (suspicious)"),
        (r"@",                                              "URL contains @ symbol (phishing trick)"),
        (r"https?://[^/]{50,}",                             "Unusually long domain in URL"),
        (r"\.exe|\.bat|\.ps1|\.vbs|\.js$",                  "URL points to executable file"),
        (r"bit\.ly|tinyurl|t\.co|goo\.gl",                  "URL shortener detected"),
    ]
    for pattern, msg in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            result["flags"].append(msg)

    result["risk"] = assess_risk(result["flags"])
    return result


# ──────────────────────────────────────────────
# 4. File Hash Scanner — MalwareBazaar (no key)
# ──────────────────────────────────────────────

def scan_hash(file_hash: str) -> dict:
    log_info(f"Looking up hash: {file_hash}")
    result = {"target": file_hash, "type": "Hash", "flags": [], "info": {}}

    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": file_hash}, timeout=15
        )
        data = r.json()
        status = data.get("query_status", "")

        if status == "ok":
            details = data.get("data", [{}])[0]
            result["flags"].append("Hash found in MalwareBazaar database")
            result["info"]["File Name"]    = details.get("file_name", "N/A")
            result["info"]["File Type"]    = details.get("file_type", "N/A")
            result["info"]["File Size"]    = f"{details.get('file_size', 'N/A')} bytes"
            result["info"]["Signature"]    = details.get("signature", "N/A")
            result["info"]["First Seen"]   = details.get("first_seen", "N/A")
            result["info"]["Last Seen"]    = details.get("last_seen", "N/A")
            tags = details.get("tags") or []
            if tags:
                result["info"]["Tags"] = ", ".join(tags)
            reporter = details.get("reporter", "N/A")
            result["info"]["Reporter"]     = reporter

        elif status == "hash_not_found":
            result["info"]["MalwareBazaar"] = "Hash not found (not known malware)"

        log_success("Hash lookup done!")

    except Exception as e:
        log_warn(f"MalwareBazaar lookup failed: {e}")

    result["risk"] = assess_risk(result["flags"])
    return result


# ──────────────────────────────────────────────
# 5. File Scanner — local hash + MalwareBazaar
# ──────────────────────────────────────────────

def scan_file(filepath: str) -> dict:
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    sha256 = compute_sha256(filepath)
    md5    = compute_md5(filepath)
    size   = os.path.getsize(filepath)

    log_info(f"SHA-256 : {sha256}")
    log_info(f"MD5     : {md5}")
    log_info(f"Size    : {size} bytes")

    result = scan_hash(sha256)
    result["target"] = filepath
    result["type"]   = "File"
    result["info"]["SHA-256"]   = sha256
    result["info"]["MD5"]       = md5
    result["info"]["File Size"] = f"{size} bytes"

    # Suspicious extension check
    suspicious_exts = [".exe", ".bat", ".ps1", ".vbs", ".js", ".jar",
                       ".scr", ".com", ".pif", ".cmd", ".msi", ".dll"]
    ext = os.path.splitext(filepath)[1].lower()
    if ext in suspicious_exts:
        result["flags"].append(f"Suspicious file extension: {ext}")

    result["risk"] = assess_risk(result["flags"])
    return result


# ──────────────────────────────────────────────
# 6. Port Scanner — socket based
# ──────────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

RISKY_PORTS = {23: "Telnet (unencrypted)", 445: "SMB (ransomware target)",
               3389: "RDP (brute force risk)", 5900: "VNC (remote access)",
               6379: "Redis (often exposed)", 27017: "MongoDB (often exposed)"}

def scan_ports(host: str) -> dict:
    log_info(f"Port scanning: {host}")
    result = {"target": host, "type": "Port Scan", "flags": [], "info": {}, "open_ports": []}

    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(host)
        result["info"]["Resolved IP"] = ip
    except socket.gaierror:
        log_error(f"Cannot resolve host: {host}")
        result["risk"] = "UNKNOWN"
        return result

    open_ports = []
    log_info(f"Scanning {len(COMMON_PORTS)} common ports...")

    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            res = sock.connect_ex((ip, port))
            if res == 0:
                open_ports.append((port, service))
                if port in RISKY_PORTS:
                    result["flags"].append(f"Risky port open: {port}/{service} — {RISKY_PORTS[port]}")
            sock.close()
        except Exception:
            pass

    result["open_ports"] = open_ports
    result["info"]["Open Ports"] = len(open_ports)
    result["risk"] = assess_risk(result["flags"])
    log_success(f"Found {len(open_ports)} open port(s).")
    return result


# ──────────────────────────────────────────────
# 7. PCAP Analyzer — Scapy + URLhaus
# ──────────────────────────────────────────────

def scan_pcap(filepath: str) -> dict:
    try:
        from scapy.all import rdpcap, IP, IPv6, DNS, DNSQR, Raw
    except ImportError:
        raise ImportError("scapy not installed. Run: pip install scapy")

    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"PCAP file not found: {filepath}")

    log_info(f"Reading PCAP: {filepath}")
    packets = rdpcap(filepath)
    log_success(f"Loaded {len(packets)} packets.")

    ips     = set()
    domains = set()
    skip    = ("10.", "192.168.", "127.", "0.", "255.", "::1", "fe80")

    for pkt in packets:
        for layer in (IP, IPv6):
            if pkt.haslayer(layer):
                for addr in (str(pkt[layer].src), str(pkt[layer].dst)):
                    if not any(addr.startswith(p) for p in skip):
                        ips.add(addr)
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                if qname and "." in qname and not qname.endswith(".local"):
                    domains.add(qname)
            except Exception:
                pass
        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode("utf-8", errors="ignore")
                for match in re.findall(r"Host:\s*([^\r\n]+)", payload):
                    host = match.strip().split(":")[0]
                    if "." in host:
                        domains.add(host)
            except Exception:
                pass

    log_info(f"Extracted {len(ips)} IPs and {len(domains)} domains.")
    ip_results     = []
    domain_results = []

    print(f"\n{Color.BOLD}  [ Scanning IPs ]{Color.RESET}")
    divider()
    for ip in sorted(ips):
        r = scan_ip(ip)
        badge = risk_badge(r["risk"])
        country = r["info"].get("Country", "N/A")
        isp     = r["info"].get("ISP", "N/A")
        print(f"  {Color.CYAN}{ip:20}{Color.RESET} {badge} | {country} | {isp}")
        for flag in r["flags"]:
            print(f"      {Color.YELLOW}>> {flag}{Color.RESET}")
        ip_results.append(r)
        time.sleep(0.3)

    print(f"\n{Color.BOLD}  [ Scanning Domains ]{Color.RESET}")
    divider()
    for domain in sorted(domains):
        r = scan_domain(domain)
        badge = risk_badge(r["risk"])
        print(f"  {Color.CYAN}{domain:40}{Color.RESET} {badge}")
        for flag in r["flags"]:
            print(f"      {Color.YELLOW}>> {flag}{Color.RESET}")
        domain_results.append(r)
        time.sleep(0.3)

    threats = sum(1 for r in ip_results + domain_results if r["risk"] != "CLEAN")
    return {
        "target": filepath, "type": "PCAP",
        "ip_results": ip_results, "domain_results": domain_results,
        "threats": threats, "flags": [],
        "info": {"IPs Scanned": len(ips), "Domains Scanned": len(domains)},
        "risk": "CRITICAL" if threats >= 5 else "HIGH" if threats >= 2 else "MEDIUM" if threats >= 1 else "CLEAN",
    }


# ──────────────────────────────────────────────
# 8. PDF Scanner — PyPDF2 (no key)
# ──────────────────────────────────────────────

def scan_pdf(filepath: str) -> dict:
    """Scan a PDF file for malicious indicators."""
    try:
        import PyPDF2
    except ImportError:
        raise ImportError("PyPDF2 not installed. Run: pip install PyPDF2")

    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    if not filepath.lower().endswith(".pdf"):
        log_warn("File does not have .pdf extension — scanning anyway.")

    result = {
        "target"  : filepath,
        "type"    : "PDF",
        "flags"   : [],
        "info"    : {},
        "urls"    : [],
        "url_results": [],
    }

    # Hash check on MalwareBazaar
    sha256 = compute_sha256(filepath)
    md5    = compute_md5(filepath)
    result["info"]["SHA-256"]   = sha256
    result["info"]["MD5"]       = md5
    result["info"]["File Size"] = f"{os.path.getsize(filepath)} bytes"

    log_info("Checking PDF hash on MalwareBazaar...")
    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256}, timeout=15
        )
        data = r.json()
        if data.get("query_status") == "ok":
            result["flags"].append("PDF hash found in MalwareBazaar malware database!")
            details = data.get("data", [{}])[0]
            result["info"]["MalwareBazaar"] = details.get("signature", "Known malware")
    except Exception:
        pass

    # Parse PDF
    log_info("Parsing PDF structure...")
    try:
        with open(filepath, "rb") as f:
            reader = PyPDF2.PdfReader(f)

            # Basic metadata
            result["info"]["Pages"]     = len(reader.pages)
            result["info"]["Encrypted"] = "Yes" if reader.is_encrypted else "No"

            meta = reader.metadata
            if meta:
                result["info"]["Author"]   = meta.get("/Author",   "N/A")
                result["info"]["Creator"]  = meta.get("/Creator",  "N/A")
                result["info"]["Producer"] = meta.get("/Producer", "N/A")
                result["info"]["Created"]  = meta.get("/CreationDate", "N/A")

            # Extract text and scan for URLs + suspicious keywords
            full_text = ""
            for page in reader.pages:
                try:
                    full_text += page.extract_text() or ""
                except Exception:
                    pass

            # Extract URLs from text
            urls_found = re.findall(
                r'https?://[^\s\]\[<>"\'{}|\\^`)(,;]+', full_text
            )
            result["urls"] = list(set(urls_found))
            if result["urls"]:
                result["info"]["URLs Found"] = len(result["urls"])
                result["flags"].append(f"{len(result['urls'])} URL(s) embedded in PDF")

            # Suspicious phishing keywords in text
            phishing_words = ["verify your account", "click here", "login",
                              "confirm your", "update your", "suspended",
                              "urgent", "password", "credit card", "social security"]
            found_keywords = []
            text_lower = full_text.lower()
            for word in phishing_words:
                if word in text_lower:
                    found_keywords.append(word)
            if found_keywords:
                result["flags"].append(f"Phishing keywords found: {', '.join(found_keywords)}")

        log_success("PDF structure parsed!")

    except PyPDF2.errors.PdfReadError:
        result["flags"].append("PDF is corrupted or malformed (possible evasion technique)")
        log_warn("Could not fully parse PDF — it may be corrupted.")
    except Exception as e:
        log_warn(f"PDF parsing error: {e}")

    # Scan raw bytes for dangerous PDF keywords
    log_info("Scanning PDF raw content for dangerous objects...")
    try:
        with open(filepath, "rb") as f:
            raw = f.read().decode("latin-1", errors="ignore")

        dangerous_keys = {
            "/JavaScript"  : "JavaScript code detected inside PDF",
            "/JS"          : "JavaScript (short form) detected inside PDF",
            "/AA"          : "Auto Action detected (runs on open)",
            "/OpenAction"  : "OpenAction detected (auto-executes on open)",
            "/Launch"      : "Launch action detected (can run executables)",
            "/EmbeddedFile": "Embedded file detected inside PDF",
            "/RichMedia"   : "RichMedia object detected (Flash/video embed)",
            "/XFA"         : "XFA form detected (commonly used in exploits)",
            "/Encrypt"     : "Encryption object found",
            "/AcroForm"    : "AcroForm detected (interactive form)",
        }

        found_keys = []
        for key, msg in dangerous_keys.items():
            if key in raw:
                found_keys.append(key)
                result["flags"].append(msg)

        result["info"]["Dangerous Objects"] = ", ".join(found_keys) if found_keys else "None"

    except Exception as e:
        log_warn(f"Raw byte scan error: {e}")

    # Scan embedded URLs against URLhaus
    if result["urls"]:
        log_info(f"Scanning {len(result['urls'])} embedded URL(s) against URLhaus...")
        for url in result["urls"][:10]:  # limit to 10 to avoid spam
            try:
                r = requests.post(
                    "https://urlhaus-api.abuse.ch/v1/url/",
                    data={"url": url}, timeout=8
                )
                data = r.json()
                status = data.get("query_status", "")
                url_risk = "MALICIOUS" if status == "is_host" else "CLEAN"
                result["url_results"].append({"url": url, "status": url_risk})
                if url_risk == "MALICIOUS":
                    result["flags"].append(f"Malicious URL in PDF: {url}")
                time.sleep(0.2)
            except Exception:
                result["url_results"].append({"url": url, "status": "UNKNOWN"})

    result["risk"] = assess_risk(result["flags"])
    return result


# ──────────────────────────────────────────────
# 9. Image Scanner (.jpg .png .gif .bmp .webp)
# ──────────────────────────────────────────────

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".ico"}

def scan_image(filepath: str) -> dict:
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    ext = os.path.splitext(filepath)[1].lower()
    result = {
        "target": filepath, "type": "Image",
        "flags": [], "info": {}, "url_results": [],
    }

    result["info"]["File Size"] = f"{os.path.getsize(filepath)} bytes"
    result["info"]["Extension"] = ext if ext else "Unknown"

    # Hash check
    sha256 = compute_sha256(filepath)
    md5    = compute_md5(filepath)
    result["info"]["SHA-256"] = sha256
    result["info"]["MD5"]     = md5

    log_info("Checking image hash on MalwareBazaar...")
    try:
        r = requests.post("https://mb-api.abuse.ch/api/v1/",
                          data={"query": "get_info", "hash": sha256}, timeout=15)
        data = r.json()
        if data.get("query_status") == "ok":
            result["flags"].append("Image hash found in MalwareBazaar database!")
            details = data.get("data", [{}])[0]
            result["info"]["MalwareBazaar"] = details.get("signature", "Known malware")
    except Exception:
        pass

    # Fake extension check — verify magic bytes
    log_info("Checking file magic bytes...")
    magic_signatures = {
        b"\xff\xd8\xff"     : "JPEG",
        b"\x89PNG\r\n\x1a\n": "PNG",
        b"GIF87a"           : "GIF",
        b"GIF89a"           : "GIF",
        b"BM"               : "BMP",
        b"RIFF"             : "WEBP",
    }
    try:
        with open(filepath, "rb") as f:
            header = f.read(12)
        detected = None
        for sig, fmt in magic_signatures.items():
            if header.startswith(sig):
                detected = fmt
                break
        result["info"]["Detected Format"] = detected or "Unknown/Suspicious"
        if detected is None:
            result["flags"].append("File magic bytes do not match any known image format")
        elif ext in IMAGE_EXTENSIONS:
            ext_map = {".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG",
                       ".gif": "GIF", ".bmp": "BMP", ".webp": "WEBP"}
            expected = ext_map.get(ext)
            if expected and detected != expected:
                result["flags"].append(
                    f"Fake extension! File is {detected} but saved as {ext}")
    except Exception as e:
        log_warn(f"Magic byte check failed: {e}")

    # EXIF metadata extraction
    log_info("Extracting EXIF metadata...")
    try:
        from PIL import Image as PILImage
        from PIL.ExifTags import TAGS
        img = PILImage.open(filepath)
        result["info"]["Image Size"] = f"{img.width} x {img.height} px"
        result["info"]["Mode"]       = img.mode
        exif_data = img._getexif() if hasattr(img, "_getexif") else None
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                if tag in ("Make", "Model", "Software", "DateTime",
                           "Artist", "Copyright", "GPSInfo"):
                    result["info"][f"EXIF {tag}"] = str(value)[:80]
            if "GPSInfo" in {TAGS.get(t) for t in exif_data}:
                result["flags"].append("GPS location data found in EXIF metadata!")
    except ImportError:
        log_warn("Pillow not installed — skipping EXIF. Run: pip install Pillow")
    except Exception:
        pass

    # Hidden text / steganography heuristic
    log_info("Scanning for hidden strings in image data...")
    try:
        with open(filepath, "rb") as f:
            raw = f.read().decode("latin-1", errors="ignore")
        urls_found = re.findall(r'https?://[^\s\x00-\x1f\x7f-\xff]{8,}', raw)
        if urls_found:
            result["flags"].append(f"{len(urls_found)} URL(s) found hidden in image data")
            result["url_results"] = [{"url": u, "status": "UNKNOWN"} for u in urls_found[:10]]

        sus_strings = ["eval(", "base64", "powershell", "cmd.exe",
                       "wget ", "curl ", "/bin/sh", "chmod +x"]
        for s in sus_strings:
            if s.lower() in raw.lower():
                result["flags"].append(f"Suspicious string found in image: '{s}'")
    except Exception:
        pass

    result["risk"] = assess_risk(result["flags"])
    log_success("Image scan complete!")
    return result


# ──────────────────────────────────────────────
# 10. Word File Scanner (.docx)
# ──────────────────────────────────────────────

def scan_word(filepath: str) -> dict:
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    result = {
        "target": filepath, "type": "Word",
        "flags": [], "info": {}, "url_results": [],
    }

    result["info"]["File Size"] = f"{os.path.getsize(filepath)} bytes"
    sha256 = compute_sha256(filepath)
    md5    = compute_md5(filepath)
    result["info"]["SHA-256"] = sha256
    result["info"]["MD5"]     = md5

    # Hash check on MalwareBazaar
    log_info("Checking Word file hash on MalwareBazaar...")
    try:
        r = requests.post("https://mb-api.abuse.ch/api/v1/",
                          data={"query": "get_info", "hash": sha256}, timeout=15)
        data = r.json()
        if data.get("query_status") == "ok":
            result["flags"].append("Word file hash found in MalwareBazaar database!")
            details = data.get("data", [{}])[0]
            result["info"]["MalwareBazaar"] = details.get("signature", "Known malware")
    except Exception:
        pass

    # Parse .docx using python-docx
    log_info("Parsing Word document structure...")
    try:
        import docx
        doc = docx.Document(filepath)

        # Metadata
        props = doc.core_properties
        result["info"]["Author"]    = props.author   or "N/A"
        result["info"]["Created"]   = str(props.created)  if props.created  else "N/A"
        result["info"]["Modified"]  = str(props.modified) if props.modified else "N/A"
        result["info"]["Company"]   = props.company  or "N/A"
        result["info"]["Revision"]  = str(props.revision) if props.revision else "N/A"
        result["info"]["Paragraphs"]= str(len(doc.paragraphs))

        # Extract full text
        full_text = "\n".join([p.text for p in doc.paragraphs])

        # Extract URLs
        urls_found = re.findall(r'https?://[^\s\]\[<>"\']+', full_text)
        if urls_found:
            result["flags"].append(f"{len(urls_found)} URL(s) found in document")
            result["info"]["URLs Found"] = len(urls_found)

        # Phishing keywords
        phishing_words = ["verify your account", "click here", "login",
                          "confirm your", "update your", "suspended",
                          "urgent", "password", "wire transfer", "invoice",
                          "enable macros", "enable content", "enable editing"]
        text_lower = full_text.lower()
        found_kw = [w for w in phishing_words if w in text_lower]
        if found_kw:
            result["flags"].append(f"Phishing/social-engineering keywords: {', '.join(found_kw)}")

        # Scan URLs via URLhaus
        for url in list(set(urls_found))[:10]:
            try:
                r2 = requests.post("https://urlhaus-api.abuse.ch/v1/url/",
                                   data={"url": url}, timeout=8)
                status = r2.json().get("query_status", "")
                url_risk = "MALICIOUS" if status == "is_host" else "CLEAN"
                result["url_results"].append({"url": url, "status": url_risk})
                if url_risk == "MALICIOUS":
                    result["flags"].append(f"Malicious URL in document: {url}")
                time.sleep(0.2)
            except Exception:
                result["url_results"].append({"url": url, "status": "UNKNOWN"})

        log_success("Word document parsed!")

    except ImportError:
        log_warn("python-docx not installed. Run: pip install python-docx")
        result["flags"].append("Could not parse .docx — python-docx not installed")
    except Exception as e:
        log_warn(f"Word parse error: {e}")

    # Raw XML scan for macros and OLE objects
    log_info("Scanning for macros and embedded objects in raw content...")
    try:
        import zipfile
        if zipfile.is_zipfile(filepath):
            with zipfile.ZipFile(filepath, "r") as z:
                names = z.namelist()
                result["info"]["Internal Files"] = len(names)
                # Check for VBA macros
                macro_files = [n for n in names if "vba" in n.lower() or "macro" in n.lower()]
                if macro_files:
                    result["flags"].append(f"VBA Macro detected: {', '.join(macro_files)}")
                # Embedded OLE objects
                ole_files = [n for n in names if n.endswith((".bin", ".ole"))]
                if ole_files:
                    result["flags"].append(f"Embedded OLE object(s) found: {len(ole_files)}")
                # External relationships
                for name in names:
                    if "rels" in name:
                        content = z.read(name).decode("utf-8", errors="ignore")
                        ext_links = re.findall(r'Target="(https?://[^"]+)"', content)
                        if ext_links:
                            result["flags"].append(
                                f"External link in document relationships: {ext_links[0]}")
        else:
            result["flags"].append("File is not a valid .docx (not a ZIP archive) — possibly .doc format or corrupt")
    except Exception as e:
        log_warn(f"Raw scan error: {e}")

    result["risk"] = assess_risk(result["flags"])
    return result


# ──────────────────────────────────────────────
# 11. TXT File Scanner
# ──────────────────────────────────────────────

def scan_txt(filepath: str) -> dict:
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    result = {
        "target": filepath, "type": "TXT",
        "flags": [], "info": {}, "url_results": [], "ip_results": [],
    }

    result["info"]["File Size"] = f"{os.path.getsize(filepath)} bytes"
    sha256 = compute_sha256(filepath)
    md5    = compute_md5(filepath)
    result["info"]["SHA-256"] = sha256
    result["info"]["MD5"]     = md5

    # Hash check
    log_info("Checking TXT file hash on MalwareBazaar...")
    try:
        r = requests.post("https://mb-api.abuse.ch/api/v1/",
                          data={"query": "get_info", "hash": sha256}, timeout=15)
        data = r.json()
        if data.get("query_status") == "ok":
            result["flags"].append("File hash found in MalwareBazaar database!")
    except Exception:
        pass

    # Read file content
    log_info("Reading and analyzing TXT content...")
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        log_error(f"Could not read file: {e}")
        result["risk"] = "UNKNOWN"
        return result

    lines_count = content.count("\n")
    result["info"]["Lines"]      = lines_count
    result["info"]["Characters"] = len(content)

    # Extract and scan URLs
    urls_found = list(set(re.findall(r'https?://[^\s\]\[<>"\']+', content)))
    if urls_found:
        result["info"]["URLs Found"] = len(urls_found)
        result["flags"].append(f"{len(urls_found)} URL(s) found in file")
        log_info(f"Scanning {min(len(urls_found), 10)} URL(s) via URLhaus...")
        for url in urls_found[:10]:
            try:
                r2 = requests.post("https://urlhaus-api.abuse.ch/v1/url/",
                                   data={"url": url}, timeout=8)
                status   = r2.json().get("query_status", "")
                url_risk = "MALICIOUS" if status == "is_host" else "CLEAN"
                result["url_results"].append({"url": url, "status": url_risk})
                if url_risk == "MALICIOUS":
                    result["flags"].append(f"Malicious URL found: {url}")
                time.sleep(0.2)
            except Exception:
                result["url_results"].append({"url": url, "status": "UNKNOWN"})

    # Extract and scan IPs
    ips_found = list(set(re.findall(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        content)))
    public_ips = [ip for ip in ips_found if not is_private_ip(ip)]
    if public_ips:
        result["info"]["IPs Found"] = len(public_ips)
        result["flags"].append(f"{len(public_ips)} public IP address(es) found in file")
        log_info(f"Scanning {min(len(public_ips), 5)} IP(s)...")
        for ip in public_ips[:5]:
            ip_res = scan_ip(ip)
            result["ip_results"].append(ip_res)
            if ip_res["risk"] != "CLEAN":
                result["flags"].append(f"Suspicious IP in file: {ip} [{ip_res['risk']}]")
            time.sleep(0.3)

    # Suspicious script patterns
    script_patterns = [
        (r"powershell\s+-[eE]",           "Encoded PowerShell command detected"),
        (r"cmd\.exe\s*/[cC]",             "CMD execution command detected"),
        (r"base64[_\-]?decode",           "Base64 decode pattern detected"),
        (r"eval\s*\(",                    "eval() function detected"),
        (r"wget\s+http",                  "wget download command detected"),
        (r"curl\s+http",                  "curl download command detected"),
        (r"chmod\s+\+x",                  "chmod +x (Linux execution) detected"),
        (r"/bin/bash|/bin/sh",            "Shell execution path detected"),
        (r"nc\s+-[lvp]",                  "Netcat listener command detected"),
        (r"msfvenom|meterpreter|msf>",    "Metasploit payload string detected"),
        (r"[A-Za-z0-9+/]{100,}={0,2}",   "Long Base64 encoded string detected"),
    ]
    for pattern, msg in script_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            result["flags"].append(msg)

    # Suspicious keywords
    sus_keywords = ["password:", "passwd:", "secret:", "api_key:",
                    "private_key", "BEGIN RSA", "BEGIN CERTIFICATE",
                    "access_token", "authorization:"]
    content_lower = content.lower()
    for kw in sus_keywords:
        if kw.lower() in content_lower:
            result["flags"].append(f"Sensitive data keyword found: '{kw}'")

    result["risk"] = assess_risk(result["flags"])
    log_success("TXT scan complete!")
    return result


# ──────────────────────────────────────────────
# Report Printer (Terminal)
# ──────────────────────────────────────────────

def print_report(result: dict):
    print()
    divider("=")
    print(f"{Color.BOLD}  404 SCANNER - SCAN REPORT  |  Team 404{Color.RESET}")
    print(f"  Type   : {Color.CYAN}{result['type'].upper()}{Color.RESET}")
    print(f"  Target : {Color.MAGENTA}{result['target']}{Color.RESET}")
    divider("=")

    print(f"\n  Risk Level : {risk_badge(result['risk'])}")

    if result["flags"]:
        print(f"\n  {Color.BOLD}Threat Indicators ({len(result['flags'])}):{Color.RESET}")
        for flag in result["flags"]:
            print(f"    {Color.YELLOW}>>{Color.RESET} {flag}")
    else:
        print(f"\n  {Color.GREEN}No threat indicators found.{Color.RESET}")

    if result.get("info"):
        print(f"\n  {Color.BOLD}Details:{Color.RESET}")
        for k, v in result["info"].items():
            print(f"    {k:20}: {v}")

    # Port scan specific
    if result.get("open_ports"):
        print(f"\n  {Color.BOLD}Open Ports:{Color.RESET}")
        for port, service in result["open_ports"]:
            color = Color.RED if port in RISKY_PORTS else Color.GREEN
            print(f"    {color}{port:6}{Color.RESET}  {service}")

    # PDF / Word / TXT URL results
    if result.get("url_results"):
        print(f"\n  {Color.BOLD}Embedded URLs ({len(result['url_results'])}):{Color.RESET}")
        for item in result["url_results"]:
            color = Color.RED if item["status"] == "MALICIOUS" else Color.GREEN
            print(f"    {color}[{item['status']:8}]{Color.RESET}  {item['url']}")

    # TXT IP results
    if result.get("ip_results"):
        print(f"\n  {Color.BOLD}IPs Found in File:{Color.RESET}")
        for r in result["ip_results"]:
            badge = risk_badge(r["risk"])
            country = r["info"].get("Country", "N/A")
            print(f"    {Color.CYAN}{r['target']:18}{Color.RESET} {badge} | {country}")

    divider("=")
    print()


# ──────────────────────────────────────────────
# Report Generation (File)
# ──────────────────────────────────────────────

def generate_report(result: dict) -> str:
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append("=" * 65)
    lines.append("          404 SCANNER - SCAN REPORT")
    lines.append("                  Team 404")
    lines.append("          No API Key Edition")
    lines.append("=" * 65)
    lines.append("")
    lines.append(f"  Date        : {now}")
    lines.append(f"  Scan Type   : {result['type'].upper()}")
    lines.append(f"  Target      : {result['target']}")
    lines.append(f"  Risk Level  : {result['risk']}")
    lines.append("")
    lines.append("-" * 65)

    if result["flags"]:
        lines.append(f"  THREAT INDICATORS ({len(result['flags'])})")
        lines.append("-" * 65)
        for flag in result["flags"]:
            lines.append(f"  >> {flag}")
        lines.append("")

    if result.get("info"):
        lines.append("-" * 65)
        lines.append("  DETAILS")
        lines.append("-" * 65)
        for k, v in result["info"].items():
            lines.append(f"  {k:20}: {v}")
        lines.append("")

    if result.get("open_ports"):
        lines.append("-" * 65)
        lines.append("  OPEN PORTS")
        lines.append("-" * 65)
        for port, service in result["open_ports"]:
            risky = " [RISKY]" if port in RISKY_PORTS else ""
            lines.append(f"  {port:6}  {service}{risky}")
        lines.append("")

    # PDF URL results
    if result.get("url_results"):
        lines.append("-" * 65)
        lines.append(f"  EMBEDDED URLS ({len(result['url_results'])})")
        lines.append("-" * 65)
        for item in result["url_results"]:
            lines.append(f"  [{item['status']:8}]  {item['url']}")
        lines.append("")

    # PCAP sub-results
    if result.get("ip_results") or result.get("domain_results"):
        lines.append("-" * 65)
        lines.append("  PCAP IP RESULTS")
        lines.append("-" * 65)
        for r in result.get("ip_results", []):
            lines.append(f"  {r['target']:20}  Risk: {r['risk']:10}  "
                         f"Country:{r['info'].get('Country','N/A')}  ISP:{r['info'].get('ISP','N/A')}")
            for flag in r["flags"]:
                lines.append(f"      >> {flag}")
        lines.append("")
        lines.append("-" * 65)
        lines.append("  PCAP DOMAIN RESULTS")
        lines.append("-" * 65)
        for r in result.get("domain_results", []):
            lines.append(f"  {r['target']:40}  Risk: {r['risk']}")
            for flag in r["flags"]:
                lines.append(f"      >> {flag}")
        lines.append("")
        lines.append(f"  Total Threats Found : {result.get('threats', 0)}")
        lines.append("")

    lines.append("=" * 65)
    lines.append("  Generated by 404 Scanner | Team 404 | No API Key Edition")
    lines.append("=" * 65)
    lines.append("")
    return "\n".join(lines)

def ask_save_report(result: dict):
    ans = input(f"\n{Color.CYAN}Save report to file? (y/n): {Color.RESET}").strip().lower()
    if ans == "y":
        content   = generate_report(result)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = f"404scan_report_{timestamp}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        log_success(f"Report saved: {Color.MAGENTA}{filename}{Color.RESET}")
    else:
        log_info("Report not saved.")


# ──────────────────────────────────────────────
# Interactive Menu
# ──────────────────────────────────────────────

MENU_OPTIONS = [
    ("[1]  URL       ", "Scan a URL for threats (URLhaus + heuristics)"),
    ("[2]  IP        ", "Scan an IP address (IPwho.is + URLhaus)"),
    ("[3]  Domain    ", "Scan a domain (DNS + URLhaus + heuristics)"),
    ("[4]  Hash      ", "Look up a file hash (MalwareBazaar)"),
    ("[5]  File      ", "Scan a local file (hash + extension check)"),
    ("[6]  PDF       ", "Scan a PDF file (JS, URLs, embedded objects)"),
    ("[7]  Image     ", "Scan an image file (EXIF, fake ext, hidden data)"),
    ("[8]  Word      ", "Scan a Word .docx file (macros, URLs, metadata)"),
    ("[9]  TXT       ", "Scan a TXT file (URLs, IPs, script patterns)"),
    ("[10] Port Scan ", "Scan open ports on a host"),
    ("[11] PCAP      ", "Analyze a PCAP file (extract + scan all IPs/domains)"),
    ("[12] Exit      ", "Quit 404 Scanner"),
]

def show_menu():
    print()
    divider()
    print(f"{Color.BOLD}  SELECT SCAN TYPE{Color.RESET}\n")
    for icon, desc in MENU_OPTIONS:
        print(f"  {Color.CYAN}{icon}{Color.RESET}  {desc}")
    divider()

def get_choice() -> int:
    while True:
        try:
            choice = int(input(f"\n{Color.BOLD}Enter choice [1-{len(MENU_OPTIONS)}]: {Color.RESET}"))
            if 1 <= choice <= len(MENU_OPTIONS):
                return choice
            log_warn(f"Enter a number between 1 and {len(MENU_OPTIONS)}.")
        except ValueError:
            log_warn("Invalid input. Please enter a number.")

def run_scan(choice: int):
    print()
    result = None
    try:
        if choice == 1:
            target = input(f"{Color.CYAN}Enter URL          : {Color.RESET}").strip()
            result = scan_url(target)

        elif choice == 2:
            target = input(f"{Color.CYAN}Enter IP Address   : {Color.RESET}").strip()
            result = scan_ip(target)

        elif choice == 3:
            target = input(f"{Color.CYAN}Enter Domain       : {Color.RESET}").strip()
            result = scan_domain(target)

        elif choice == 4:
            target = input(f"{Color.CYAN}Enter Hash (MD5/SHA-256): {Color.RESET}").strip()
            result = scan_hash(target)

        elif choice == 5:
            target = input(f"{Color.CYAN}Enter File Path    : {Color.RESET}").strip()
            result = scan_file(target)

        elif choice == 6:
            target = input(f"{Color.CYAN}Enter PDF Path     : {Color.RESET}").strip()
            result = scan_pdf(target)

        elif choice == 7:
            target = input(f"{Color.CYAN}Enter Image Path   : {Color.RESET}").strip()
            result = scan_image(target)

        elif choice == 8:
            target = input(f"{Color.CYAN}Enter Word Path    : {Color.RESET}").strip()
            result = scan_word(target)

        elif choice == 9:
            target = input(f"{Color.CYAN}Enter TXT Path     : {Color.RESET}").strip()
            result = scan_txt(target)

        elif choice == 10:
            target = input(f"{Color.CYAN}Enter Host/IP      : {Color.RESET}").strip()
            result = scan_ports(target)

        elif choice == 11:
            target = input(f"{Color.CYAN}Enter PCAP Path    : {Color.RESET}").strip()
            result = scan_pcap(target)

        if result:
            print_report(result)
            ask_save_report(result)

    except FileNotFoundError as e:
        log_error(str(e))
    except ImportError as e:
        log_error(str(e))
    except requests.RequestException as e:
        log_error(f"Network error: {e}")
    except Exception as e:
        log_error(f"Unexpected error: {e}")

    input(f"\n{Color.CYAN}Press Enter to return to menu...{Color.RESET}")


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────

def main():
    banner()
    log_success("No API key needed — ready to scan!\n")

    while True:
        show_menu()
        choice = get_choice()
        if choice == len(MENU_OPTIONS):
            print(f"\n{Color.CYAN}Goodbye! Team 404 Scanner signing off.\n{Color.RESET}")
            break
        run_scan(choice)

if __name__ == "__main__":
    main()
