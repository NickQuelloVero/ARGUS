# ARGUS - All-seeing Recon & General Unified Security

```
     █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
    ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
    ███████║██████╔╝██║  ███╗██║   ██║███████╗
    ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
    ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
```

**v5.0.0** — 80 tools across four categories

ARGUS is a comprehensive terminal-based OSINT and security toolkit written in Python. It provides **80 tools** organized into four categories — reconnaissance, exploitation testing, stress testing, and phishing simulation — all accessible through an interactive two-column menu.

---

## Table of Contents

- [Disclaimer](#disclaimer)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Tools](#tools)
  - [OSINT and Reconnaissance (40)](#osint-and-reconnaissance)
  - [Exploitation Testing (20)](#exploitation-testing)
  - [Stress Testing (10)](#stress-testing)
  - [Phishing Simulation (10)](#phishing-simulation)
- [Dependencies](#dependencies)
- [License](#license)

---

## Disclaimer

This tool is intended for **authorized security testing**, educational purposes, and legitimate penetration testing engagements only. Unauthorized use against systems you do not own or have explicit permission to test is **illegal**. The authors assume no liability for misuse.

Exploitation, stress testing, and phishing tools require explicit confirmation before use. Stress and phishing modules require typing **"I ACCEPT ALL RESPONSIBILITY"** to proceed.

---

## Requirements

- Python 3.8 or higher
- pip (Python package manager)

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/nickquellovero/ARGUS.git
cd ARGUS
```

2. Create and activate a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install the dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

Launch ARGUS from the terminal:

```bash
python3 argus.py
```

An interactive two-column menu will appear with all 80 tools organized by category. Enter the number corresponding to the tool you want to use and follow the on-screen prompts. Press `0` to exit. You can interrupt any running operation with `Ctrl+C`.

---

## Tools

### OSINT and Reconnaissance

40 tools for gathering open-source intelligence and mapping attack surfaces.

| # | Tool | Description |
|---|------|-------------|
| 1 | Username Search | Searches for a username across 22+ social platforms and websites to find existing accounts. |
| 2 | Email Lookup | Queries public information associated with an email address, including Gravatar and MX records. |
| 3 | Phone Number Lookup | Retrieves carrier, location, and line type information for a given phone number. |
| 4 | IP Address Lookup | Geolocates an IP address and returns ISP, organization, AS number, and approximate coordinates. |
| 5 | WHOIS Lookup | Performs a WHOIS query on a domain to retrieve registrar, creation/expiration dates, name servers, and registrant details. |
| 6 | DNS Lookup | Resolves DNS records (A, AAAA, MX, NS, TXT, CNAME) for a given domain. |
| 7 | Subdomain Enumeration | Discovers subdomains via certificate transparency logs (crt.sh). |
| 8 | HTTP Headers Analysis | Fetches and displays HTTP response headers, highlighting security-relevant headers (HSTS, CSP, X-Frame-Options). |
| 9 | Website Technology Detection | Fingerprints the technology stack of a website (CMS, frameworks, server software, JavaScript libraries). |
| 10 | Port Scanner | Scans a host for open TCP ports on 16 common services with multi-threaded execution. |
| 11 | Reverse DNS Lookup | Resolves an IP address back to its associated hostname (PTR record). |
| 12 | MAC Address Lookup | Identifies the manufacturer/vendor associated with a given MAC address using the IEEE OUI database. |
| 13 | Email Breach Check | Checks whether an email address has appeared in known data breaches via Have I Been Pwned. |
| 14 | Metadata Extractor | Extracts EXIF metadata from images (GPS coordinates, camera model, timestamps). |
| 15 | Social Media Scraper | Collects publicly available profile information from GitHub and Reddit. |
| 16 | SSL/TLS Certificate Info | Retrieves and displays details of a domain's SSL/TLS certificate (issuer, validity, SANs, serial). |
| 17 | Wayback Machine Lookup | Queries the Internet Archive's Wayback Machine for historical snapshots of a URL. |
| 18 | Robots.txt and Sitemap Analyzer | Fetches and parses a website's robots.txt and sitemap.xml to reveal structure and access rules. |
| 19 | Link Extractor | Crawls a webpage and extracts all internal and external hyperlinks. |
| 20 | Google Dorks Generator | Generates 25 targeted Google search queries (dorks) to find exposed files, login pages, and sensitive data. |
| 21 | Traceroute | Traces the network route to a target host using ICMP/UDP with TTL increments. |
| 22 | Hash Identifier and Lookup | Identifies the type of a hash (MD5, SHA1, SHA256, etc.) and attempts to crack it via online rainbow tables. |
| 23 | ASN Lookup | Retrieves Autonomous System Number information for an IP or domain via BGPView. |
| 24 | Website Screenshot | Captures a screenshot of a webpage using a headless rendering service. |
| 25 | Reverse Image Search | Generates reverse image search URLs for Google, Bing, and TinEye. |
| 26 | CVE Search | Searches the MITRE CVE and NIST NVD databases for known vulnerabilities. |
| 27 | Paste / Code Search | Generates search links for GitHub, GitLab, Pastebin, and Stack Overflow. |
| 28 | DNS Zone Transfer Check | Tests whether a domain's name servers are vulnerable to unauthorized DNS zone transfers (AXFR). |
| 29 | SSL/TLS Suite Scanner | Tests TLS 1.2/1.3 support and enumerates cipher suites. |
| 30 | Shodan Host Lookup | Queries the Shodan InternetDB API for open ports, CPEs, and known vulnerabilities. |
| 31 | Favicon Hash Lookup | Downloads a site's favicon, computes its MurmurHash3 fingerprint, and generates a Shodan search query. |
| 32 | DMARC / SPF / DKIM Check | Queries DNS TXT records for SPF, DMARC, and DKIM (17 common selectors) to assess email security. |
| 33 | Security.txt Checker | Fetches and parses /.well-known/security.txt for vulnerability disclosure policy. |
| 34 | HTTP Methods Discovery | Probes a target with all HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT) and flags dangerous ones. |
| 35 | Cloud Storage Finder | Tests 16 naming mutations across AWS S3, Azure Blob, GCP Storage, and DigitalOcean Spaces for exposed buckets. |
| 36 | JS Endpoint Extractor | Fetches JavaScript files from a page and extracts API endpoints, AWS keys, tokens, emails, and IPs via regex. |
| 37 | WAF / CDN Detector | Detects 12 WAF/CDN vendors (Cloudflare, Akamai, AWS WAF, Sucuri, Imperva, etc.) from headers, cookies, and response bodies. |
| 38 | Banner Grabbing | Connects to specified ports and retrieves service banners (SSH, FTP, SMTP, HTTP, MySQL, Redis, etc.). |
| 39 | Subdomain Bruteforce | DNS brute-forces ~130 common subdomain names with multi-threaded resolution. Supports custom wordlists. |
| 40 | Ping Sweep / Host Discovery | Scans a CIDR range or IP range for live hosts via TCP connect on ports 80, 443, and 22. |

### Exploitation Testing

20 tools for vulnerability assessment. All require authorization confirmation before use.

| # | Tool | Description |
|---|------|-------------|
| 41 | SQL Injection Tester | Tests URL parameters with 20 SQL injection payloads (union, blind, time-based, error-based). |
| 42 | XSS Scanner (Reflected) | Scans URL parameters with 18 XSS payload vectors including event handlers and encoding bypasses. |
| 43 | Directory / File Bruteforcer | Discovers hidden directories and files on a web server using a 67-entry wordlist with multi-threading. |
| 44 | CORS Misconfiguration Scanner | Checks whether a target's CORS policy allows unauthorized cross-origin requests. |
| 45 | Open Redirect Scanner | Tests URL parameters with 15 open redirect payloads including protocol and hostname confusion tricks. |
| 46 | LFI / Path Traversal Tester | Tests 20 LFI payloads with 6 file signature detections (path traversal, PHP wrappers, log injection). |
| 47 | Subdomain Takeover Check | Checks whether subdomains point to unclaimed external services and are vulnerable to takeover. |
| 48 | Reverse Shell Generator | Generates reverse shell one-liners in 11 languages (Bash, Python, Perl, PHP, Ruby, PowerShell, Java, Netcat, socat, Lua, xterm). |
| 49 | CMS Vulnerability Scanner | Scans for known vulnerabilities in WordPress, Joomla, and Drupal installations. |
| 50 | Payload Encoder / Decoder | Encodes and decodes payloads in 11 modes (URL, Base64, Hex, HTML entities, Unicode, double URL, MD5/SHA hashing). |
| 51 | CRLF Injection Tester | Tests 10 CRLF payloads for header injection and HTTP response splitting. |
| 52 | SSRF Tester | Tests 20 SSRF payloads targeting localhost, cloud metadata endpoints (AWS/GCP/Azure), and internal services. |
| 53 | JWT Analyzer | Decodes JWT headers and payloads, checks expiry, analyzes algorithm security, and brute-forces common HMAC secrets. |
| 54 | Clickjacking Tester | Checks X-Frame-Options and CSP frame-ancestors, generates proof-of-concept HTML if vulnerable. |
| 55 | XXE Tester | Tests 6 XML External Entity payloads (file read, SSRF, PHP wrappers) against XML-accepting endpoints. |
| 56 | Command Injection Tester | Tests 20 OS command injection payloads with time-based and output-based detection. |
| 57 | Host Header Injection | Tests 10 host header manipulation vectors (X-Forwarded-Host, Forwarded, X-Original-URL, etc.). |
| 58 | Insecure Cookie Checker | Analyzes all Set-Cookie headers for missing Secure, HttpOnly, and SameSite flags. |
| 59 | CSRF Token Analyzer | Scans HTML forms for CSRF token presence and quality, checks meta tags and CORS headers. |
| 60 | Prototype Pollution Scanner | Tests prototype pollution via query parameters and JSON body payloads. |

### Stress Testing

10 tools for load and resilience testing. All require double authorization (confirmation + "I ACCEPT ALL RESPONSIBILITY").

| # | Tool | Description |
|---|------|-------------|
| 61 | HTTP Flood (GET/POST) | Sends a high volume of HTTP requests with random user-agents and X-Forwarded-For spoofing. Configurable threads (1-200) and duration (1-300s). |
| 62 | Slowloris | Holds concurrent connections open by sending partial HTTP headers, exhausting the server's connection pool. |
| 63 | Slow POST (R.U.D.Y.) | Sends HTTP POST requests with extremely slow body transmission to keep connections occupied. |
| 64 | TCP Connection Flood | Opens a large number of raw TCP connections to a target host and port. |
| 65 | UDP Flood | Sends a continuous stream of random UDP packets to a target host and port. |
| 66 | ICMP Ping Flood | Sends a high volume of ICMP echo request packets (requires root/admin privileges on some systems). |
| 67 | HTTP Slow Read | Sends legitimate HTTP requests but reads the response extremely slowly, tying up server resources. |
| 68 | GoldenEye (Keep-Alive Flood) | Floods with HTTP requests using persistent Keep-Alive connections and randomized headers. |
| 69 | DNS Flood | Floods a DNS server with queries for random subdomains. Configurable threads and duration. |
| 70 | WebSocket Flood | Opens multiple WebSocket connections and floods with masked frames. Configurable connections, duration, and message size. |

### Phishing Simulation

10 tools for authorized phishing simulations and red-team engagements. All require double authorization (confirmation + "I ACCEPT ALL RESPONSIBILITY").

| # | Tool | Description |
|---|------|-------------|
| 71 | Homoglyph Domain Generator | Generates lookalike domains using Unicode/Cyrillic homoglyphs, typo swaps, missing/doubled chars, and QWERTY adjacency. Optionally checks registration. |
| 72 | Phishing URL Analyzer | Scores a suspicious URL (0-100) by checking for IP usage, suspicious TLDs, brand impersonation, encoding, URL shorteners, and urgency keywords. |
| 73 | Email Spoofing Checker | Evaluates a domain's email spoofing resistance by checking SPF, DMARC, DKIM, and MTA-STS records. |
| 74 | Typosquatting Generator | Generates typosquatted domain variations via bit-flips, vowel swaps, dot insertion, prefix/suffix abuse, and hyphenation. Optionally checks registration. |
| 75 | Credential Harvester Template Generator | Generates 8 ready-to-use phishing page templates (Generic Login, Office 365, Google, VPN Portal, WiFi Captive Portal, Password Reset, 2FA, File Share) with configurable callback URL and company name. |
| 76 | URL Obfuscator | Obfuscates a URL using 10+ techniques: decimal/hex/octal IP, @ redirect, subdomain spoof, RTL Unicode override, URL credentials, fragment trick. |
| 77 | Email Header Analyzer | Analyzes raw email headers for phishing indicators: SPF/DKIM/DMARC results, From/Return-Path mismatch, Reply-To mismatch, suspicious mailers, and urgency tactics. Outputs a phishing score. |
| 78 | IDN Homograph Attack Generator | Generates internationalized domain names using Cyrillic character substitution with punycode output. Supports single, multi, and full-script replacement. |
| 79 | Phishing Kit Detector | Scans a suspicious URL for signatures of 11 known phishing kits (GoPhish, Evilginx2, King Phisher, SET, Modlishka, etc.) plus behavioral indicators. |
| 80 | Phishing Campaign Planner | Generates an intelligence report for a target domain: email security posture, mail infrastructure, web presence, ranked pretexts, timing recommendations, and evasion tips. |

---

## Dependencies

All dependencies are listed in `requirements.txt`:

| Package | Purpose | Required |
|---------|---------|----------|
| requests | HTTP requests for all web-based tools | Yes |
| colorama | Colored terminal output | Yes |
| python-whois | WHOIS domain lookups | Optional |
| dnspython | DNS record resolution, zone transfers, DMARC/SPF/DKIM checks | Optional |
| beautifulsoup4 | HTML parsing for scraping, link extraction, tech detection, JS extraction, CSRF analysis | Optional |
| Pillow | Image processing and EXIF metadata extraction | Optional |

Install all at once with:

```bash
pip install -r requirements.txt
```

Tools with missing optional dependencies will display a warning and skip gracefully rather than crashing.

---

## License

This project is provided as-is for educational and authorized testing purposes only.
