# ARGUS - All-seeing Recon & General Unified Security

```
     █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
    ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
    ███████║██████╔╝██║  ███╗██║   ██║███████╗
    ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
    ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
```

**v5.1.0** // 81 tools across four categories + AI-powered search

ARGUS is a comprehensive terminal-based OSINT and security toolkit written in Python. It provides **81 tools** organized into four categories (reconnaissance, exploitation testing, stress testing, and phishing simulation), all accessible through an interactive two-column menu. It includes an **AI Search** feature that uses natural language to find the best tool for your needs. It also features a hardened **Stealth Mode** with multi-layer anonymization: Tor/SOCKS5/HTTP proxy routing, IPv6 leak blocking, DNS leak prevention, full HTTP fingerprint randomization, MAC address spoofing, and Tor circuit rotation.

---

## Table of Contents

- [Disclaimer](#disclaimer)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [AI Search](#ai-search)
- [API Backend](#api-backend)
- [Stealth Mode](#stealth-mode)
  - [Protection Layers](#protection-layers)
  - [Kill-Switch](#kill-switch)
  - [Menu Options](#stealth-menu-options)
  - [Known Limitations](#known-limitations)
- [Tools](#tools)
  - [OSINT and Reconnaissance (40)](#osint-and-reconnaissance)
  - [Exploitation Testing (21)](#exploitation-testing)
  - [Stress Testing (10)](#stress-testing)
  - [Phishing Simulation (10)](#phishing-simulation)
- [Authorization System](#authorization-system)
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
- Tor (for Stealth Mode with Tor routing)

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

4. (Optional) Install and enable Tor for Stealth Mode:

```bash
sudo pacman -S tor          # Arch
sudo apt install tor         # Debian/Ubuntu
sudo systemctl enable tor
sudo systemctl start tor
```

To enable Tor circuit rotation (option 9 in Stealth Menu), add the following to `/etc/tor/torrc`:

```
ControlPort 9051
CookieAuthentication 1
```

Then restart Tor: `sudo systemctl restart tor`

---

## Usage

Launch ARGUS from the terminal:

```bash
python3 argus.py
```

An interactive two-column menu will appear with all 81 tools organized by category. Enter the number corresponding to the tool you want to use and follow the on-screen prompts. Press `A` to open AI Search, `S` to open Stealth Mode configuration, or `0` to exit. You can interrupt any running operation with `Ctrl+C`.

The menu is color-coded by category:

- **Cyan** = OSINT / Reconnaissance
- **Red** = Exploitation and Stress Testing
- **Magenta** = Phishing Simulation
- **Green** = AI Search

---

## AI Search

ARGUS includes an AI-powered search feature that helps you find the right tool using natural language. Press `A` from the main menu, describe what you want to do (e.g. "scan a website for SQL injection" or "find subdomains of a target"), and the AI will return up to 3 matching tools ranked by relevance with an explanation of why each tool fits your query. You can then launch the selected tool directly from the results.

AI Search connects to a remote API backend hosted on Vercel. No API key or local setup is required on the client side.

---

## API Backend

The `api/` folder contains the backend that powers AI Search. It is a FastAPI application deployed on Vercel that uses Groq (LLM inference) to match natural language queries against the full ARGUS tool catalog.

### Structure

```
api/
├── main.py              # FastAPI app with /search and /tools endpoints
├── tools_catalog.py     # Static catalog of all 81 tools with descriptions
├── requirements.txt     # Python dependencies (fastapi, groq, uvicorn)
├── vercel.json          # Vercel deployment configuration
└── .env.example         # Template for the GROQ_API_KEY environment variable
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/search?q=...` | GET | Takes a natural language query, sends it to Groq (Llama 3.3 70B), and returns up to 3 matching tools with relevance explanations |
| `/tools` | GET | Returns the full catalog of all 81 tools |

### Self-hosting

If you want to host the API yourself:

```bash
cd api
pip install -r requirements.txt
export GROQ_API_KEY=gsk_your_key_here
uvicorn main:app --reload
```

Then set the `ARGUS_API_URL` environment variable before running ARGUS:

```bash
export ARGUS_API_URL=http://localhost:8000
python3 argus.py
```

By default, ARGUS connects to the hosted instance at `https://argusbackend-psi.vercel.app`.

---

## Stealth Mode

ARGUS includes a hardened **Stealth Mode** that anonymizes all network traffic generated by the tool. Access it by pressing `S` from the main menu.

> **Important:** Stealth Mode protects traffic made by ARGUS only. It does not affect your browser, system DNS, or other applications. For full system anonymity, use a system-wide VPN or configure your browser to use the Tor SOCKS proxy at `127.0.0.1:9050`.

### Protection Layers

| Layer | What it does | How it works |
|-------|-------------|--------------|
| **Proxy routing** | Routes all HTTP/HTTPS requests and TCP connections through Tor, SOCKS5, or HTTP proxy | Monkey-patches `requests` and `socket.socket` at runtime. Every tool benefits automatically without per-tool configuration. |
| **IPv6 leak blocking** | Prevents IPv6 traffic from bypassing the proxy | Forces `AF_INET` (IPv4) on all sockets and `getaddrinfo` calls. Tor and most SOCKS proxies do not support IPv6, so any IPv6 connection would leak your real address. |
| **DNS leak prevention** | Blocks local DNS resolution that would expose your IP to DNS servers | `socket.gethostbyname` and `socket.getaddrinfo` are patched to **block** (not just warn) hostname resolution when stealth is active. Proxied connections resolve DNS remotely through the SOCKS proxy (`socks5h://` with remote DNS). |
| **DNS resolver TCP forcing** | Forces `dnspython` queries through the proxy | When stealth is active, `dns.resolver.Resolver.resolve()` is forced to use TCP instead of UDP. TCP connections go through the SOCKS proxy; UDP cannot be proxied and would leak your IP. |
| **HTTP fingerprint randomization** | Prevents server-side browser fingerprinting | Every request gets a randomized set of headers: `User-Agent` (15+ realistic browsers), `Accept-Language` (10 locales), `Accept`, `Accept-Encoding`, `Sec-Fetch-*`, `DNT`, and `Upgrade-Insecure-Requests`. |
| **MAC address spoofing** | Hides your hardware identifier on the local network | Generates a random locally-administered MAC and applies it to the active interface via `ip link`. The original MAC is saved and restored when stealth is disabled. |
| **Tor circuit rotation** | Prevents correlation between operations | Sends `SIGNAL NEWNYM` to Tor's ControlPort (9051) to request a fresh circuit with a new exit IP. |

### Kill-Switch

Stealth Mode includes a **kill-switch** that prevents any connection from leaking your real IP:

- Before every HTTP request, ARGUS verifies the proxy is reachable (cached check every 10 seconds). If the proxy is down, the request is **blocked** with a `ConnectionError` instead of falling through to a direct connection.
- At the socket level, `_SmartSocksSocket` never falls back to a direct TCP connection. If the SOCKS proxy fails, the exception propagates up and the connection is refused.
- If PySocks is not installed and a SOCKS/Tor proxy is configured, all requests are blocked with a clear error message.
- On stealth activation, ARGUS automatically verifies your identity by checking the external IP via `api.ipify.org`. If verification fails, it offers to disable stealth to prevent accidental exposure.

### Stealth Menu Options

| Option | Description |
|--------|-------------|
| 1 | Enable via **Tor** (auto-detects or starts Tor on `127.0.0.1:9050`) |
| 2 | Enable via a **custom SOCKS5 proxy** |
| 3 | Enable via a **custom HTTP proxy** |
| 4 | **Disable** Stealth Mode (also restores original MAC if spoofed) |
| 5 | **Test connection** via Tor Project API (confirms Tor routing) |
| 6 | **Show current external IP** (via ipify.org) |
| 7 | **Spoof MAC address** (randomizes MAC on active interface, requires sudo) |
| 8 | **Restore original MAC** |
| 9 | **New Tor identity** (rotates circuit, shows new exit IP. Requires ControlPort 9051) |
| 0 | Back to main menu |

### Supported Proxy Types

| Type | URI format | Notes |
|------|-----------|-------|
| **Tor** | `socks5h://127.0.0.1:9050` | Requires a running Tor service. ARGUS will attempt to auto-start it via `systemctl` if not running. |
| **SOCKS5** | `socks5h://host:port` | Any SOCKS5 proxy. The `h` suffix forces remote DNS resolution. |
| **HTTP** | `http://host:port` | Any HTTP proxy. Socket-level proxying uses HTTP CONNECT. |

### Known Limitations

These are inherent limitations of the proxy/Tor architecture and cannot be fully resolved in software:

| Limitation | Explanation |
|-----------|-------------|
| **RAW/UDP sockets bypass the proxy** | Tools that use `SOCK_RAW` or `SOCK_DGRAM` (Traceroute, Ping Sweep, UDP Flood, ICMP Flood, DNS Flood) cannot be routed through SOCKS. ARGUS displays a warning and requires explicit consent before running these tools in stealth mode. |
| **Your ISP sees Tor usage** | Your ISP can observe that you are connecting to the Tor network (but not what you are doing). To hide Tor usage from your ISP, use a Tor bridge with pluggable transports. |
| **Tor exit node sees unencrypted traffic** | If a tool makes plain HTTP (not HTTPS) requests, the Tor exit node can observe the content. Most ARGUS tools use HTTPS. |
| **Timing correlation** | An adversary monitoring both your entry and exit traffic could theoretically correlate requests by timing. Circuit rotation (option 9) mitigates this. |
| **Stealth Mode scope** | Only ARGUS traffic is anonymized. Your browser, system DNS, and other applications are not affected. |

---

## Tools

### OSINT and Reconnaissance

40 tools for gathering open-source intelligence and mapping attack surfaces.

| # | Tool | Description |
|---|------|-------------|
| 1 | Username Search | Searches for a username across 22+ social platforms and websites to find existing accounts. |
| 2 | Email Lookup | Queries public information associated with an email address, including Gravatar and MX records. |
| 3 | Phone Number Lookup | Validates and analyzes a phone number using Google's libphonenumber: country, carrier, line type (mobile/fixed/VoIP), timezone, and international/national/E.164 formatting. Falls back to prefix-based analysis (100+ countries) if the library is not installed. |
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

21 tools for vulnerability assessment. All require authorization confirmation before use.

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
| 61 | Supabase RLS Auditor | Scans a website using Supabase for exposed project URLs and anon keys, then tests all discoverable tables for Row-Level Security (RLS) misconfigurations. |

### Stress Testing

10 tools for load and resilience testing. All require double authorization (confirmation + "I ACCEPT ALL RESPONSIBILITY").

| # | Tool | Description |
|---|------|-------------|
| 62 | HTTP Flood (GET/POST) | Sends a high volume of HTTP requests with random user-agents and X-Forwarded-For spoofing. Configurable threads (1-200) and duration (1-300s). |
| 63 | Slowloris | Holds concurrent connections open by sending partial HTTP headers, exhausting the server's connection pool. |
| 64 | Slow POST (R.U.D.Y.) | Sends HTTP POST requests with extremely slow body transmission to keep connections occupied. |
| 65 | TCP Connection Flood | Opens a large number of raw TCP connections to a target host and port. |
| 66 | UDP Flood | Sends a continuous stream of random UDP packets to a target host and port. |
| 67 | ICMP Ping Flood | Sends a high volume of ICMP echo request packets (requires root/admin privileges on some systems). |
| 68 | HTTP Slow Read | Sends legitimate HTTP requests but reads the response extremely slowly, tying up server resources. |
| 69 | GoldenEye (Keep-Alive Flood) | Floods with HTTP requests using persistent Keep-Alive connections and randomized headers. |
| 70 | DNS Flood | Floods a DNS server with queries for random subdomains. Configurable threads and duration. |
| 71 | WebSocket Flood | Opens multiple WebSocket connections and floods with masked frames. Configurable connections, duration, and message size. |

### Phishing Simulation

10 tools for authorized phishing simulations and red-team engagements. All require double authorization (confirmation + "I ACCEPT ALL RESPONSIBILITY").

| # | Tool | Description |
|---|------|-------------|
| 72 | Homoglyph Domain Generator | Generates lookalike domains using Unicode/Cyrillic homoglyphs, typo swaps, missing/doubled chars, and QWERTY adjacency. Optionally checks registration. |
| 73 | Phishing URL Analyzer | Scores a suspicious URL (0-100) by checking for IP usage, suspicious TLDs, brand impersonation, encoding, URL shorteners, and urgency keywords. |
| 74 | Email Spoofing Checker | Evaluates a domain's email spoofing resistance by checking SPF, DMARC, DKIM, and MTA-STS records. |
| 75 | Typosquatting Generator | Generates typosquatted domain variations via bit-flips, vowel swaps, dot insertion, prefix/suffix abuse, and hyphenation. Optionally checks registration. |
| 76 | Credential Harvester Template Generator | Generates 8 ready-to-use phishing page templates (Generic Login, Office 365, Google, VPN Portal, WiFi Captive Portal, Password Reset, 2FA, File Share) with configurable callback URL and company name. |
| 77 | URL Obfuscator | Obfuscates a URL using 10+ techniques: decimal/hex/octal IP, @ redirect, subdomain spoof, RTL Unicode override, URL credentials, fragment trick. |
| 78 | Email Header Analyzer | Analyzes raw email headers for phishing indicators: SPF/DKIM/DMARC results, From/Return-Path mismatch, Reply-To mismatch, suspicious mailers, and urgency tactics. Outputs a phishing score. |
| 79 | IDN Homograph Attack Generator | Generates internationalized domain names using Cyrillic character substitution with punycode output. Supports single, multi, and full-script replacement. |
| 80 | Phishing Kit Detector | Scans a suspicious URL for signatures of 11 known phishing kits (GoPhish, Evilginx2, King Phisher, SET, Modlishka, etc.) plus behavioral indicators. |
| 81 | Phishing Campaign Planner | Generates an intelligence report for a target domain: email security posture, mail infrastructure, web presence, ranked pretexts, timing recommendations, and evasion tips. |

---

## Authorization System

ARGUS enforces a three-tier authorization model based on tool category:

| Category | Tools | Authorization |
|----------|-------|---------------|
| OSINT / Reconnaissance | 1-40 | None required. Runs immediately. |
| Exploitation Testing | 41-61 | Single confirmation: you must confirm you have authorization to test the target. |
| Stress Testing | 62-71 | Double confirmation: confirm authorization **and** type `I ACCEPT ALL RESPONSIBILITY`. |
| Phishing Simulation | 72-81 | Double confirmation: confirm authorization **and** type `I ACCEPT ALL RESPONSIBILITY`. |

---

## Built-in Payloads and Wordlists

ARGUS ships with extensive built-in payload databases so no external wordlist files are needed:

- 20 SQL injection payloads (union, blind, time-based, error-based)
- 18 XSS payload vectors
- 67 common directories and files
- 15 open redirect payloads
- 20 LFI / path traversal payloads
- ~130 subdomain names for brute-forcing
- 10 CRLF injection payloads
- 20 SSRF payloads (localhost, cloud metadata, internal services)
- 6 XXE payloads
- 20 OS command injection payloads
- CMS-specific wordlists (WordPress plugins, themes, usernames, passwords)
- Homoglyph and IDN character mappings
- 11 phishing kit signature fingerprints
- 12 WAF/CDN detection signatures
- Service takeover fingerprint database

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
| PySocks | SOCKS proxy support for Stealth Mode (Tor / SOCKS5). **Required for full stealth protection.** | Optional |
| phonenumbers | Phone number validation, carrier/line type detection, formatting (Google libphonenumber) | Optional |

Install all at once with:

```bash
pip install -r requirements.txt
```

Tools with missing optional dependencies will display a warning and skip gracefully rather than crashing.

---

## License

This project is provided as-is for educational and authorized testing purposes only.
