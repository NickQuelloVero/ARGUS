# ARGUS - All-seeing Recon & General Unified Security

```
     █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
    ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
    ███████║██████╔╝██║  ███╗██║   ██║███████╗
    ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
    ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
```

ARGUS is a comprehensive terminal-based OSINT and security reconnaissance toolkit written in Python. It provides 49 tools organized in three categories: reconnaissance, exploitation testing, and stress testing, all accessible through an interactive menu.

---

## Table of Contents

- [Disclaimer](#disclaimer)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Tools](#tools)
  - [OSINT and Reconnaissance](#osint-and-reconnaissance)
  - [Exploitation Testing](#exploitation-testing)
  - [Stress Testing](#stress-testing)
- [Dependencies](#dependencies)
- [License](#license)

---

## Disclaimer

This tool is intended for authorized security testing, educational purposes, and legitimate penetration testing engagements only. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The authors assume no liability for misuse.

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

An interactive menu will appear with all available tools organized by category. Enter the number corresponding to the tool you want to use and follow the on-screen prompts. Press `0` to exit. You can interrupt any running operation with `Ctrl+C`.

---

## Tools

### OSINT and Reconnaissance

| # | Tool | Description |
|---|------|-------------|
| 1 | Username Search | Searches for a username across 30+ social platforms and websites to find existing accounts. |
| 2 | Email Lookup | Queries public information associated with an email address, including related services and breach exposure. |
| 3 | Phone Number Lookup | Retrieves carrier, location, and line type information for a given phone number. |
| 4 | IP Address Lookup | Geolocates an IP address and returns ISP, organization, AS number, and approximate coordinates. |
| 5 | WHOIS Lookup | Performs a WHOIS query on a domain to retrieve registrar, creation/expiration dates, name servers, and registrant details. |
| 6 | DNS Lookup | Resolves DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) for a given domain. |
| 7 | Subdomain Enumeration | Discovers subdomains of a target domain using wordlist-based brute-forcing and public sources. |
| 8 | HTTP Headers Analysis | Fetches and displays the HTTP response headers of a URL, highlighting security-relevant headers. |
| 9 | Website Technology Detection | Fingerprints the technology stack of a website (CMS, frameworks, server software, JavaScript libraries). |
| 10 | Port Scanner | Scans a host for open TCP ports with configurable port ranges and multi-threaded execution. |
| 11 | Reverse DNS Lookup | Resolves an IP address back to its associated hostname (PTR record). |
| 12 | MAC Address Lookup | Identifies the manufacturer/vendor associated with a given MAC address using the IEEE OUI database. |
| 13 | Email Breach Check | Checks whether an email address has appeared in known data breaches via public breach databases. |
| 14 | Metadata Extractor | Extracts EXIF metadata from images (GPS coordinates, camera model, timestamps) fetched from a URL. |
| 15 | Social Media Scraper | Collects publicly available profile information from major social media platforms given a username. |
| 16 | SSL/TLS Certificate Info | Retrieves and displays details of a domain's SSL/TLS certificate (issuer, validity, SANs, fingerprint). |
| 17 | Wayback Machine Lookup | Queries the Internet Archive's Wayback Machine for historical snapshots of a URL. |
| 18 | Robots.txt and Sitemap Analyzer | Fetches and parses a website's robots.txt and sitemap.xml files to reveal structure and access rules. |
| 19 | Link Extractor | Crawls a webpage and extracts all internal and external hyperlinks. |
| 20 | Google Dorks Generator | Generates targeted Google search queries (dorks) for a given domain to find exposed files, login pages, and sensitive data. |
| 21 | Traceroute | Traces the network route from your machine to a target host, showing each hop and latency. |
| 22 | Hash Identifier and Lookup | Identifies the type of a hash (MD5, SHA1, SHA256, etc.) and attempts to crack it using online rainbow tables. |
| 23 | ASN Lookup | Retrieves the Autonomous System Number information for an IP or domain, including prefix and organization details. |
| 24 | Website Screenshot | Captures a screenshot of a webpage using a headless rendering service. |
| 25 | Reverse Image Search | Generates reverse image search URLs for Google, Yandex, and TinEye given an image URL. |
| 26 | CVE Search | Searches the CVE (Common Vulnerabilities and Exposures) database for known vulnerabilities by keyword or CVE ID. |
| 27 | Paste / Code Search | Searches public paste sites and code repositories for leaked data or mentions of a target keyword. |
| 28 | DNS Zone Transfer Check | Tests whether a domain's name servers are vulnerable to unauthorized DNS zone transfers (AXFR). |
| 29 | SSL/TLS Suite Scanner | Analyzes a domain's SSL/TLS configuration including supported protocols, cipher suites, and security grade. |
| 30 | Shodan Host Lookup | Queries the Shodan API for information about a host's open ports, services, and vulnerabilities (requires API key). |

### Exploitation Testing

| # | Tool | Description |
|---|------|-------------|
| 31 | SQL Injection Tester | Tests URL parameters for common SQL injection vulnerabilities using a set of standard payloads. |
| 32 | XSS Scanner (Reflected) | Scans URL parameters for reflected cross-site scripting vulnerabilities using multiple payload vectors. |
| 33 | Directory / File Bruteforcer | Attempts to discover hidden directories and files on a web server using a wordlist. |
| 34 | CORS Misconfiguration Scanner | Checks whether a target's CORS policy is misconfigured to allow unauthorized cross-origin requests. |
| 35 | Open Redirect Scanner | Tests URL parameters for open redirect vulnerabilities that could be used in phishing attacks. |
| 36 | LFI / Path Traversal Tester | Tests for Local File Inclusion and path traversal vulnerabilities using common traversal sequences. |
| 37 | Subdomain Takeover Check | Checks whether subdomains point to unclaimed external services and are vulnerable to takeover. |
| 38 | Reverse Shell Generator | Generates reverse shell one-liners in multiple languages (Bash, Python, Netcat, PHP, etc.) for a given IP and port. |
| 39 | CMS Vulnerability Scanner | Scans for known vulnerabilities and misconfigurations in popular CMS platforms (WordPress, Joomla, Drupal). |
| 40 | Payload Encoder / Decoder | Encodes and decodes payloads in various formats (Base64, URL encoding, HTML entities, hex, etc.). |

### Stress Testing

| # | Tool | Description |
|---|------|-------------|
| 41 | HTTP Flood (GET/POST) | Sends a high volume of HTTP GET or POST requests to a target URL using multiple threads. |
| 42 | Slowloris | Holds many concurrent connections open by sending partial HTTP headers, exhausting the server's connection pool. |
| 43 | Slow POST (R.U.D.Y.) | Sends HTTP POST requests with an extremely slow body transmission to keep connections occupied. |
| 44 | TCP Connection Flood | Opens a large number of raw TCP connections to a target host and port. |
| 45 | UDP Flood | Sends a continuous stream of UDP packets to a target host and port. |
| 46 | ICMP Ping Flood | Sends a high volume of ICMP echo request packets to a target (requires root privileges). |
| 47 | HTTP Slow Read | Sends legitimate HTTP requests but reads the response extremely slowly, tying up server resources. |
| 48 | GoldenEye (Keep-Alive Flood) | Floods a target with HTTP requests using keep-alive connections and randomized headers to bypass basic protections. |

---

## Dependencies

All dependencies are listed in `requirements.txt`:

| Package | Purpose |
|---------|---------|
| requests | HTTP requests for all web-based tools |
| python-whois | WHOIS domain lookups |
| dnspython | DNS record resolution and zone transfer checks |
| beautifulsoup4 | HTML parsing for scraping, link extraction, and tech detection |
| colorama | Colored terminal output |
| Pillow | Image processing and EXIF metadata extraction |
| shodan | Shodan API integration for host lookups |

Install all at once with:

```bash
pip install -r requirements.txt
```

Some tools have optional dependencies. If a required library is not installed, the tool will display a warning and skip gracefully rather than crashing.

---

## License

This project is provided as-is for educational and authorized testing purposes only.
