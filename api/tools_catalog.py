TOOLS = [
    # ── OSINT / Reconnaissance (1-40) ──
    {
        "id": 1,
        "name": "Username Search",
        "category": "OSINT / Reconnaissance",
        "description": "Searches for a username across 22+ social platforms and websites to find existing accounts."
    },
    {
        "id": 2,
        "name": "Email Lookup",
        "category": "OSINT / Reconnaissance",
        "description": "Queries public information associated with an email address, including Gravatar and MX records."
    },
    {
        "id": 3,
        "name": "Phone Number Lookup",
        "category": "OSINT / Reconnaissance",
        "description": "Validates and analyzes a phone number: country, carrier, line type (mobile/fixed/VoIP), timezone, and international/national/E.164 formatting."
    },
    {
        "id": 4,
        "name": "IP Address Lookup",
        "category": "OSINT / Reconnaissance",
        "description": "Geolocates an IP address and returns ISP, organization, AS number, and approximate coordinates."
    },
    {
        "id": 5,
        "name": "WHOIS Lookup",
        "category": "OSINT / Reconnaissance",
        "description": "Performs a WHOIS query on a domain to retrieve registrar, creation/expiration dates, name servers, and registrant details."
    },
    {
        "id": 6,
        "name": "DNS Lookup",
        "category": "OSINT / Reconnaissance",
        "description": "Resolves DNS records (A, AAAA, MX, NS, TXT, CNAME) for a given domain."
    },
    {
        "id": 7,
        "name": "Subdomain Enumeration",
        "category": "OSINT / Reconnaissance",
        "description": "Discovers subdomains via certificate transparency logs (crt.sh)."
    },
    {
        "id": 8,
        "name": "HTTP Headers Analysis",
        "category": "OSINT / Reconnaissance",
        "description": "Fetches and displays HTTP response headers, highlighting security-relevant headers (HSTS, CSP, X-Frame-Options)."
    },
    {
        "id": 9,
        "name": "Website Technology Detection",
        "category": "OSINT / Reconnaissance",
        "description": "Fingerprints the technology stack of a website (CMS, frameworks, server software, JavaScript libraries)."
    },
    {
        "id": 10,
        "name": "Port Scanner",
        "category": "OSINT / Reconnaissance",
        "description": "Scans a host for open TCP ports on 16 common services with multi-threaded execution."
    },
    {
        "id": 11,
        "name": "Reverse DNS Lookup",
        "category": "OSINT / Reconnaissance",
        "description": "Resolves an IP address back to its associated hostname (PTR record)."
    },
    {
        "id": 12,
        "name": "MAC Address Lookup",
        "category": "OSINT / Reconnaissance",
        "description": "Identifies the manufacturer/vendor associated with a given MAC address using the IEEE OUI database."
    },
    {
        "id": 13,
        "name": "Email Breach Check",
        "category": "OSINT / Reconnaissance",
        "description": "Checks whether an email address has appeared in known data breaches via Have I Been Pwned."
    },
    {
        "id": 14,
        "name": "Metadata Extractor",
        "category": "OSINT / Reconnaissance",
        "description": "Extracts EXIF metadata from images (GPS coordinates, camera model, timestamps)."
    },
    {
        "id": 15,
        "name": "Social Media Scraper",
        "category": "OSINT / Reconnaissance",
        "description": "Collects publicly available profile information from GitHub and Reddit."
    },
    {
        "id": 16,
        "name": "SSL/TLS Certificate Info",
        "category": "OSINT / Reconnaissance",
        "description": "Retrieves and displays details of a domain's SSL/TLS certificate (issuer, validity, SANs, serial)."
    },
    {
        "id": 17,
        "name": "Wayback Machine Lookup",
        "category": "OSINT / Reconnaissance",
        "description": "Queries the Internet Archive's Wayback Machine for historical snapshots of a URL."
    },
    {
        "id": 18,
        "name": "Robots.txt & Sitemap Analyzer",
        "category": "OSINT / Reconnaissance",
        "description": "Fetches and parses a website's robots.txt and sitemap.xml to reveal structure and access rules."
    },
    {
        "id": 19,
        "name": "Link Extractor",
        "category": "OSINT / Reconnaissance",
        "description": "Crawls a webpage and extracts all internal and external hyperlinks."
    },
    {
        "id": 20,
        "name": "Google Dorks Generator",
        "category": "OSINT / Reconnaissance",
        "description": "Generates 25 targeted Google search queries (dorks) to find exposed files, login pages, and sensitive data."
    },
    {
        "id": 21,
        "name": "Traceroute",
        "category": "OSINT / Reconnaissance",
        "description": "Traces the network route to a target host using ICMP/UDP with TTL increments."
    },
    {
        "id": 22,
        "name": "Hash Identifier & Lookup",
        "category": "OSINT / Reconnaissance",
        "description": "Identifies the type of a hash (MD5, SHA1, SHA256, etc.) and attempts to crack it via online rainbow tables."
    },
    {
        "id": 23,
        "name": "ASN Lookup",
        "category": "OSINT / Reconnaissance",
        "description": "Retrieves Autonomous System Number information for an IP or domain via BGPView."
    },
    {
        "id": 24,
        "name": "Website Screenshot",
        "category": "OSINT / Reconnaissance",
        "description": "Captures a screenshot of a webpage using a headless rendering service."
    },
    {
        "id": 25,
        "name": "Reverse Image Search",
        "category": "OSINT / Reconnaissance",
        "description": "Generates reverse image search URLs for Google, Bing, and TinEye."
    },
    {
        "id": 26,
        "name": "CVE Search",
        "category": "OSINT / Reconnaissance",
        "description": "Searches the MITRE CVE and NIST NVD databases for known vulnerabilities."
    },
    {
        "id": 27,
        "name": "Paste / Code Search",
        "category": "OSINT / Reconnaissance",
        "description": "Generates search links for GitHub, GitLab, Pastebin, and Stack Overflow."
    },
    {
        "id": 28,
        "name": "DNS Zone Transfer Check",
        "category": "OSINT / Reconnaissance",
        "description": "Tests whether a domain's name servers are vulnerable to unauthorized DNS zone transfers (AXFR)."
    },
    {
        "id": 29,
        "name": "SSL/TLS Suite Scanner",
        "category": "OSINT / Reconnaissance",
        "description": "Tests TLS 1.2/1.3 support and enumerates cipher suites."
    },
    {
        "id": 30,
        "name": "Shodan Host Lookup",
        "category": "OSINT / Reconnaissance",
        "description": "Queries the Shodan InternetDB API for open ports, CPEs, and known vulnerabilities."
    },
    {
        "id": 31,
        "name": "Favicon Hash Lookup",
        "category": "OSINT / Reconnaissance",
        "description": "Downloads a site's favicon, computes its MurmurHash3 fingerprint, and generates a Shodan search query."
    },
    {
        "id": 32,
        "name": "DMARC / SPF / DKIM Check",
        "category": "OSINT / Reconnaissance",
        "description": "Queries DNS TXT records for SPF, DMARC, and DKIM (17 common selectors) to assess email security."
    },
    {
        "id": 33,
        "name": "Security.txt Checker",
        "category": "OSINT / Reconnaissance",
        "description": "Fetches and parses /.well-known/security.txt for vulnerability disclosure policy."
    },
    {
        "id": 34,
        "name": "HTTP Methods Discovery",
        "category": "OSINT / Reconnaissance",
        "description": "Probes a target with all HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT) and flags dangerous ones."
    },
    {
        "id": 35,
        "name": "Cloud Storage Finder",
        "category": "OSINT / Reconnaissance",
        "description": "Tests 16 naming mutations across AWS S3, Azure Blob, GCP Storage, and DigitalOcean Spaces for exposed buckets."
    },
    {
        "id": 36,
        "name": "JS Endpoint Extractor",
        "category": "OSINT / Reconnaissance",
        "description": "Fetches JavaScript files from a page and extracts API endpoints, AWS keys, tokens, emails, and IPs via regex."
    },
    {
        "id": 37,
        "name": "WAF / CDN Detector",
        "category": "OSINT / Reconnaissance",
        "description": "Detects 12 WAF/CDN vendors (Cloudflare, Akamai, AWS WAF, Sucuri, Imperva, etc.) from headers, cookies, and response bodies."
    },
    {
        "id": 38,
        "name": "Banner Grabbing",
        "category": "OSINT / Reconnaissance",
        "description": "Connects to specified ports and retrieves service banners (SSH, FTP, SMTP, HTTP, MySQL, Redis, etc.)."
    },
    {
        "id": 39,
        "name": "Subdomain Bruteforce",
        "category": "OSINT / Reconnaissance",
        "description": "DNS brute-forces ~130 common subdomain names with multi-threaded resolution. Supports custom wordlists."
    },
    {
        "id": 40,
        "name": "Ping Sweep / Host Discovery",
        "category": "OSINT / Reconnaissance",
        "description": "Scans a CIDR range or IP range for live hosts via TCP connect on ports 80, 443, and 22."
    },
    {
        "id": 41,
        "name": "Vibe-Coded Site Finder",
        "category": "OSINT / Reconnaissance",
        "description": "Given a project or app name, checks for its existence across 25+ vibe-coding hosting platforms (Vercel, Netlify, Lovable, Replit, Render, Railway, Firebase, Cloudflare Pages, HuggingFace Spaces, Streamlit, etc.)."
    },
    # ── Exploitation Testing (42-62) ──
    {
        "id": 42,
        "name": "SQL Injection Tester",
        "category": "Exploitation Testing",
        "description": "Tests URL parameters with 20 SQL injection payloads (union, blind, time-based, error-based)."
    },
    {
        "id": 43,
        "name": "XSS Scanner (Reflected)",
        "category": "Exploitation Testing",
        "description": "Scans URL parameters with 18 XSS payload vectors including event handlers and encoding bypasses."
    },
    {
        "id": 44,
        "name": "Directory / File Bruteforcer",
        "category": "Exploitation Testing",
        "description": "Discovers hidden directories and files on a web server using a 67-entry wordlist with multi-threading."
    },
    {
        "id": 45,
        "name": "CORS Misconfiguration Scanner",
        "category": "Exploitation Testing",
        "description": "Checks whether a target's CORS policy allows unauthorized cross-origin requests."
    },
    {
        "id": 46,
        "name": "Open Redirect Scanner",
        "category": "Exploitation Testing",
        "description": "Tests URL parameters with 15 open redirect payloads including protocol and hostname confusion tricks."
    },
    {
        "id": 47,
        "name": "LFI / Path Traversal Tester",
        "category": "Exploitation Testing",
        "description": "Tests 20 LFI payloads with 6 file signature detections (path traversal, PHP wrappers, log injection)."
    },
    {
        "id": 48,
        "name": "Subdomain Takeover Check",
        "category": "Exploitation Testing",
        "description": "Checks whether subdomains point to unclaimed external services and are vulnerable to takeover."
    },
    {
        "id": 49,
        "name": "Reverse Shell Generator",
        "category": "Exploitation Testing",
        "description": "Generates reverse shell one-liners in 11 languages (Bash, Python, Perl, PHP, Ruby, PowerShell, Java, Netcat, socat, Lua, xterm)."
    },
    {
        "id": 50,
        "name": "CMS Vulnerability Scanner",
        "category": "Exploitation Testing",
        "description": "Scans for known vulnerabilities in WordPress, Joomla, and Drupal installations."
    },
    {
        "id": 51,
        "name": "Payload Encoder / Decoder",
        "category": "Exploitation Testing",
        "description": "Encodes and decodes payloads in 11 modes (URL, Base64, Hex, HTML entities, Unicode, double URL, MD5/SHA hashing)."
    },
    {
        "id": 52,
        "name": "CRLF Injection Tester",
        "category": "Exploitation Testing",
        "description": "Tests 10 CRLF payloads for header injection and HTTP response splitting."
    },
    {
        "id": 53,
        "name": "SSRF Tester",
        "category": "Exploitation Testing",
        "description": "Tests 20 SSRF payloads targeting localhost, cloud metadata endpoints (AWS/GCP/Azure), and internal services."
    },
    {
        "id": 54,
        "name": "JWT Analyzer",
        "category": "Exploitation Testing",
        "description": "Decodes JWT headers and payloads, checks expiry, analyzes algorithm security, and brute-forces common HMAC secrets."
    },
    {
        "id": 55,
        "name": "Clickjacking Tester",
        "category": "Exploitation Testing",
        "description": "Checks X-Frame-Options and CSP frame-ancestors, generates proof-of-concept HTML if vulnerable."
    },
    {
        "id": 56,
        "name": "XXE Tester",
        "category": "Exploitation Testing",
        "description": "Tests 6 XML External Entity payloads (file read, SSRF, PHP wrappers) against XML-accepting endpoints."
    },
    {
        "id": 57,
        "name": "Command Injection Tester",
        "category": "Exploitation Testing",
        "description": "Tests 20 OS command injection payloads with time-based and output-based detection."
    },
    {
        "id": 58,
        "name": "Host Header Injection",
        "category": "Exploitation Testing",
        "description": "Tests 10 host header manipulation vectors (X-Forwarded-Host, Forwarded, X-Original-URL, etc.)."
    },
    {
        "id": 59,
        "name": "Insecure Cookie Checker",
        "category": "Exploitation Testing",
        "description": "Analyzes all Set-Cookie headers for missing Secure, HttpOnly, and SameSite flags."
    },
    {
        "id": 60,
        "name": "CSRF Token Analyzer",
        "category": "Exploitation Testing",
        "description": "Scans HTML forms for CSRF token presence and quality, checks meta tags and CORS headers."
    },
    {
        "id": 61,
        "name": "Prototype Pollution Scanner",
        "category": "Exploitation Testing",
        "description": "Tests prototype pollution via query parameters and JSON body payloads."
    },
    {
        "id": 62,
        "name": "Supabase RLS Auditor",
        "category": "Exploitation Testing",
        "description": "Scans a website using Supabase for exposed project URLs and anon keys, then tests all discoverable tables for Row-Level Security (RLS) misconfigurations."
    },
    # ── Stress Testing / Denial of Service (63-72) ──
    {
        "id": 63,
        "name": "HTTP Flood (GET/POST)",
        "category": "Stress Testing",
        "description": "Sends a high volume of HTTP requests with random user-agents and X-Forwarded-For spoofing. Configurable threads and duration."
    },
    {
        "id": 64,
        "name": "Slowloris",
        "category": "Stress Testing",
        "description": "Holds concurrent connections open by sending partial HTTP headers, exhausting the server's connection pool."
    },
    {
        "id": 65,
        "name": "Slow POST (R.U.D.Y.)",
        "category": "Stress Testing",
        "description": "Sends HTTP POST requests with extremely slow body transmission to keep connections occupied."
    },
    {
        "id": 66,
        "name": "TCP Connection Flood",
        "category": "Stress Testing",
        "description": "Opens a large number of raw TCP connections to a target host and port."
    },
    {
        "id": 67,
        "name": "UDP Flood",
        "category": "Stress Testing",
        "description": "Sends a continuous stream of random UDP packets to a target host and port."
    },
    {
        "id": 68,
        "name": "ICMP Ping Flood",
        "category": "Stress Testing",
        "description": "Sends a high volume of ICMP echo request packets (requires root/admin privileges on some systems)."
    },
    {
        "id": 69,
        "name": "HTTP Slow Read",
        "category": "Stress Testing",
        "description": "Sends legitimate HTTP requests but reads the response extremely slowly, tying up server resources."
    },
    {
        "id": 70,
        "name": "GoldenEye (Keep-Alive Flood)",
        "category": "Stress Testing",
        "description": "Floods with HTTP requests using persistent Keep-Alive connections and randomized headers."
    },
    {
        "id": 71,
        "name": "DNS Flood",
        "category": "Stress Testing",
        "description": "Floods a DNS server with queries for random subdomains. Configurable threads and duration."
    },
    {
        "id": 72,
        "name": "WebSocket Flood",
        "category": "Stress Testing",
        "description": "Opens multiple WebSocket connections and floods with masked frames. Configurable connections, duration, and message size."
    },
    # ── Phishing Simulation (73-82) ──
    {
        "id": 73,
        "name": "Homoglyph Domain Generator",
        "category": "Phishing Simulation",
        "description": "Generates lookalike domains using Unicode/Cyrillic homoglyphs, typo swaps, missing/doubled chars, and QWERTY adjacency."
    },
    {
        "id": 74,
        "name": "Phishing URL Analyzer",
        "category": "Phishing Simulation",
        "description": "Scores a suspicious URL (0-100) by checking for IP usage, suspicious TLDs, brand impersonation, encoding, URL shorteners, and urgency keywords."
    },
    {
        "id": 75,
        "name": "Email Spoofing Checker",
        "category": "Phishing Simulation",
        "description": "Evaluates a domain's email spoofing resistance by checking SPF, DMARC, DKIM, and MTA-STS records."
    },
    {
        "id": 76,
        "name": "Typosquatting Generator",
        "category": "Phishing Simulation",
        "description": "Generates typosquatted domain variations via bit-flips, vowel swaps, dot insertion, prefix/suffix abuse, and hyphenation."
    },
    {
        "id": 77,
        "name": "Credential Harvester Template Generator",
        "category": "Phishing Simulation",
        "description": "Generates 8 ready-to-use phishing page templates (Generic Login, Office 365, Google, VPN Portal, WiFi Captive Portal, Password Reset, 2FA, File Share)."
    },
    {
        "id": 78,
        "name": "URL Obfuscator",
        "category": "Phishing Simulation",
        "description": "Obfuscates a URL using 10+ techniques: decimal/hex/octal IP, @ redirect, subdomain spoof, RTL Unicode override, URL credentials, fragment trick."
    },
    {
        "id": 79,
        "name": "Email Header Analyzer",
        "category": "Phishing Simulation",
        "description": "Analyzes raw email headers for phishing indicators: SPF/DKIM/DMARC results, From/Return-Path mismatch, Reply-To mismatch, suspicious mailers."
    },
    {
        "id": 80,
        "name": "IDN Homograph Attack Generator",
        "category": "Phishing Simulation",
        "description": "Generates internationalized domain names using Cyrillic character substitution with punycode output."
    },
    {
        "id": 81,
        "name": "Phishing Kit Detector",
        "category": "Phishing Simulation",
        "description": "Scans a suspicious URL for signatures of 11 known phishing kits (GoPhish, Evilginx2, King Phisher, SET, Modlishka, etc.)."
    },
    {
        "id": 82,
        "name": "Phishing Campaign Planner",
        "category": "Phishing Simulation",
        "description": "Generates an intelligence report for a target domain: email security posture, mail infrastructure, web presence, ranked pretexts, and timing recommendations."
    },
]
