# byp4xx.py

Unified 40x/401/403 access-control bypass scanner. Fires known header, path,
method, IP-spoof, geo, and appliance-CVE bypass techniques at a protected URL,
then verifies + confidence-scores every hit to kill false positives.

**Authorized targets only.** This finds *misconfigurations* — it is not a
skeleton key. A site with proper source-IP ACLs and real auth is not bypassable
by it, no matter how many IPs you spray.

## Do I need to install anything?

- **Required:** Python 3 + `requests`
  ```
  pip install requests
  ```
- **Not required:** the IP database. You only need it for **geo mode**
  (`--geo-db`). Normal bypass runs need no IP list.

## Optional: geo mode (spoof real in-country IPs)

Only if you want to test a **geo/country ACL**. Download the DB once:

```
git clone https://github.com/iplocate/ip-address-databases
# use ip-to-country/ip-to-country.csv.zip
```

Then the TLD picks the country automatically:

```
python3 byp4xx.py -d site.tn --geo-db ip-to-country/ip-to-country.csv.zip -k
#  .tn -> Tunisian IPs,  .fr -> French IPs,  .de -> German ...
```

Override the country: `--geo-country US,FR`. Cap per country: `--geo-limit 100`.

## Usage

```
python3 byp4xx.py -u https://target.com/admin -t 10 --delay 0.2 -k
python3 byp4xx.py -d target.tn --geo-db ip-to-country.csv.zip -k
python3 byp4xx.py -l urls.txt -o hits.txt --json hits.json --only-hits
```

Target input (pick one): `-u <url>` | `-d <domain>` | `-l <file>`

Recommended flags: `-t 10 --delay 0.2 -k` — polite rate (avoid IP bans),
skip TLS verification on self-signed appliances.

### Key options

| Flag | Purpose |
|------|---------|
| `-t N` | threads (default 20) |
| `--delay S` | per-request jittered delay — avoids rate-limit/CDN bans |
| `-k` | skip TLS verification |
| `-x URL` | proxy (e.g. Burp `http://127.0.0.1:8080`) |
| `--internal-ip IP` | spoof a known internal/allowlisted IP across all trust headers (repeatable) |
| `--origin-ip IP` | hit a candidate origin IP directly with the target Host header — bypass the CDN/WAF edge (repeatable) |
| `--origin-list FILE` | file of candidate origin IPs, one per line |
| `--geo-db PATH` | iplocate ip-to-country CSV/zip for geo spoofing |
| `--geo-country CC` | force country code(s); default = inferred from domain TLD |
| `--no-cve` | skip appliance/WAF auth-bypass CVE probes |
| `--only-hits` | print only successful bypasses |
| `--min-confidence 0-1` | drop hits below this score (default 0.80) |

## What it tries

- Path mutations (traversal, encoding, matrix params, case, unicode, backslash)
- HTTP method / verb tampering + method-override headers
- IP trust-header spoofing (loopback obfuscations + RFC1918 + docker/k8s/ECS +
  cloud metadata), IP-SHOTGUN (all headers at once), PATH+IP combos
- Geo IP spoofing from the country DB (`GEO-SPOOF`, `GEO-RFC7239`)
- URL/prefix override headers (`X-Original-URL`, `X-Forwarded-Prefix`), Host swap
- Modern header bypasses: Next.js `X-Middleware-Subrequest` (CVE-2025-29927),
  Spring prefix collapse, Akamai debug, `X-Accel-Redirect`, Early-Data 0-RTT
- **Appliance/WAF auth-bypass CVEs** (verifiable, CVE-labeled):
  FortiOS `CVE-2022-40684`, F5 BIG-IP `CVE-2022-1388` / `CVE-2020-5902`,
  Citrix `CVE-2019-19781`, Fortinet SSL-VPN `CVE-2018-13379`, Ivanti
  `CVE-2023-46805`.

## Bypassing Cloudflare / Akamai / any CDN-WAF (origin-direct)

There is no header-CVE that bypasses Cloudflare. The real bypass is to reach
the **origin server directly**, skipping the edge. Two steps:

1. **Discover** candidate origin IPs (separate — use your recon tooling):
   - `cloud-recon --cf-bypass <domain>` / CloudFail
   - crt.sh + Censys/Shodan cert search, DNS history (SecurityTrails/ViewDNS)
   - subdomains that resolve off-CDN (`mail.`, `dev.`, `origin.`, direct A records)
2. **Test** them with byp4xx — it connects to each IP with the site's Host
   header and reports if the origin serves the protected resource WAF-free:
   ```
   python3 byp4xx.py -u https://target.com/admin --origin-list origins.txt -k
   python3 byp4xx.py -u https://target.com/admin --origin-ip 203.0.113.9 -k
   ```
   `ORIGIN-DIRECT` hits = the edge is bypassed. TLS verification is auto-disabled
   (the origin cert won't match a bare IP). Works when the origin serves the
   vhost by Host header (most nginx/Apache) — an origin that strictly requires
   SNI match may not answer.

### Not included / honest limits

- Origin discovery itself is not built in — feed IPs from recon. byp4xx tests
  candidates, it does not enumerate them.
- Header/IP spoofing works **only** if the backend trusts a client-supplied
  header for its access decision. Correct configs read the real socket IP and
  ignore it.
