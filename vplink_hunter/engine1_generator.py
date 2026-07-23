"""Engine 1 — Proxy List Scraper with source scoring, TTL-based re-fetch,
subnet scanning, and port prioritization.

Fetches fresh proxy candidates from quality public sources.
Re-fetches each source after its TTL expires so the pipeline never starves."""

import asyncio
import base64
import json
import random
import re
import subprocess
import time

BLOCKED_SUBNETS = [
    "0.",
    "10.", "127.", "169.254.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "100.64.", "100.65.", "100.66.", "100.67.", "100.68.", "100.69.",
    "100.70.", "100.71.", "100.72.", "100.73.", "100.74.", "100.75.",
    "100.76.", "100.77.", "100.78.", "100.79.", "100.80.", "100.81.",
    "100.82.", "100.83.", "100.84.", "100.85.", "100.86.", "100.87.",
    "100.88.", "100.89.", "100.90.", "100.91.", "100.92.", "100.93.",
    "100.94.", "100.95.", "100.96.", "100.97.", "100.98.", "100.99.",
    "100.100.", "100.101.", "100.102.", "100.103.", "100.104.", "100.105.",
    "100.106.", "100.107.", "100.108.", "100.109.", "100.110.", "100.111.",
    "100.112.", "100.113.", "100.114.", "100.115.", "100.116.", "100.117.",
    "100.118.", "100.119.", "100.120.", "100.121.", "100.122.", "100.123.",
    "100.124.", "100.125.", "100.126.", "100.127.",
    "192.0.0.", "192.0.2.", "192.88.99.",
    "198.18.", "198.19.", "198.51.100.",
    "203.0.113.",
    "6.", "7.", "11.", "21.", "22.",
    "26.", "28.", "29.", "30.", "33.",
    "48.", "53.", "57.",
    "214.", "215.",
    "224.", "225.", "226.", "227.", "228.", "229.", "230.",
    "231.", "232.", "233.", "234.", "235.", "236.", "237.", "238.",
    "239.", "240.", "241.", "242.", "243.", "244.", "245.", "246.",
    "247.", "248.", "249.", "250.", "251.", "252.", "253.", "254.", "255.",
]

# ── Scrape sources ────────────────────────────────────────────────
# Each tuple: (name, url, ttl_seconds)
# GitHub raw files: TTL 10-15min (they update periodically)
# HTML scrapers: TTL 5min (live page, can scrape more often)
PROXY_SOURCES: list[tuple[str, str, int]] = [
    # GitHub raw lists — update every 30-60 min, re-fetch every 10 min
    ("proxyscrape_v4", "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text", 300),
    ("proxifly_http", "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt", 300),
    ("monosans_http", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", 300),
    ("proxripper_http", "https://raw.githubusercontent.com/mohammedcha/ProxRipper/main/full_proxies/http.txt", 300),
    ("proxygenerator_stable", "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/MostStable/http.txt", 300),
    ("ianlusule_http", "https://raw.githubusercontent.com/Ian-Lusule/Proxies/main/proxies/http.txt", 300),
    ("vpslabcloud_http", "https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/http_all.txt", 300),
    ("clearproxy_http", "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/http/raw/all.txt", 300),
    ("solispi_http", "https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/http.txt", 300),
    ("thespeedx_http", "https://raw.githubusercontent.com/TheSpeedX/proxy-list/master/http.txt", 300),
    ("proxyscrape_http_mirror", "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/http/data.txt", 300),
    ("proxyscrape_https_mirror", "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/https/data.txt", 300),
    ("proxyscrape_all_mirror", "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.txt", 300),
    ("getfreeproxy_http", "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/http.txt", 300),
    ("getfreeproxy_https", "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/https.txt", 300),
    ("stormsia_http", "https://raw.githubusercontent.com/stormsia/proxy-list/main/http.txt", 300),
    ("vpslabcloud_http_elite", "https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/http_elite.txt", 300),
    ("clarketm_proxy_list", "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", 300),
    ("jetkai_proxy_list", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt", 300),
    ("shiftytr_proxy_list", "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt", 300),
    ("sunny9577_proxy_scraper", "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt", 300),
    ("hookzof_proxy_list", "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", 300),
    ("komutan234_http", "https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/http.txt", 300),
    ("vakhov_http", "https://vakhov.github.io/fresh-proxy-list/http.txt", 300),
    ("vakhov_https", "https://vakhov.github.io/fresh-proxy-list/https.txt", 300),
    ("theriturajps_proxy_list", "https://raw.githubusercontent.com/theriturajps/proxy-list/main/proxies.txt", 300),
    ("fyvri_http", "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/http.txt", 300),
    ("proxy4parsing_http", "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt", 300),
    ("dinoz0rg_scraped_http", "https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/scraped_proxies/http.txt", 300),
    ("dinoz0rg_checked_http", "https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/checked_proxies/http.txt", 300),
    ("thordata_http", "https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/http.txt", 300),
    ("proxyscraper_http", "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/http.txt", 300),
    ("fyvri_https", "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/https.txt", 300),
    ("hw630590_http", "https://raw.githubusercontent.com/hw630590/free-proxies/refs/heads/main/proxies/http/http.txt", 300),
    ("hw630590_https", "https://raw.githubusercontent.com/hw630590/free-proxies/refs/heads/main/proxies/https/https.txt", 300),
    ("databay_labs_http", "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt", 300),
    ("syscallh00k_http", "https://raw.githubusercontent.com/Syscallh00k/proxy-list/main/http.txt", 300),
    ("zloi_user_http", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt", 300),
    ("zaeem20_http", "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt", 300),
    # HTML scraper sources — TTL 300s (5 min), pages update frequently
    ("hideip_me_http", "https://hideip.me/us/proxy/list/?t=http&p=1", 120),
    ("hideip_me_https", "https://hideip.me/us/proxy/list/?t=https&p=1", 120),
    ("premproxy_http", "https://premproxy.com/list/http-01.htm", 120),
    ("premproxy_https", "https://premproxy.com/list/https-01.htm", 120),
]

IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:\s]\s*(\d+)")
PROXYDB_RE = re.compile(r'href="/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+)#(http|https)"')
TOTAL_RE = re.compile(r"Showing \d+ to \d+ of (\d+) total")

# ── JS deobfuscation helpers (for ProxyNova) ──────────────────────

def _js_arith(expr: str) -> int:
    expr = expr.strip()
    m = re.match(r'(\d+)\s*([+-])\s*(\d+)', expr)
    if m:
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        return a + b if op == '+' else a - b
    try:
        return int(expr)
    except ValueError:
        return 0


def _apply_methods(base: str, methods: str) -> str:
    while methods:
        m = re.match(r'\.substring\(([^,]+),\s*([^)]+)\)\s*(.*)', methods)
        if m:
            a, b = _js_arith(m.group(1)), _js_arith(m.group(2))
            base = base[a:b]
            methods = m.group(3).strip()
            continue
        m = re.match(r'\.repeat\((\d+)\)\s*(.*)', methods)
        if m:
            base = base * int(m.group(1))
            methods = m.group(2).strip()
            continue
        m = re.match(r'\.split\(""\)\.reverse\(\)\.join\(""\)\s*(.*)', methods)
        if m:
            base = base[::-1]
            methods = m.group(1).strip()
            continue
        m = re.match(r'\.concat\((.+)\)\s*(.*)', methods)
        if m:
            arg = m.group(1).strip()
            if arg.startswith('"') and arg.endswith('"'):
                base = base + arg[1:-1]
            else:
                base = base + _js_eval(arg)
            methods = m.group(2).strip()
            continue
        break
    return base


def _js_eval(expr: str) -> str:
    expr = expr.strip()
    if expr.startswith('"') and expr.endswith('"'):
        return expr[1:-1]
    m = re.fullmatch(r'atob\("([^"]*)"\)', expr)
    if m:
        try:
            return base64.b64decode(m.group(1)).decode()
        except Exception:
            return ""
    m = re.fullmatch(
        r'\[([^\]]+)\]\.map\(\(([^)]+)\)\s*=>\s*String\.fromCharCode\(([^)]+)\)\)\.join\(""\)',
        expr,
    )
    if m:
        codes = [int(x.strip()) for x in m.group(1).split(',')]
        return ''.join(chr(c) for c in codes if 32 <= c <= 126)
    m = re.match(r'("[^"]*")(.*)', expr)
    if m:
        return _apply_methods(m.group(1)[1:-1], m.group(2).strip())
    m = re.match(r'\[([^\]]+)\](.*)', expr)
    if m:
        codes = [int(x.strip()) for x in m.group(1).split(',')]
        base = ''.join(chr(c) for c in codes if 32 <= c <= 126)
        return _apply_methods(base, m.group(2).strip())
    return expr


def _match_parens(text: str, start: int) -> int:
    count = 1
    for i in range(start, len(text)):
        if text[i] == '(':
            count += 1
        elif text[i] == ')':
            count -= 1
            if count == 0:
                return i
    return -1


def _valid_ip(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

# ── Source scoring ────────────────────────────────────────────────
SOURCE_STATS: dict[str, dict] = {}
MIN_PASS_RATE = 0.05
MIN_SAMPLES = 100

SOURCE_E3_STATS: dict[str, dict] = {}

FAILED_IPS: dict[tuple[str, int], float] = {}
FAILED_TTL = 3600  # 60 min — don't re-test a dead IP too aggressively

WORKING_SUBNETS: set[str] = set()
SUBNET_E3: dict[str, dict] = {}
EXPLORE_PCT = 10  # try unknown subnets this % of the time (exploration)

PORT_HITS: dict[int, int] = {}
PORT_TRIES: dict[int, int] = {}
LAST_CLEANUP: float = 0.0
CLEANUP_INTERVAL = 300

_WEIGHTED_SOURCES: list[tuple[str, str]] | None = None

# ── Source TTL tracking ───────────────────────────────────────────
# Each source has a TTL. After it expires, we re-fetch.
# Before re-fetch, we clear FAILED_IPS for IPs from that source's last fetch
# so stale addresses get a fresh chance.
SOURCE_LAST_FETCH: dict[str, float] = {}  # source_name -> timestamp
SOURCE_SEEN_IPS: dict[str, set[tuple[str, int]]] = {}  # source_name -> set of (ip,port)


def subnet_key(ip: str) -> str:
    return ".".join(ip.split(".")[:3])


def mark_failed(ip: str, port: int):
    FAILED_IPS[(ip, port)] = time.time()


def mark_working(ip: str, port: int):
    sk = subnet_key(ip)
    WORKING_SUBNETS.add(sk)


def record_port_test(port: int, success: bool):
    PORT_TRIES[port] = PORT_TRIES.get(port, 0) + 1
    if success:
        PORT_HITS[port] = PORT_HITS.get(port, 0) + 1


def best_ports(n: int = 10) -> list[int]:
    scored = [(p, PORT_HITS.get(p, 0) / max(PORT_TRIES.get(p, 1), 1))
              for p in set(PORT_HITS.keys()) | set(PORT_TRIES.keys())]
    scored.sort(key=lambda x: -x[1])
    return [p for p, _ in scored[:n]]


def _source_e3_weight(name: str) -> float:
    e3 = SOURCE_E3_STATS.get(name)
    if not e3 or e3["total"] < 5:
        return 0.5
    rate = e3["passed"] / max(e3["total"], 1)
    return rate


def weighted_sources() -> list[tuple[str, str, int]]:
    scored = [(n, u, t, _source_e3_weight(n)) for n, u, t in PROXY_SOURCES]
    scored.sort(key=lambda x: -x[3])
    return [(n, u, t) for n, u, t, _ in scored]


def should_skip_ip(ip: str, port: int) -> bool:
    key = (ip, port)
    if key in FAILED_IPS:
        age = time.time() - FAILED_IPS[key]
        if age < FAILED_TTL:
            return True
        del FAILED_IPS[key]
    sk = subnet_key(ip)
    if len(WORKING_SUBNETS) > 200 and sk not in WORKING_SUBNETS:
        if random.randint(1, 100) > EXPLORE_PCT:
            return True
    return False


def port_ok(port: int) -> bool:
    tries = PORT_TRIES.get(port, 0)
    if tries < 200:
        return True
    hits = PORT_HITS.get(port, 0)
    rate = hits / max(tries, 1)
    return rate >= 0.01


def record_e3_result(source: str, ip: str, success: bool):
    if source:
        s = SOURCE_E3_STATS.setdefault(source, {"total": 0, "passed": 0})
        s["total"] += 1
        if success:
            s["passed"] += 1
    sk = subnet_key(ip)
    se = SUBNET_E3.setdefault(sk, {"total": 0, "passed": 0})
    se["total"] += 1
    if success:
        se["passed"] += 1


def cleanup_cache():
    global _WEIGHTED_SOURCES
    now = time.time()
    expired = [k for k, ts in FAILED_IPS.items() if now - ts >= FAILED_TTL]
    for k in expired:
        del FAILED_IPS[k]
    for p in list(PORT_TRIES.keys()):
        if PORT_TRIES[p] >= 100:
            PORT_TRIES[p] = max(1, PORT_TRIES[p] // 2)
            PORT_HITS[p] = max(1, PORT_HITS.get(p, 0) // 2)
    for sk in list(SUBNET_E3.keys()):
        se = SUBNET_E3[sk]
        if se["total"] >= 50:
            se["total"] = max(1, se["total"] // 2)
            se["passed"] = max(1, se["passed"] // 2)
    _WEIGHTED_SOURCES = weighted_sources()


def maybe_cleanup():
    global LAST_CLEANUP
    now = time.time()
    if now - LAST_CLEANUP >= CLEANUP_INTERVAL:
        cleanup_cache()
        LAST_CLEANUP = now


def should_skip_source(source: str) -> bool:
    stats = SOURCE_STATS.get(source)
    if not stats or stats["total"] < MIN_SAMPLES:
        return False
    rate = stats["passed"] / max(stats["total"], 1)
    return rate < MIN_PASS_RATE


def record_source_result(source: str, total: int, passed: int):
    if source not in SOURCE_STATS:
        SOURCE_STATS[source] = {"total": 0, "passed": 0}
    SOURCE_STATS[source]["total"] += total
    SOURCE_STATS[source]["passed"] += passed


def source_pass_rate(source: str) -> str:
    stats = SOURCE_STATS.get(source)
    if not stats or stats["total"] == 0:
        return "?/? (---)"
    return f"{stats['passed']}/{stats['total']} ({stats['passed']/stats['total']*100:.0f}%)"


def _blocked_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in BLOCKED_SUBNETS)


# ── Source freshness management ───────────────────────────────────

def _source_ttl(name: str) -> int:
    for n, _, ttl in PROXY_SOURCES:
        if n == name:
            return ttl
    return 600  # default 10 min


def _source_is_stale(name: str, now: float | None = None) -> bool:
    if now is None:
        now = time.time()
    last = SOURCE_LAST_FETCH.get(name, 0.0)
    ttl = _source_ttl(name)
    return (now - last) >= ttl


def force_stale_all():
    """Force all sources to be re-fetched on next scrape_lists call."""
    now = time.time() - 9999
    for name, _, _ in PROXY_SOURCES:
        SOURCE_LAST_FETCH[name] = now
    for name in ("proxydb", "geonode", "proxynova", "fpln"):
        SOURCE_LAST_FETCH[name] = now


def _clear_source_ips(name: str):
    """Clear FAILED_IPS for IPs last seen from this source so they get
    retested on re-fetch."""
    seen = SOURCE_SEEN_IPS.get(name)
    if seen:
        for ip_port in seen:
            FAILED_IPS.pop(ip_port, None)


async def fetch_url(url: str, timeout: int = 10) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sL", "--max-time", str(timeout),
            url, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
        return out.decode(errors="replace")
    except Exception:
        return ""


async def scrape_proxydb(max_pages: int = 10) -> list[tuple[str, int, str]]:
    source = "proxydb"
    results = []
    base = "https://proxydb.net/?protocol=http&offset="
    first = await fetch_url(base + "0")
    if not first:
        return results
    total_match = TOTAL_RE.search(first)
    total_proxies = int(total_match.group(1)) if total_match else 0
    total_pages = min(max_pages, (total_proxies + 29) // 30)
    seen = set()
    for match in PROXYDB_RE.finditer(first):
        ip, port_str, _ = match.groups()
        port = int(port_str)
        key = (ip, port)
        if key not in seen and not _blocked_ip(ip):
            seen.add(key)
            results.append((ip, port, source))
    for page in range(1, total_pages):
        await asyncio.sleep(0.5)
        text = await fetch_url(f"{base}{page * 30}")
        if not text:
            continue
        for match in PROXYDB_RE.finditer(text):
            ip, port_str, _ = match.groups()
            port = int(port_str)
            key = (ip, port)
            if key not in seen and not _blocked_ip(ip):
                seen.add(key)
                results.append((ip, port, source))
    return results


async def scrape_geonode(max_pages: int = 3) -> list[tuple[str, int, str]]:
    source = "geonode"
    results = []
    base = "https://proxylist.geonode.com/api/proxy-list?limit=500&sort_by=responseTime&sort_type=asc&page="
    text = await fetch_url(base + "1", timeout=15)
    if not text:
        return results
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return results
    total = data.get("total", 0)
    total_pages = min(max_pages, (total + 499) // 500)
    seen = set()
    for page in range(1, total_pages + 1):
        if page > 1:
            await asyncio.sleep(0.3)
            text = await fetch_url(f"{base}{page}", timeout=15)
            if not text:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
        for proxy in data.get("data", []):
            protocols = proxy.get("protocols", [])
            if not any(p in protocols for p in ("http", "https")):
                continue
            ip = proxy.get("ip", "")
            port = int(proxy.get("port", 0))
            if port == 0:
                continue
            key = (ip, port)
            if key not in seen and not _blocked_ip(ip):
                seen.add(key)
                results.append((ip, port, source))
    return results


async def scrape_proxynova() -> list[tuple[str, int, str]]:
    source = "proxynova"
    results = []
    text = await fetch_url("https://www.proxynova.com/proxy-server-list/", timeout=15)
    if not text:
        return results
    rows = re.findall(r'<tr[^>]*>(.*?)</tr>', text, re.DOTALL)
    seen = set()
    for row in rows:
        tds = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
        if len(tds) < 2:
            continue
        ip_cell, port_cell = tds[0], tds[1]
        ip = None
        m = re.search(
            r'<abbr title="(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.', ip_cell,
        )
        if m and _valid_ip(m.group(1)):
            ip = m.group(1)
        else:
            dw_start = ip_cell.find("document.write(")
            if dw_start >= 0:
                paren = dw_start + len("document.write(")
                end = _match_parens(ip_cell, paren)
                if end >= 0:
                    expr = ip_cell[paren:end]
                    result = _js_eval(expr)
                    for m2 in re.finditer(
                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', result,
                    ):
                        if _valid_ip(m2.group(1)):
                            ip = m2.group(1)
                            break
                    if not ip:
                        for m2 in re.finditer(
                            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', expr,
                        ):
                            if _valid_ip(m2.group(1)):
                                ip = m2.group(1)
                                break
        if not ip or _blocked_ip(ip):
            continue
        port_m = re.search(r'>(\d{2,5})<', port_cell)
        if not port_m:
            continue
        port = int(port_m.group(1))
        key = (ip, port)
        if key not in seen:
            seen.add(key)
            results.append((ip, port, source))
    return results


async def scrape_fpln() -> list[tuple[str, int, str]]:
    source = "fpln"
    results = []
    urls = [
        "https://free-proxy-list.net/",
        "https://www.us-proxy.org/",
        "https://www.sslproxies.org/",
    ]
    seen = set()
    for url in urls:
        text = await fetch_url(url, timeout=15)
        if not text:
            continue
        ips = re.findall(
            r'<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>\s*<td>(\d+)</td>',
            text,
        )
        for ip, port_str in ips:
            port = int(port_str)
            key = (ip, port)
            if key not in seen and not _blocked_ip(ip):
                seen.add(key)
                results.append((ip, port, source))
    return results


async def scrape_hideipme(name: str, url: str) -> list[tuple[str, int, str]]:
    """Scrape hideip.me proxy list HTML page."""
    results = []
    text = await fetch_url(url, timeout=15)
    if not text:
        return results
    ips = re.findall(
        r'<td[^>]*>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>\s*<td[^>]*>(\d+)</td>',
        text,
    )
    seen = set()
    for ip, port_str in ips:
        port = int(port_str)
        key = (ip, port)
        if key not in seen and not _blocked_ip(ip):
            seen.add(key)
            results.append((ip, port, name))
    return results


async def scrape_premproxy(name: str, url: str) -> list[tuple[str, int, str]]:
    """Scrape premproxy.com HTML table."""
    results = []
    text = await fetch_url(url, timeout=15)
    if not text:
        return results
    ips = re.findall(
        r'<td[^>]*>\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*</td>\s*<td[^>]*>\s*(\d+)\s*</td>',
        text,
    )
    seen = set()
    for ip, port_str in ips:
        port = int(port_str)
        key = (ip, port)
        if key not in seen and not _blocked_ip(ip):
            seen.add(key)
            results.append((ip, port, name))
    return results


# ── Subnet scanning ───────────────────────────────────────────────
SCAN_TARGETS: dict[str, list[tuple[str, int, str]]] = {}
# source name -> list of (ip, port, source) for subnets to explore
# Populated by record_subnet_scan_target().
SUBNET_SCAN_QUEUE: list[tuple[str, int, str]] = []
SUBNET_SCAN_MAX_TTL = 600  # 10 min before we forget a subnet


def record_subnet_scan_target(ip: str, port: int, source: str):
    """When a proxy works, record its /24 + port so we can scan neighbors."""
    sk = subnet_key(ip)
    parts = ip.split(".")
    prefix = ".".join(parts[:3])
    # Generate 5 random IPs in the same /24
    for _ in range(5):
        last_octet = random.randint(1, 254)
        neighbor = f"{prefix}.{last_octet}"
        if neighbor != ip and not _blocked_ip(neighbor) and _valid_ip(neighbor):
            SUBNET_SCAN_QUEUE.append((neighbor, port, f"scan_{source}"))


def drain_subnet_scan(max_items: int = 100) -> list[tuple[str, int, str]]:
    """Drain up to max_items from the subnet scan queue."""
    out = []
    while SUBNET_SCAN_QUEUE and len(out) < max_items:
        out.append(SUBNET_SCAN_QUEUE.pop(0))
    return out


async def scrape_lists(max_items: int = 3000, force_refresh: bool = False) -> list[tuple[str, int, str]]:
    """Fetch fresh candidates from all sources whose TTL has expired.

    Re-fetches sources on a per-source TTL timer. Before re-fetching,
    clears FAILED_IPS for that source's previous IPs so stale addresses
    get a fresh chance.

    When force_refresh=True, all sources are re-fetched immediately
    regardless of TTL (useful when the queue is draining faster than
    sources go stale).

    Returns (ip, port, source_name) tuples, deduplicated and filtered."""
    maybe_cleanup()
    if force_refresh:
        force_stale_all()

    seen: set[tuple[str, int]] = set()
    proxies: list[tuple[str, int, str]] = []

    # Always try to drain subnet scan queue first (highest priority)
    subnets = drain_subnet_scan(max_items // 3)
    for ip, port, source in subnets:
        if len(proxies) >= max_items:
            break
        key = (ip, port)
        if key in seen or _blocked_ip(ip) or should_skip_ip(ip, port) or not port_ok(port):
            continue
        seen.add(key)
        proxies.append((ip, port, source))

    async def fetch_source(name: str, url: str, ttl: int):
        if should_skip_source(name):
            return name, 0

        # Check if source TTL has expired
        if not _source_is_stale(name):
            return name, 0

        # Clear FAILED_IPS for IPs from this source's previous fetch
        _clear_source_ips(name)

        text = await fetch_url(url)
        found = 0
        for match in IP_RE.finditer(text):
            if len(proxies) >= max_items:
                break
            ip, port_str = match.groups()
            port = int(port_str)
            key = (ip, port)
            if key in seen or _blocked_ip(ip) or should_skip_ip(ip, port) or not port_ok(port):
                continue
            seen.add(key)
            proxies.append((ip, port, name))
            found += 1
            # Track seen IPs for this source
            SOURCE_SEEN_IPS.setdefault(name, set()).add(key)

        # Update last fetch timestamp
        SOURCE_LAST_FETCH[name] = time.time()
        return name, found

    # Order sources by E3 VPLINK conversion rate
    sources = _WEIGHTED_SOURCES if _WEIGHTED_SOURCES else [(n, u, t) for n, u, t in PROXY_SOURCES]
    if not _WEIGHTED_SOURCES:
        random.shuffle(sources)

    for name, url, ttl in sources:
        if len(proxies) >= max_items:
            break
        await fetch_source(name, url, ttl)

    # HTML scrapers — check if stale and run
    if len(proxies) < max_items and _source_is_stale("proxydb") and not should_skip_source("proxydb"):
        _clear_source_ips("proxydb")
        pd = await scrape_proxydb()
        SOURCE_LAST_FETCH["proxydb"] = time.time()
        for item in pd:
            if len(proxies) >= max_items:
                break
            key = (item[0], item[1])
            if key not in seen and not should_skip_ip(item[0], item[1]):
                seen.add(key)
                proxies.append(item)
                SOURCE_SEEN_IPS.setdefault("proxydb", set()).add(key)

    if len(proxies) < max_items and _source_is_stale("geonode") and not should_skip_source("geonode"):
        _clear_source_ips("geonode")
        gn = await scrape_geonode()
        SOURCE_LAST_FETCH["geonode"] = time.time()
        for item in gn:
            if len(proxies) >= max_items:
                break
            key = (item[0], item[1])
            if key not in seen and not should_skip_ip(item[0], item[1]):
                seen.add(key)
                proxies.append(item)
                SOURCE_SEEN_IPS.setdefault("geonode", set()).add(key)

    if len(proxies) < max_items and _source_is_stale("proxynova") and not should_skip_source("proxynova"):
        _clear_source_ips("proxynova")
        pn = await scrape_proxynova()
        SOURCE_LAST_FETCH["proxynova"] = time.time()
        for item in pn:
            if len(proxies) >= max_items:
                break
            key = (item[0], item[1])
            if key not in seen and not should_skip_ip(item[0], item[1]):
                seen.add(key)
                proxies.append(item)
                SOURCE_SEEN_IPS.setdefault("proxynova", set()).add(key)

    if len(proxies) < max_items and _source_is_stale("fpln") and not should_skip_source("fpln"):
        _clear_source_ips("fpln")
        fpl = await scrape_fpln()
        SOURCE_LAST_FETCH["fpln"] = time.time()
        for item in fpl:
            if len(proxies) >= max_items:
                break
            key = (item[0], item[1])
            if key not in seen and not should_skip_ip(item[0], item[1]):
                seen.add(key)
                proxies.append(item)
                SOURCE_SEEN_IPS.setdefault("fpln", set()).add(key)

    # HTML scrapers — hideip.me
    if len(proxies) < max_items:
        for name, url, ttl in [(n,u,t) for n,u,t in PROXY_SOURCES if n.startswith("hideip_me_")]:
            if _source_is_stale(name) and not should_skip_source(name):
                _clear_source_ips(name)
                hp = await scrape_hideipme(name, url)
                SOURCE_LAST_FETCH[name] = time.time()
                for item in hp:
                    if len(proxies) >= max_items:
                        break
                    key = (item[0], item[1])
                    if key not in seen and not should_skip_ip(item[0], item[1]):
                        seen.add(key)
                        proxies.append(item)
                        SOURCE_SEEN_IPS.setdefault(name, set()).add(key)

    # HTML scrapers — premproxy
    if len(proxies) < max_items:
        for name, url, ttl in [(n,u,t) for n,u,t in PROXY_SOURCES if n.startswith("premproxy_")]:
            if _source_is_stale(name) and not should_skip_source(name):
                _clear_source_ips(name)
                pp = await scrape_premproxy(name, url)
                SOURCE_LAST_FETCH[name] = time.time()
                for item in pp:
                    if len(proxies) >= max_items:
                        break
                    key = (item[0], item[1])
                    if key not in seen and not should_skip_ip(item[0], item[1]):
                        seen.add(key)
                        proxies.append(item)
                        SOURCE_SEEN_IPS.setdefault(name, set()).add(key)

    return proxies
