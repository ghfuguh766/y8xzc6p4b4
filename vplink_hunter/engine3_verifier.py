"""Engine 3 — VPLINK Verifier + Residential Detector.

httpx async through proxy (singular kwarg for 0.28+).
Three-layer classification: CIDR ranges → org regex → fresh lookup."""

import asyncio
import ipaddress
import json
import re
import time

import httpx


DATACENTER_ORGS = re.compile(
    r"alibaba|amazon|google|hetzner|ovh|digitalocean|vultr|"
    r"linode|microsoft|oracle|ibm|rackspace|softlayer|scaleway|"
    r"contabo|netcup|cogent|datacamp|zenlayer|psychz|gige|choopa|"
    r"sharktech|cloudflare|vps\b|dedicated|hosting|colocrossing|"
    r"theplanet|leaseweb|akamai|stackpath|oneprovider|worldstream|"
    r"buyvm|snel|racknerd|hostiger|nfry|serverel|choopa|zare|"
    r"tencent|dpkgsoft|m247|mevspace|terrahost|"
    r"datapacket|multacom|crosslayer|hosthat|astrohost|"
    r"gcore|lansrv|hitron|voxility|datawise|"
    r"firstheberg|starline|develapp|itltd|zenex|"
    r"naver[^a-z]|nhn\s|kakao\s|kt\s*cloud|lg.?cns|"
    r"ionos|hostinger|hostgator|bluehost|godaddy|dreamhost|"
    r"a2\s*hosting|siteground|inmotion|liquid.?web|"
    r"kinsta|wp.?engine|namecheap|hostarmada|kamatera|"
    r"interserver|cloudways|greengeeks|scalahosting|"
    r"fastcomet|chemicloud|tmdhosting|verpex|servers\.com|"
    r"phoenixnap|hivelocity|hostwinds|hostpapa|"
    r"coreweave|equinix|digital.?realty|flexential|"
    r"cyxtera|vapor.?io|iron.?mountain|"
    r"routerhosting|"
    r"hostkey|aeza|aezaglobal|aeza\.group|"
    r"global.?connectivity|port.?networks|"
    r"timeweb|webair|modulis"
)

_CIDR_STRS = [
    "13.32.0.0/12", "13.64.0.0/11", "15.64.0.0/10", "16.0.0.0/8",
    "18.0.0.0/8", "35.160.0.0/13", "35.176.0.0/12", "44.192.0.0/10",
    "52.0.0.0/10", "54.0.0.0/9", "34.0.0.0/10", "35.184.0.0/13",
    "35.208.0.0/12", "35.224.0.0/12", "8.34.0.0/15", "20.0.0.0/8",
    "40.64.0.0/10", "52.128.0.0/10", "64.225.0.0/16", "104.248.0.0/16",
    "138.197.0.0/16", "139.59.0.0/16", "143.110.0.0/15", "157.230.0.0/16",
    "159.65.0.0/16", "161.35.0.0/16", "165.22.0.0/16", "167.71.0.0/16",
    "167.99.0.0/16", "170.64.0.0/14", "178.128.0.0/16", "188.166.0.0/16",
    "206.81.0.0/16", "45.32.0.0/15", "45.63.0.0/16", "45.76.0.0/16",
    "65.20.0.0/15", "95.179.0.0/16", "104.156.0.0/14", "104.238.0.0/15",
    "108.61.0.0/16", "136.244.0.0/16", "141.164.0.0/16", "149.28.0.0/15",
    "155.138.0.0/15", "192.248.0.0/16", "207.148.0.0/16", "209.222.0.0/15",
    "45.33.0.0/16", "45.56.0.0/15", "45.79.0.0/16", "50.116.0.0/15",
    "66.175.0.0/16", "69.164.0.0/16", "72.14.176.0/20", "96.126.96.0/19",
    "104.200.0.0/14", "106.187.0.0/16", "139.144.0.0/15", "172.104.0.0/15",
    "173.230.0.0/16", "192.155.0.0/16", "192.81.128.0/21", "198.58.0.0/15",
    "46.105.0.0/16", "51.68.0.0/16", "51.75.0.0/16", "51.77.0.0/16",
    "51.178.0.0/16", "51.195.0.0/16", "51.210.0.0/16", "51.254.0.0/16",
    "54.36.0.0/15", "54.37.0.0/16", "91.134.0.0/16", "94.23.0.0/16",
    "141.94.0.0/16", "145.239.0.0/16", "147.135.0.0/16", "149.56.0.0/15",
    "158.69.0.0/16", "163.172.0.0/16", "167.114.0.0/16", "188.165.0.0/16",
    "192.95.0.0/16", "198.27.0.0/16", "213.251.0.0/16", "5.9.0.0/16",
    "23.88.0.0/16", "46.4.0.0/16", "49.12.0.0/16", "49.13.0.0/16",
    "65.108.0.0/16", "65.109.0.0/16", "78.46.0.0/16", "78.47.0.0/16",
    "85.10.0.0/16", "88.198.0.0/16", "94.130.0.0/16", "95.216.0.0/16",
    "116.202.0.0/16", "125.19.0.0/16", "136.243.0.0/16", "138.201.0.0/16",
    "142.132.0.0/16", "144.76.0.0/16", "148.251.0.0/16", "157.90.0.0/16",
    "159.69.0.0/16", "162.55.0.0/16", "167.235.0.0/16", "168.119.0.0/16",
    "171.22.0.0/16", "176.9.0.0/16", "178.63.0.0/16", "188.40.0.0/16",
    "195.201.0.0/16", "213.133.0.0/16", "8.208.0.0/12", "8.208.0.0/15",
    "8.210.0.0/15", "8.212.0.0/14", "8.216.0.0/13", "8.224.0.0/11",
    "39.96.0.0/12", "47.52.0.0/15", "47.74.0.0/15", "47.76.0.0/14",
    "47.88.0.0/14", "47.92.0.0/14", "47.96.0.0/11", "59.80.0.0/14",
    "106.14.0.0/15", "119.23.0.0/16", "120.24.0.0/14", "120.52.0.0/15",
    "121.196.0.0/14", "123.56.0.0/14", "139.129.0.0/16", "139.196.0.0/15",
    "139.224.0.0/16", "161.117.0.0/16", "163.230.0.0/16", "170.33.0.0/16",
    "172.16.0.0/12", "185.154.0.0/16", "203.119.0.0/16", "1.12.0.0/14",
    "9.0.0.0/8", "43.128.0.0/10", "49.48.0.0/14", "49.56.0.0/14",
    "49.64.0.0/11", "81.68.0.0/14", "82.156.0.0/14", "101.32.0.0/12",
    "106.52.0.0/14", "106.55.0.0/16", "110.40.0.0/14", "118.24.0.0/13",
    "118.89.0.0/16", "119.28.0.0/15", "120.53.0.0/16", "121.4.0.0/15",
    "129.211.0.0/16", "129.226.0.0/16", "132.232.0.0/16", "134.175.0.0/16",
    "139.155.0.0/16", "140.143.0.0/16", "146.56.0.0/16", "150.109.0.0/16",
    "150.158.0.0/16", "162.14.0.0/16", "170.106.0.0/16", "175.24.0.0/14",
    "175.27.0.0/15", "182.254.0.0/16", "190.92.0.0/16", "193.112.0.0/16",
    "211.159.0.0/16", "129.146.0.0/17", "130.61.0.0/16", "132.145.0.0/16",
    "134.213.0.0/16", "138.2.0.0/16", "140.91.0.0/16", "140.238.0.0/16",
    "141.144.0.0/16", "143.47.0.0/16", "144.24.0.0/15", "146.58.0.0/16",
    "147.154.0.0/16", "147.161.0.0/16", "150.136.0.0/16", "150.230.0.0/16",
    "152.67.0.0/16", "152.70.0.0/15", "155.248.0.0/16", "158.101.0.0/16",
    "168.138.0.0/16", "185.111.0.0/16", "192.9.0.0/16", "193.122.0.0/16",
    "193.123.0.0/16", "195.128.0.0/16", "209.90.0.0/16", "213.32.0.0/16",
    "194.59.204.0/24", "46.38.0.0/16", "106.10.0.0/15", "119.207.0.0/16",
    "175.196.0.0/15", "175.206.0.0/15", "222.100.0.0/15", "174.137.134.0/24",
    "216.38.0.0/15", "69.42.0.0/16", "38.117.0.0/16", "138.124.0.0/16",
    "85.234.0.0/16", "62.133.0.0/16", "205.215.0.0/16", "94.198.0.0/16",
    "185.71.0.0/16",
]
DATACENTER_CIDRS = [ipaddress.IPv4Network(c, strict=False) for c in dict.fromkeys(_CIDR_STRS)]

VPLINK_TEST_URL = "https://vplink.in/UbpV2D"
VPN_DETECTED_PATTERNS = re.compile(
    r"vpn\s*detected|proxy\s*detected|access\s*denied|blocked|"
    r"your\s*ip\s*has\s*been|suspicious\s*activity",
    re.IGNORECASE,
)
WORKING_PATTERNS = re.compile(
    r"Please Wait|Opening Link|whatsgrouphub|click here|"
    r"window\.location|Continue",
)

_HTTPX_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}


def cleanup_subprocesses():
    pass


async def _http_get(ip: str, port: int, host: str, path: str, timeout: float = 6) -> str | None:
    """HTTP GET through proxy via raw asyncio socket."""
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=min(timeout, 3)
        )
        req = f"GET http://{host}{path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        writer.write(req.encode())
        await asyncio.wait_for(writer.drain(), timeout=min(timeout, 3))

        response = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=2)
            if not chunk:
                break
            response += chunk
        if not response:
            return None
        header_end = response.index(b"\r\n\r\n")
        body = response[header_end + 4:]
        return body.decode(errors="replace")
    except Exception:
        return None
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def check_vplink(ip: str, port: int, timeout: float = 10.0) -> dict:
    """Test proxy against VPLINK via httpx through the proxy."""
    proxy_url = f"http://{ip}:{port}"
    try:
        async with httpx.AsyncClient(
            proxy=proxy_url,
            timeout=httpx.Timeout(timeout, connect=5.0),
            follow_redirects=True,
        ) as client:
            resp = await client.get(VPLINK_TEST_URL, headers=_HTTPX_HEADERS)
            text = resp.text
    except httpx.ConnectError:
        return {"ok": False, "detail": "connect_failed"}
    except httpx.TimeoutException:
        return {"ok": False, "detail": "timeout"}
    except httpx.ProxyError:
        return {"ok": False, "detail": "proxy_error"}
    except Exception:
        return {"ok": False, "detail": "unknown"}

    if not text:
        return {"ok": False, "detail": "empty_response"}

    if VPN_DETECTED_PATTERNS.search(text):
        return {"ok": False, "detail": "vpn_detected"}
    if WORKING_PATTERNS.search(text) or len(text) > 500:
        return {"ok": True, "detail": "passed"}
    if len(text) < 200:
        return {"ok": False, "detail": "too_short"}
    return {"ok": False, "detail": "unknown_pattern"}


MIN_SPEED_KBPS = 10
IDEAL_SPEED_KBPS = 50
DL_TARGET_BYTES = 102_400  # 100KB — real-world article page size
_DL_URL = "http://speedtest.tele2.net/100KB.zip"


async def check_download(ip: str, port: int, timeout: float = 15.0) -> dict:
    t0 = time.time()
    proxy_url = f"http://{ip}:{port}"
    try:
        async with httpx.AsyncClient(
            proxy=proxy_url,
            timeout=httpx.Timeout(timeout, connect=5.0),
            follow_redirects=True,
        ) as client:
            resp = await client.get(_DL_URL, headers=_HTTPX_HEADERS)
            elapsed_s = time.time() - t0
            size = len(resp.content)
            speed_kbps = round((size / 1024) / elapsed_s) if elapsed_s > 0 else 0
            return {
                "ok": speed_kbps >= MIN_SPEED_KBPS,
                "size_bytes": size,
                "latency_ms": round(elapsed_s * 1000),
                "speed_kbps": speed_kbps,
            }
    except Exception:
        elapsed_s = time.time() - t0
        return {
            "ok": False,
            "size_bytes": 0,
            "latency_ms": round(elapsed_s * 1000),
            "speed_kbps": 0,
        }


def _ip_in_dc_cidr(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
        for net in DATACENTER_CIDRS:
            if ip in net:
                return True
    except ValueError:
        pass
    return False


def classify(ip: str | None = None, org: str | None = None) -> str:
    if ip and _ip_in_dc_cidr(ip):
        return "datacenter"
    if org and DATACENTER_ORGS.search(org.lower()):
        return "datacenter"
    return "residential"


async def _get_org_via_proxy(ip: str, port: int) -> str | None:
    text = await _http_get(ip, port, "ipinfo.io", "/json", timeout=8)
    if not text:
        return None
    try:
        data = json.loads(text)
        return data.get("org", "")
    except (json.JSONDecodeError, ValueError):
        return None


async def verify(candidate: dict, do_vplink: bool = True,
                 fail_counts: dict | None = None) -> dict | None:
    proxy_ip = candidate["ip"]
    proxy_org = candidate.get("org", "")

    if classify(ip=proxy_ip, org=proxy_org) == "datacenter":
        if fail_counts is not None:
            fail_counts["dc_classify_initial"] = fail_counts.get("dc_classify_initial", 0) + 1
        return None

    vplink_result = {"ok": False, "detail": "skipped"}

    if do_vplink:
        vplink_result = await check_vplink(proxy_ip, candidate["port"])
        if not vplink_result["ok"]:
            if fail_counts is not None:
                reason = f"vplink_{vplink_result.get('detail', 'fail')}"
                fail_counts[reason] = fail_counts.get(reason, 0) + 1
            return None
    else:
        vplink_result["ok"] = True

    fresh_org = await _get_org_via_proxy(proxy_ip, candidate["port"])
    if fresh_org is not None:
        if classify(ip=proxy_ip, org=fresh_org) == "datacenter":
            if fail_counts is not None:
                fail_counts["dc_fresh_org"] = fail_counts.get("dc_fresh_org", 0) + 1
            return None
        proxy_org = fresh_org
    else:
        if classify(ip=proxy_ip) == "datacenter":
            if fail_counts is not None:
                fail_counts["dc_no_org"] = fail_counts.get("dc_no_org", 0) + 1
            return None
        if fail_counts is not None:
            fail_counts["org_fetch_failed"] = fail_counts.get("org_fetch_failed", 0) + 1

    download_result = await check_download(proxy_ip, candidate["port"])
    if not download_result["ok"]:
        if fail_counts is not None:
            speed = download_result.get("speed_kbps", 0)
            fail_counts[f"download_slow_{speed}_kbps"] = fail_counts.get(f"download_slow_{speed}_kbps", 0) + 1
        return None

    proxy_type = classify(ip=proxy_ip, org=proxy_org)

    return {
        "ip": proxy_ip,
        "port": candidate["port"],
        "proto": "http",
        "latency": candidate["latency"],
        "type": proxy_type,
        "isp": proxy_org,
        "country": candidate.get("country", ""),
        "city": candidate.get("city", ""),
        "region": candidate.get("region", ""),
        "vplink_ok": vplink_result["ok"],
        "speed_kbps": download_result.get("speed_kbps", 0),
    }
