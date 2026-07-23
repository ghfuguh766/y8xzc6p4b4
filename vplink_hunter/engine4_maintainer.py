"""Engine 4 — DB Proxy Maintenance.

Scans all proxies in the database, re-tests liveness/speed,
and deletes dead or too-slow entries. Uses relaxed thresholds:
  latency < 5000ms  |  speed > 10 KB/s"""

import asyncio
import socket
import time

from . import supabase_client as sb
from .engine3_verifier import _ip_in_dc_cidr, classify

_DL_URL = "http://speedtest.tele2.net/100KB.zip"
_DL_HOST = "speedtest.tele2.net"
_DL_PATH = "/100KB.zip"
_DL_BYTES = 102_400

MAX_LATENCY_MS = 5000
MIN_SPEED_KBPS = 50
IDEAL_SPEED_KBPS = 100

_HTTP_GET = (
    "GET {} HTTP/1.1\r\n"
    "Host: {}\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n"
    "\r\n"
).format(_DL_URL, _DL_HOST).encode()


async def _test_proxy(ip: str, port: int) -> dict:
    t0 = time.time()
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(
            loop.sock_connect(sock, (ip, port)), timeout=5.0
        )
        t1 = time.time()
        reader, writer = await asyncio.open_connection(sock=sock)
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return {"ok": False, "reason": "connect_failed", "latency_ms": round((time.time() - t0) * 1000), "speed_kbps": 0}

    try:
        writer.write(_HTTP_GET)
        await asyncio.wait_for(writer.drain(), timeout=3)

        response = b""
        deadline = time.time() + 10
        while time.time() < deadline:
            remain = deadline - time.time()
            if remain <= 0:
                break
            chunk = await asyncio.wait_for(
                reader.read(65536), timeout=min(remain, 3.0)
            )
            if not chunk:
                break
            response += chunk
    except Exception:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return {"ok": False, "reason": "http_failed", "latency_ms": round((time.time() - t0) * 1000), "speed_kbps": 0}

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    try:
        header_end = response.index(b"\r\n\r\n")
        headers_raw = response[:header_end].decode(errors="replace")
        body = response[header_end + 4:]
        status_code = headers_raw.split()[1] if len(headers_raw.split()) > 1 else ""
        if status_code != "200":
            return {"ok": False, "reason": f"status_{status_code}", "latency_ms": round((time.time() - t0) * 1000), "speed_kbps": 0}
    except (ValueError, IndexError):
        return {"ok": False, "reason": "parse_failed", "latency_ms": round((time.time() - t0) * 1000), "speed_kbps": 0}

    elapsed_s = time.time() - t0
    latency_ms = round(elapsed_s * 1000)
    body_bytes = len(body)
    speed_kbps = round((body_bytes / 1024) / elapsed_s) if elapsed_s > 0 else 0

    ok = latency_ms < MAX_LATENCY_MS and speed_kbps >= MIN_SPEED_KBPS
    reason = ""
    if not ok:
        if latency_ms >= MAX_LATENCY_MS:
            reason = f"slow_{latency_ms}ms"
        elif speed_kbps < MIN_SPEED_KBPS:
            reason = f"slow_{speed_kbps}kbps"

    return {
        "ok": ok,
        "reason": reason,
        "latency_ms": latency_ms,
        "speed_kbps": speed_kbps,
    }


async def maintain(max_workers: int = 20) -> dict:
    limit = 200
    offset = 0
    tested = 0
    passed = 0
    deleted = 0
    errors = 0

    print(f"  Engine 4 — DB Maintenance")
    print(f"  Thresholds: latency < {MAX_LATENCY_MS}ms, speed >= {MIN_SPEED_KBPS} KB/s")
    print(f"  Download: {_DL_URL}")
    print()

    while True:
        rows = sb.list_proxies(limit=limit, offset=offset)
        if not rows:
            break

        sem = asyncio.Semaphore(max_workers)

        async def test_and_clean(row):
            nonlocal passed, deleted, errors
            ip = row["ip"]
            port = row["port"]
            async with sem:
                result = await _test_proxy(ip, port)

            if result["ok"]:
                passed += 1
                sb.upsert_proxy({
                    "ip": ip,
                    "port": port,
                    "proto": row.get("proto", "http"),
                    "latency": result["latency_ms"],
                    "type": row.get("type", "unknown"),
                    "isp": row.get("isp", ""),
                    "country": row.get("country", ""),
                    "city": row.get("city", ""),
                    "region": row.get("region", ""),
                    "vplink_ok": row.get("vplink_ok", False),
                    "e2_ok": True,
                })
            else:
                deleted += 1
                sb.delete_proxy(ip, port)

            return result

        tasks = [test_and_clean(row) for row in rows]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                errors += 1
            else:
                tested += 1

        offset += limit
        print(f"  Tested {tested}, kept {passed}, deleted {deleted}, errors {errors}", end="\r")

    print()
    print()
    print(f"  Done — {tested} tested, {passed} kept, {deleted} deleted, {errors} errors")
    return {"tested": tested, "passed": passed, "deleted": deleted, "errors": errors}
