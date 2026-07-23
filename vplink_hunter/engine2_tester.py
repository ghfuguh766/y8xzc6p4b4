"""Engine 2 — Rapid Fire Tester.

Raw asyncio socket HTTP through proxy.
Single TCP connect then HTTP GET verify."""

import asyncio
import json
import socket
import time

from .engine1_generator import mark_failed, mark_working, record_port_test, record_subnet_scan_target
from .engine3_verifier import _ip_in_dc_cidr

_ipinfo_cache: dict[str, dict] = {}

port_hits: dict[int, int] = {}
port_tries: dict[int, int] = {}

_TEST_ENDPOINTS = [
    "http://ipinfo.io/json",
    "http://httpbin.org/ip",
    "http://api.ipify.org?format=json",
]

_HTTP_GET_TPL = (
    "GET {} HTTP/1.1\r\n"
    "Host: {}\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
    "Accept: application/json\r\n"
    "Connection: close\r\n"
    "\r\n"
)


async def _connect(ip: str, port: int, timeout: float = 2.0) -> tuple | None:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_SYNCNT, 2)
    except (OSError, AttributeError):
        pass
    sock.setblocking(False)
    try:
        await asyncio.wait_for(
            loop.sock_connect(sock, (ip, port)), timeout=timeout
        )
        reader, writer = await asyncio.open_connection(sock=sock)
        return reader, writer
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return None


async def test_one(ip: str, port: int) -> dict | None:
    t0 = time.time()
    port_tries[port] = port_tries.get(port, 0) + 1

    if ip in _ipinfo_cache:
        data = _ipinfo_cache[ip]
        latency = round((time.time() - t0) * 1000)
        port_hits[port] = port_hits.get(port, 0) + 1
        record_port_test(port, True)
        mark_working(ip, port)
        record_subnet_scan_target(ip, port, "known")
        return {
            "ip": ip, "port": port, "proto": "http", "latency": latency,
            "isp": data.get("org", ""), "country": data.get("country", ""),
            "city": data.get("city", ""), "region": data.get("region", ""),
            "org": (data.get("org") or "").lower(),
        }

    conn = await _connect(ip, port)
    if conn is None:
        mark_failed(ip, port)
        record_port_test(port, False)
        return None
    reader, writer = conn

    result = None
    for endpoint in _TEST_ENDPOINTS:
        host = endpoint.split("/")[2]
        req = _HTTP_GET_TPL.format(endpoint, host)
        try:
            writer.write(req.encode())
            await asyncio.wait_for(writer.drain(), timeout=2)

            response = b""
            deadline = time.time() + 5
            while time.time() < deadline:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                chunk = await asyncio.wait_for(
                    reader.read(4096), timeout=min(remaining, 2.0)
                )
                if not chunk:
                    break
                response += chunk
        except (asyncio.TimeoutError, Exception):
            continue

        result = _parse_response(response, ip, port, t0)
        if result:
            break

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    if result:
        port_hits[port] = port_hits.get(port, 0) + 1
        record_port_test(port, True)
        mark_working(result["ip"], port)
        record_subnet_scan_target(result["ip"], port, "scraped")
    else:
        mark_failed(ip, port)
        record_port_test(port, False)

    return result


def _parse_response(response: bytes, ip: str, port: int, t0: float) -> dict | None:
    try:
        header_end = response.index(b"\r\n\r\n")
        headers_raw = response[:header_end].decode(errors="replace")
        body = response[header_end + 4:]

        status_line = headers_raw.split("\r\n")[0] if headers_raw else ""
        status_code = status_line.split()[1] if len(status_line.split()) > 1 else ""

        if status_code == "429":
            return None

        if status_code != "200":
            record_port_test(port, False)
            return None

        data = json.loads(body.decode(errors="replace"))
    except (ValueError, json.JSONDecodeError, IndexError):
        return None

    latency = round((time.time() - t0) * 1000)
    org = (data.get("org") or "").lower()
    ip_addr = data.get("ip", ip)
    _ipinfo_cache[ip_addr] = data

    return {
        "ip": ip_addr,
        "port": port,
        "proto": "http",
        "latency": latency,
        "isp": data.get("org", ""),
        "country": data.get("country", ""),
        "city": data.get("city", ""),
        "region": data.get("region", ""),
        "org": org,
    }


async def test_ip(ip: str, primary_port: int) -> dict | None:
    if _ip_in_dc_cidr(ip):
        return None
    return await test_one(ip, primary_port)


async def worker(q: asyncio.Queue, results: list, ready_event: asyncio.Event):
    """Consume (ip, port) from queue, test the port, append result if working."""
    while True:
        got_item = False
        try:
            ip_port = await asyncio.wait_for(q.get(), timeout=1)
            got_item = True
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            break
        try:
            ip, port = ip_port
            result = await test_ip(ip, port)
            results.append(result)
            ready_event.set()
        except asyncio.CancelledError:
            break
        except Exception:
            results.append(None)
            ready_event.set()
        finally:
            if got_item:
                q.task_done()
