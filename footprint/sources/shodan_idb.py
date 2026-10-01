"""Shodan InternetDB lookup — free, no API key required."""

import asyncio
import socket

import httpx

from footprint.models import ShodanIDBResult

IDB_URL = "https://internetdb.shodan.io/"


def _resolve_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


async def query(domain: str, timeout: float = 15.0) -> ShodanIDBResult:
    result = ShodanIDBResult()
    ip = await asyncio.to_thread(_resolve_ip, domain)
    if not ip:
        return result
    result.ip = ip

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(IDB_URL + ip)
            if resp.status_code == 404:
                return result
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return result

    result.ports = sorted(data.get("ports", []))
    result.hostnames = data.get("hostnames", [])
    result.cpes = data.get("cpes", [])
    result.tags = data.get("tags", [])
    result.vulns = data.get("vulns", [])
    return result
