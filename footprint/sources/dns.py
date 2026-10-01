"""DNS record enumeration via dnspython."""

import asyncio

import dns.resolver

from footprint.models import DNSResult

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def _resolve(domain: str, rtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=5.0)
        return sorted({str(r).strip('"') for r in answers})
    except Exception:
        return []


async def query(domain: str) -> DNSResult:
    result = DNSResult()
    tasks = [asyncio.to_thread(_resolve, domain, rt) for rt in RECORD_TYPES]
    values = await asyncio.gather(*tasks, return_exceptions=True)

    for rtype, value in zip(RECORD_TYPES, values):
        if isinstance(value, Exception) or not value:
            continue
        setattr(result, rtype.lower(), value)
    return result
