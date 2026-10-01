"""Subdomain enumeration via crt.sh certificate transparency logs."""

import httpx

from footprint.models import SubdomainResult

CRTSH_URL = "https://crt.sh/"


async def query(domain: str, timeout: float = 30.0) -> SubdomainResult:
    result = SubdomainResult()
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                CRTSH_URL,
                params={"q": f"%.{domain}", "output": "json"},
                headers={"User-Agent": "footprint/0.1"},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return result

    names: set[str] = set()
    for entry in data:
        for field in ("name_value", "common_name"):
            value = entry.get(field, "")
            for line in str(value).splitlines():
                name = line.strip().lower().lstrip("*.")
                if name and name.endswith(domain):
                    names.add(name)

    result.subdomains = sorted(names)
    result.count = len(names)
    return result
