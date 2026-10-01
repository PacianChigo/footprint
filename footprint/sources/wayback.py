"""Historical URL discovery via the Wayback Machine CDX API."""

import httpx

from footprint.models import WaybackResult

CDX_URL = "https://web.archive.org/cdx/search/cdx"


async def query(domain: str, limit: int = 100, timeout: float = 30.0) -> WaybackResult:
    result = WaybackResult()
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                CDX_URL,
                params={
                    "url": f"{domain}/*",
                    "output": "json",
                    "limit": limit,
                    "fl": "original",
                    "collapse": "urlkey",
                },
                headers={"User-Agent": "footprint/0.1"},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return result

    if not data:
        return result

    rows = data[1:] if data[0] == ["original"] else data
    urls = [row[0] for row in rows if row]
    result.sample_urls = urls
    result.total_sampled = len(urls)
    return result
