"""Runs all sources concurrently and aggregates the results."""

import asyncio

from footprint.models import Footprint
from footprint.sources import crtsh, dns, shodan_idb, wayback, whois_lookup


def _compute_risk(fp: Footprint) -> float:
    score = 0.0

    if fp.subdomains and fp.subdomains.count > 30:
        score += 1.5
    if fp.subdomains and fp.subdomains.count > 100:
        score += 1.0

    if fp.shodan:
        risky_ports = {21, 22, 23, 25, 3306, 3389, 5432, 6379, 9200, 27017}
        exposed = risky_ports & set(fp.shodan.ports)
        score += min(len(exposed) * 0.75, 2.0)
        if fp.shodan.vulns:
            score += min(len(fp.shodan.vulns) * 0.5, 2.5)

    if fp.dns and not any("v=spf1" in t for t in fp.dns.txt):
        score += 1.0

    if fp.whois and fp.whois.expiration_date:
        score += 0.5

    return round(min(score, 10.0), 1)


async def gather(target: str, verbose: bool = False) -> Footprint:
    fp = Footprint(target=target)

    labels = ["subdomains", "dns", "whois", "shodan", "wayback"]
    coros = [
        crtsh.query(target),
        dns.query(target),
        whois_lookup.query(target),
        shodan_idb.query(target),
        wayback.query(target),
    ]
    results = await asyncio.gather(*coros, return_exceptions=True)

    for label, result in zip(labels, results):
        if isinstance(result, Exception):
            fp.errors.append(f"{label}: {result}")
            if verbose:
                print(f"[!] {label} failed: {result}")
            continue
        setattr(fp, label, result)

    fp.risk_score = _compute_risk(fp)
    return fp
