"""WHOIS lookup via python-whois."""

import asyncio
from datetime import datetime

import whois

from footprint.models import WhoisResult


def _fmt(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    return str(value)


def _lookup(domain: str) -> WhoisResult:
    result = WhoisResult()
    try:
        w = whois.whois(domain)
    except Exception:
        return result

    result.registrar = _fmt(w.get("registrar"))
    result.org = _fmt(w.get("org"))
    result.creation_date = _fmt(w.get("creation_date"))
    result.expiration_date = _fmt(w.get("expiration_date"))

    ns = w.get("name_servers") or []
    if isinstance(ns, str):
        ns = [ns]
    result.name_servers = sorted({str(n).lower() for n in ns if n})

    emails = w.get("emails") or []
    if isinstance(emails, str):
        emails = [emails]
    result.emails = sorted({str(e).lower() for e in emails if e})
    return result


async def query(domain: str) -> WhoisResult:
    return await asyncio.to_thread(_lookup, domain)
