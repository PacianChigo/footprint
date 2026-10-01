"""Pydantic models for unified footprint output."""

from pydantic import BaseModel, Field


class SubdomainResult(BaseModel):
    source: str = "crt.sh"
    subdomains: list[str] = Field(default_factory=list)
    count: int = 0


class DNSResult(BaseModel):
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)


class WhoisResult(BaseModel):
    registrar: str | None = None
    org: str | None = None
    creation_date: str | None = None
    expiration_date: str | None = None
    name_servers: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)


class ShodanIDBResult(BaseModel):
    ip: str | None = None
    ports: list[int] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    cpes: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)


class WaybackResult(BaseModel):
    total_sampled: int = 0
    sample_urls: list[str] = Field(default_factory=list)


class Footprint(BaseModel):
    target: str
    subdomains: SubdomainResult | None = None
    dns: DNSResult | None = None
    whois: WhoisResult | None = None
    shodan: ShodanIDBResult | None = None
    wayback: WaybackResult | None = None
    risk_score: float = 0.0
    errors: list[str] = Field(default_factory=list)
