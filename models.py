"""Data models for Validin Infrastructure Hunter."""

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Set, Tuple
from datetime import datetime
from enum import Enum


class IOCType(Enum):
    """Supported IOC types."""
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class ConnectionType(Enum):
    """Types of connections between IOCs."""
    SHARED_IP = "shared_ip"
    SHARED_HEADER_HASH = "shared_header_hash"
    SHARED_BANNER_HASH = "shared_banner_hash"
    SHARED_BODY_HASH = "shared_body_hash"
    SHARED_CERT = "shared_cert"
    SHARED_FAVICON = "shared_favicon"
    SHARED_CLASS_HASH = "shared_class_hash"
    SHARED_TITLE = "shared_title"
    SHARED_LOCATION_DOMAIN = "shared_location_domain"  # Domains redirecting to same location
    CONTENT_LINK_JS = "content_link_js"
    CONTENT_LINK_REDIRECT = "content_link_redirect"
    CONTENT_LINK_IFRAME = "content_link_iframe"
    CONTENT_LINK_ANCHOR = "content_link_anchor"
    SHARED_REGISTRAR = "shared_registrar"
    SHARED_NS = "shared_ns"
    SAME_SUBNET = "same_subnet"
    OSINT_COOCCURRENCE = "osint_cooccurrence"
    NAMING_PATTERN = "naming_pattern"
    A_RECORD = "a_record"
    AAAA_RECORD = "aaaa_record"
    # Corpus-mode signature connection types
    SHARED_SAN = "shared_san"
    SHARED_REGISTRANT = "shared_registrant"
    SHARED_ASN = "shared_asn"
    CORPUS_SIGNATURE_MATCH = "corpus_signature_match"


@dataclass
class IOC:
    """Represents an Indicator of Compromise."""
    value: str                      # The refanged/normalized indicator
    ioc_type: IOCType               # Type of IOC
    original: str = ""              # Original text as found in report
    source_file: str = ""           # Which report file it was extracted from
    context: str = ""               # Surrounding text for human review
    is_seed: bool = False           # Whether this is a seed IOC from reports
    discovered_via: str = ""        # How this IOC was discovered (for pivoted IOCs)
    connected_to_seed: str = ""     # Which seed IOC led to this discovery

    def __hash__(self):
        return hash((self.value, self.ioc_type))

    def __eq__(self, other):
        if not isinstance(other, IOC):
            return False
        return self.value == other.value and self.ioc_type == other.ioc_type


@dataclass
class Connection:
    """Represents a connection between two IOCs."""
    source_ioc: IOC
    target_ioc: IOC
    connection_type: ConnectionType
    confidence_tier: int            # 1, 2, or 3
    confidence_score: float         # 0.0 - 1.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    pivot_path: List[str] = field(default_factory=list)
    timestamp_overlap: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "source": self.source_ioc.value,
            "source_type": self.source_ioc.ioc_type.value,
            "target": self.target_ioc.value,
            "target_type": self.target_ioc.ioc_type.value,
            "type": self.connection_type.value,
            "tier": self.confidence_tier,
            "score": self.confidence_score,
            "evidence": self.evidence,
            "pivot_path": self.pivot_path,
            "timestamp_overlap": self.timestamp_overlap,
            "notes": self.notes
        }


@dataclass
class DNSRecord:
    """Represents a DNS record from Validin."""
    key: str                        # Domain or IP
    value: str                      # Resolved value
    value_type: str                 # ip4, ip6, dom, etc.
    record_type: str                # A, AAAA, NS, PTR, etc.
    first_seen: int                 # Unix timestamp
    last_seen: int                  # Unix timestamp

    @property
    def first_seen_dt(self) -> datetime:
        return datetime.fromtimestamp(self.first_seen)

    @property
    def last_seen_dt(self) -> datetime:
        return datetime.fromtimestamp(self.last_seen)


@dataclass
class HostFingerprint:
    """Represents a host response fingerprint."""
    hash_value: str
    hash_type: str                  # HEADER_HASH, BODY_SHA1, FAVICON_HASH, etc.
    host: str                       # Domain or IP
    first_seen: int
    last_seen: int
    connectivity: int = 0           # How many hosts share this hash


@dataclass
class HashPivotData:
    """Full result of a hash pivot query, including temporal and backend-IP data."""
    connectivity: int
    hosts: List[str]
    host_timestamps: Dict[str, Tuple[int, int]]  # domain -> (first_seen, last_seen)
    backend_ips: List[str]                        # non-CDN IPs that also have this hash
    ip_timestamps: Dict[str, Tuple[int, int]]     # ip -> (first_seen, last_seen)


@dataclass
class LocationDomain:
    """Represents a redirect location domain (HOST-LOCATION_DOMAIN)."""
    location: str                   # The domain being redirected to (e.g., timesync.io)
    host: str                       # Domain that redirects (e.g., ruzede.com)
    first_seen: int
    last_seen: int
    connectivity: int = 0           # How many hosts redirect to this location


@dataclass
class CertificateInfo:
    """Represents TLS certificate information."""
    sha1: str
    subject: str = ""
    issuer: str = ""
    not_before: Optional[int] = None
    not_after: Optional[int] = None
    is_self_signed: bool = False
    domains: List[str] = field(default_factory=list)


@dataclass
class RegistrationInfo:
    """Represents domain registration information."""
    domain: str
    registrar: str = ""
    created_date: Optional[int] = None
    updated_date: Optional[int] = None
    expires_date: Optional[int] = None
    registrant_name: str = ""
    registrant_org: str = ""
    nameservers: List[str] = field(default_factory=list)


@dataclass
class OSINTHit:
    """Represents an OSINT/threat feed hit."""
    indicator: str
    feed_name: str
    category: str = ""
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class EnrichmentResult:
    """Contains all enrichment data for an IOC."""
    ioc: IOC
    dns_records: List[DNSRecord] = field(default_factory=list)
    host_fingerprints: List[HostFingerprint] = field(default_factory=list)
    location_domains: List['LocationDomain'] = field(default_factory=list)
    certificates: List[CertificateInfo] = field(default_factory=list)
    registration: Optional[RegistrationInfo] = None
    osint_hits: List[OSINTHit] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    raw_responses: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "ioc": {
                "value": self.ioc.value,
                "type": self.ioc.ioc_type.value,
                "is_seed": self.ioc.is_seed
            },
            "dns_records": [
                {
                    "key": r.key,
                    "value": r.value,
                    "type": r.record_type,
                    "first_seen": r.first_seen,
                    "last_seen": r.last_seen
                }
                for r in self.dns_records
            ],
            "host_fingerprints": [
                {
                    "hash": f.hash_value,
                    "type": f.hash_type,
                    "host": f.host,
                    "connectivity": f.connectivity
                }
                for f in self.host_fingerprints
            ],
            "location_domains": [
                {
                    "location": ld.location,
                    "host": ld.host,
                    "connectivity": ld.connectivity
                }
                for ld in self.location_domains
            ],
            "certificates": [
                {
                    "sha1": c.sha1,
                    "subject": c.subject,
                    "issuer": c.issuer,
                    "is_self_signed": c.is_self_signed
                }
                for c in self.certificates
            ],
            "registration": {
                "registrar": self.registration.registrar,
                "created": self.registration.created_date,
                "nameservers": self.registration.nameservers
            } if self.registration else None,
            "osint_hits": [
                {
                    "feed": h.feed_name,
                    "category": h.category
                }
                for h in self.osint_hits
            ],
            "subdomains": self.subdomains,
            "errors": self.errors
        }


@dataclass
class IndicatorHit:
    """One indicator from a seed that links back to a discovered host."""
    indicator_type: str    # e.g. "HOST-BANNER_0_HASH", "HOST-LOCATION_DOMAIN", "shared_ip"
    indicator_value: str   # hash hex, redirect-target domain, or IP address
    connectivity: int      # how many hosts globally share this indicator (rarity proxy)
    weight: float          # type reliability weight (from HASH_TYPE_WEIGHTS or equivalent)
    first_seen: int = 0    # when this hash was first seen on the discovered host
    last_seen: int = 0     # when this hash was last seen on the discovered host
    backend_ips: List[str] = field(default_factory=list)  # non-CDN IPs that also carry this hash

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "indicator_type": self.indicator_type,
            "indicator_value": self.indicator_value,
            "connectivity": self.connectivity,
            "weight": round(self.weight, 2),
        }
        if self.first_seen:
            d["first_seen"] = self.first_seen
        if self.last_seen:
            d["last_seen"] = self.last_seen
        if self.backend_ips:
            d["backend_ips"] = self.backend_ips
        return d


@dataclass
class MultiIndicatorMatch:
    """
    A host that shares one or more indicators with a seed IOC.

    indicator_count — how many distinct indicator types/values overlap with the seed.
    quality_score   — sum of (weight × connectivity_rarity) across all hits;
                      set by find_multi_indicator_matches, not recomputed here to
                      avoid circular imports with connection_analyzer.
    """
    host: str
    ioc_type: IOCType
    indicator_hits: List['IndicatorHit'] = field(default_factory=list)
    quality_score: float = 0.0

    @property
    def indicator_count(self) -> int:
        return len(self.indicator_hits)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "ioc_type": self.ioc_type.value,
            "indicator_count": self.indicator_count,
            "quality_score": self.quality_score,
            "indicators": [h.to_dict() for h in self.indicator_hits],
        }


@dataclass
class NewIOC:
    """Represents a newly discovered IOC from pivoting."""
    ioc: IOC
    discovered_via: str             # e.g., "shared_ip_pivot", "hash_pivot"
    connected_to_seed: str          # The seed IOC that led to discovery
    confidence_score: float
    confidence_tier: int
    evidence: Dict[str, Any] = field(default_factory=dict)
    # Corpus mode: signatures (by id) that attributed this IOC. Empty in single-IOC hunts.
    source_signatures: List[str] = field(default_factory=list)
    promoted: bool = False          # Set when multi-signature promotion fires

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "value": self.ioc.value,
            "type": self.ioc.ioc_type.value,
            "discovered_via": self.discovered_via,
            "connected_to_seed": self.connected_to_seed,
            "confidence_score": self.confidence_score,
            "tier": self.confidence_tier,
            "evidence": self.evidence,
            "source_signatures": self.source_signatures,
            "promoted": self.promoted,
        }


@dataclass
class CorpusSignature:
    """
    A parameter shared by 2+ seeds in a corpus, used to expand the hunt.

    Signal score = coverage_ratio * rarity_score; higher means more distinctive
    across the corpus and rarer overall.
    """
    param_type: str                     # e.g. "cert_sha1", "registrant_name", "header_hash"
    value: str                          # The shared value itself
    supporting_seeds: Set[str] = field(default_factory=set)
    coverage_ratio: float = 0.0         # len(supporting_seeds) / total_seeds
    rarity_score: float = 0.0           # 0.0-1.0 — higher = rarer in Validin
    source_connectivity: Optional[int] = None  # Validin connectivity if known
    # Original hash_type when param_type is hash-derived (HEADER_HASH, etc.), so we
    # can pass it back into per-type noise/scoring heuristics during expansion.
    hash_type: Optional[str] = None
    expanded: bool = False              # Whether we've already called pivot endpoints for it
    discovered_iocs: List[str] = field(default_factory=list)  # IOCs this sig produced

    @property
    def signal_score(self) -> float:
        return round(self.coverage_ratio * self.rarity_score, 4)

    @property
    def signature_id(self) -> str:
        # Stable id used for attribution lookups; value can be long (hashes), so truncate.
        v = self.value if len(self.value) <= 32 else self.value[:32] + "..."
        return f"{self.param_type}:{v}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.signature_id,
            "param_type": self.param_type,
            "value": self.value,
            "hash_type": self.hash_type,
            "supporting_seeds": sorted(self.supporting_seeds),
            "seeds_covered": len(self.supporting_seeds),
            "coverage_ratio": round(self.coverage_ratio, 3),
            "rarity_score": round(self.rarity_score, 3),
            "signal_score": self.signal_score,
            "source_connectivity": self.source_connectivity,
            "expanded": self.expanded,
            "new_iocs_count": len(self.discovered_iocs),
            "discovered_iocs": self.discovered_iocs,
        }


@dataclass
class HuntResult:
    """Contains the full results of an infrastructure hunt."""
    timestamp: str
    seed_iocs: List[IOC]
    enrichment_results: Dict[str, EnrichmentResult]
    connections: List[Connection]
    new_iocs: List[NewIOC]
    pivot_depth: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Multi-indicator pivot results: seed value -> ranked list of matching hosts
    multi_indicator_matches: Dict[str, List['MultiIndicatorMatch']] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "metadata": {
                "timestamp": self.timestamp,
                "seed_iocs_count": len(self.seed_iocs),
                "new_iocs_found": len(self.new_iocs),
                "connections_found": len(self.connections),
                "pivot_depth": self.pivot_depth,
                **self.metadata
            },
            "seed_iocs": [
                {
                    "value": ioc.value,
                    "type": ioc.ioc_type.value,
                    "source": ioc.source_file
                }
                for ioc in self.seed_iocs
            ],
            "enrichment_results": {
                key: result.to_dict()
                for key, result in self.enrichment_results.items()
            },
            "connections": [c.to_dict() for c in self.connections],
            "new_iocs": [n.to_dict() for n in self.new_iocs],
            "multi_indicator_matches": {
                seed: [m.to_dict() for m in matches]
                for seed, matches in self.multi_indicator_matches.items()
            },
        }


@dataclass
class CorpusHuntResult:
    """
    Extends HuntResult with the set-intersection signatures extracted across the
    full seed corpus and the IOCs promoted via multi-signature match.
    """
    timestamp: str
    seed_iocs: List[IOC]
    enrichment_results: Dict[str, EnrichmentResult]
    connections: List[Connection]
    new_iocs: List[NewIOC]
    signatures: List[CorpusSignature]
    promoted_iocs: List[NewIOC]     # Subset of new_iocs matched by >= N signatures
    pivot_depth: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": {
                "timestamp": self.timestamp,
                "seed_iocs_count": len(self.seed_iocs),
                "new_iocs_found": len(self.new_iocs),
                "promoted_iocs_count": len(self.promoted_iocs),
                "signatures_count": len(self.signatures),
                "connections_found": len(self.connections),
                "pivot_depth": self.pivot_depth,
                "mode": "corpus",
                **self.metadata,
            },
            "seed_iocs": [
                {"value": ioc.value, "type": ioc.ioc_type.value, "source": ioc.source_file}
                for ioc in self.seed_iocs
            ],
            "signatures": [s.to_dict() for s in self.signatures],
            "promoted_iocs": [n.to_dict() for n in self.promoted_iocs],
            "enrichment_results": {
                key: result.to_dict() for key, result in self.enrichment_results.items()
            },
            "connections": [c.to_dict() for c in self.connections],
            "new_iocs": [n.to_dict() for n in self.new_iocs],
        }
