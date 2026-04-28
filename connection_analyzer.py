"""Connection analysis and scoring for infrastructure relationships."""

import logging
from typing import List, Dict, Any, Tuple, Set, Optional
from datetime import datetime
from difflib import SequenceMatcher

from models import (
    IOC, IOCType, Connection, ConnectionType, EnrichmentResult,
    DNSRecord, HostFingerprint, CertificateInfo, RegistrationInfo,
    NewIOC, HuntResult, LocationDomain, CorpusSignature,
    IndicatorHit, MultiIndicatorMatch,
)
from enrichment import EnrichmentEngine
from validin_client import ValidinAuthError, ValidinAPIError
from noise_filter import NoiseFilter, get_filter
from ioc_extractor import is_valid_ipv4
from config import (
    MAX_COTENANCY, MAX_HASH_CONNECTIVITY, REG_WINDOW_DAYS,
    HASH_TYPE_WEIGHTS, PIVOT_DEPTH, MIN_HASH_WEIGHT, MAX_HASH_QUERIES_PER_IOC,
    ENABLE_LOCATION_DOMAIN_PIVOTS, MAX_LOCATION_DOMAIN_CONNECTIVITY,
    LOCATION_DOMAIN_WEIGHT,
    CORPUS_MIN_COVERAGE, CORPUS_MIN_SIGS_FOR_PROMOTION,
    CORPUS_MAX_PIVOTS_PER_SIG, CORPUS_SIG_MIN_SIGNAL,
    CORPUS_PROMOTION_CONFIDENCE, CORPUS_MAX_SIGNATURES_TO_EXPAND,
    CORPUS_HASH_PARAM_TYPES,
    MULTI_INDICATOR_MAX_HASH_QUERIES, MULTI_INDICATOR_MAX_CONNECTIVITY,
    MULTI_INDICATOR_MAX_PER_HASH_TYPE,
    HASH_COLOCAL_WINDOW_HOURS,
    IP_COLOCAL_WINDOW_HOURS,
)


# Mapping Validin hash_type -> internal corpus param_type
_HASH_TYPE_TO_PARAM = {
    "HOST-HEADER_HASH": "header_hash",
    "HOST-BANNER_0_HASH": "banner_hash",
    "HOST-BODY_SHA1": "body_hash",
    "HOST-CERT_SHA1": "cert_sha1",
    "HOST-FAVICON_HASH": "favicon_hash",
    "HOST-CLASS_0_HASH": "class_hash",
    "HOST-CLASS_1_HASH": "class_hash",
    "TITLE-HOST": "title_hash",
}

_PARAM_TO_CONNECTION_TYPE = {
    "header_hash": ConnectionType.SHARED_HEADER_HASH,
    "banner_hash": ConnectionType.SHARED_BANNER_HASH,
    "body_hash": ConnectionType.SHARED_BODY_HASH,
    "cert_sha1": ConnectionType.SHARED_CERT,
    "favicon_hash": ConnectionType.SHARED_FAVICON,
    "class_hash": ConnectionType.SHARED_CLASS_HASH,
    "title_hash": ConnectionType.SHARED_TITLE,
    "san_domain": ConnectionType.SHARED_SAN,
    "registrar": ConnectionType.SHARED_REGISTRAR,
    "registrant_name": ConnectionType.SHARED_REGISTRANT,
    "registrant_org": ConnectionType.SHARED_REGISTRANT,
    "nameserver": ConnectionType.SHARED_NS,
    "shared_ip": ConnectionType.SHARED_IP,
    "subnet_24": ConnectionType.SAME_SUBNET,
    "osint_tag": ConnectionType.OSINT_COOCCURRENCE,
    "asn": ConnectionType.SHARED_ASN,
}


def _default_param_rarity(param_type: str) -> float:
    """Baseline rarity when we have no connectivity data for the parameter."""
    return {
        "header_hash": 0.9,
        "banner_hash": 0.9,
        "body_hash": 0.85,
        "cert_sha1": 0.9,
        "favicon_hash": 0.7,
        "class_hash": 0.75,
        "title_hash": 0.4,
        "san_domain": 0.7,
        "registrar": 0.15,
        "registrant_name": 0.85,
        "registrant_org": 0.85,
        "nameserver": 0.5,
        "shared_ip": 0.8,
        "subnet_24": 0.3,
        "osint_tag": 0.3,
        "asn": 0.35,
    }.get(param_type, 0.5)


def _as_strings(value: Any) -> List[str]:
    """Coerce a registration field that Validin may return as str/list/None into a clean list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple, set)):
        out: List[str] = []
        for v in value:
            if isinstance(v, str) and v.strip():
                out.append(v)
            elif isinstance(v, dict):
                # e.g. {"name": "...", "value": "..."} shapes — best-effort
                for k in ("name", "value", "text"):
                    s = v.get(k)
                    if isinstance(s, str) and s.strip():
                        out.append(s)
                        break
        return out
    return []


def _connectivity_rarity(connectivity: int) -> float:
    if connectivity <= 0:
        # 0 = unknown (Validin returned no data); fall back to neutral
        return 0.5
    if connectivity <= 5:
        return 1.0
    if connectivity <= 20:
        return 0.9
    if connectivity <= 50:
        return 0.8
    if connectivity <= 100:
        return 0.7
    if connectivity <= 200:
        return 0.5
    if connectivity <= 500:
        return 0.3
    return 0.1

logger = logging.getLogger(__name__)


def timestamps_overlap(
    a_first: int, a_last: int,
    b_first: int, b_last: int
) -> bool:
    """Check if two time ranges overlap."""
    return a_first <= b_last and b_first <= a_last


def calculate_overlap_ratio(
    a_first: int, a_last: int,
    b_first: int, b_last: int
) -> float:
    """Calculate the ratio of overlap between two time ranges."""
    if not timestamps_overlap(a_first, a_last, b_first, b_last):
        return 0.0

    overlap_start = max(a_first, b_first)
    overlap_end = min(a_last, b_last)
    overlap_duration = overlap_end - overlap_start

    total_duration = max(a_last, b_last) - min(a_first, b_first)
    if total_duration == 0:
        return 1.0

    return overlap_duration / total_duration


class ConnectionAnalyzer:
    """
    Analyzes infrastructure relationships and scores connections.

    Implements the 3-tier scoring system:
    - Tier 1 (0.8-1.0): Strong connections (shared IP, unique hashes, certs, content links)
    - Tier 2 (0.4-0.7): Moderate connections (registration patterns, NS, subnet)
    - Tier 3 (0.1-0.3): Contextual (OSINT co-occurrence, naming patterns)
    """

    def __init__(
        self,
        engine: EnrichmentEngine = None,
        noise_filter: NoiseFilter = None
    ):
        self.engine = engine or EnrichmentEngine()
        self.noise_filter = noise_filter or get_filter()
        self._connections: List[Connection] = []
        self._new_iocs: List[NewIOC] = []
        self._seen_connections: Set[Tuple[str, str, str]] = set()
        self._skip_hash_queries = False  # Set to True if hash queries fail with 403
        self._skip_ip_cotenancy_queries = False  # Set to True if IP cotenancy queries fail with 403
        self._skip_location_domain_queries = False  # Set to True if location domain queries fail

    def _add_connection(
        self,
        source: IOC,
        target: IOC,
        conn_type: ConnectionType,
        tier: int,
        score: float,
        evidence: Dict[str, Any],
        pivot_path: List[str],
        has_overlap: bool = False,
        notes: str = ""
    ):
        """Add a connection if not already recorded."""
        # Create unique key
        key = (
            min(source.value, target.value),
            max(source.value, target.value),
            conn_type.value
        )
        if key in self._seen_connections:
            return

        self._seen_connections.add(key)
        self._connections.append(Connection(
            source_ioc=source,
            target_ioc=target,
            connection_type=conn_type,
            confidence_tier=tier,
            confidence_score=score,
            evidence=evidence,
            pivot_path=pivot_path,
            timestamp_overlap=has_overlap,
            notes=notes
        ))
        logger.debug(
            f"Connection: {source.value} -> {target.value} "
            f"({conn_type.value}, tier={tier}, score={score:.2f})"
        )

    def _add_new_ioc(
        self,
        ioc: IOC,
        discovered_via: str,
        connected_to: str,
        score: float,
        tier: int,
        evidence: Dict[str, Any]
    ):
        """Add a newly discovered IOC."""
        # Check if already exists
        for existing in self._new_iocs:
            if existing.ioc.value == ioc.value:
                # Update if better score
                if score > existing.confidence_score:
                    existing.confidence_score = score
                    existing.confidence_tier = tier
                return

        self._new_iocs.append(NewIOC(
            ioc=ioc,
            discovered_via=discovered_via,
            connected_to_seed=connected_to,
            confidence_score=score,
            confidence_tier=tier,
            evidence=evidence
        ))

    # =========================================================================
    # Tier 1: Strong Connections
    # =========================================================================

    def analyze_shared_ip(
        self,
        source_result: EnrichmentResult,
        all_results: Dict[str, EnrichmentResult]
    ) -> List[Connection]:
        """
        Tier 1a: Analyze shared IP with low co-tenancy and temporal overlap.
        """
        source = source_result.ioc
        connections = []

        # Get A records for source
        source_ips = {}
        for record in source_result.dns_records:
            if record.record_type == 'A':
                if record.value not in source_ips:
                    source_ips[record.value] = []
                source_ips[record.value].append(record)

        # Check each IP
        for ip, source_records in source_ips.items():
            # Skip if not a valid IP (could be domain from reverse DNS)
            if not is_valid_ipv4(ip):
                logger.debug(f"  Skipping non-IP value in A record: {ip}")
                continue

            # Skip if IP cotenancy queries were disabled due to permission error
            if self._skip_ip_cotenancy_queries:
                cotenancy, cohosted_domains = 0, []
            else:
                try:
                    cotenancy, cohosted_domains = self.engine.get_ip_cotenancy(ip)
                except ValidinAuthError:
                    logger.warning("IP cotenancy queries not permitted - skipping IP analysis")
                    self._skip_ip_cotenancy_queries = True
                    cotenancy, cohosted_domains = 0, []

            # Skip if too many co-tenants
            if cotenancy > MAX_COTENANCY:
                logger.debug(f"  Skipping IP {ip} - too many co-tenants ({cotenancy})")
                continue

            # Check other enriched domains for this IP
            for target_key, target_result in all_results.items():
                if target_key == source.value:
                    continue

                target = target_result.ioc
                target_records = [
                    r for r in target_result.dns_records
                    if r.record_type == 'A' and r.value == ip
                ]

                if not target_records:
                    continue

                # Check temporal overlap
                for s_rec in source_records:
                    for t_rec in target_records:
                        has_overlap = timestamps_overlap(
                            s_rec.first_seen, s_rec.last_seen,
                            t_rec.first_seen, t_rec.last_seen
                        )
                        overlap_ratio = calculate_overlap_ratio(
                            s_rec.first_seen, s_rec.last_seen,
                            t_rec.first_seen, t_rec.last_seen
                        )

                        # Calculate score based on co-tenancy and overlap
                        if cotenancy <= 5:
                            base_score = 1.0
                        elif cotenancy <= 10:
                            base_score = 0.95
                        elif cotenancy <= 15:
                            base_score = 0.9
                        elif cotenancy <= 20:
                            base_score = 0.85
                        else:
                            base_score = 0.8

                        # Adjust for temporal overlap
                        if has_overlap:
                            score = base_score * (0.8 + 0.2 * overlap_ratio)
                        else:
                            score = base_score * 0.5  # Significant penalty for no overlap

                        # 48h co-deployment: did this IP appear on both seeds close together?
                        ip_co_deployment_hours: Optional[float] = None
                        ip_co_deployed = False
                        if s_rec.first_seen and t_rec.first_seen:
                            ip_co_deployment_hours = abs(s_rec.first_seen - t_rec.first_seen) / 3600
                            ip_co_deployed = ip_co_deployment_hours <= IP_COLOCAL_WINDOW_HOURS

                        evidence: dict = {
                            "shared_ip": ip,
                            "cotenancy": cotenancy,
                            "source_first_seen": s_rec.first_seen,
                            "source_last_seen": s_rec.last_seen,
                            "target_first_seen": t_rec.first_seen,
                            "target_last_seen": t_rec.last_seen,
                            "overlap_ratio": round(overlap_ratio, 2),
                        }
                        if ip_co_deployment_hours is not None:
                            evidence["ip_co_deployment_hours"] = round(ip_co_deployment_hours, 1)
                            evidence["ip_co_deployment_signal"] = ip_co_deployed

                        notes = f"Shared IP with {cotenancy} co-tenants"
                        if ip_co_deployed and ip_co_deployment_hours is not None:
                            notes += f" [IP co-deployed within {ip_co_deployment_hours:.0f}h]"

                        self._add_connection(
                            source=source,
                            target=target,
                            conn_type=ConnectionType.SHARED_IP,
                            tier=1,
                            score=round(score, 2),
                            evidence=evidence,
                            pivot_path=[source.value, f"-> IP {ip}", target.value],
                            has_overlap=has_overlap,
                            notes=notes,
                        )

            # Also discover new IOCs from co-hosting
            for host in cohosted_domains:
                if host == source.value:
                    continue
                if host in all_results:
                    continue
                # Skip hash-like values that aren't actual domains/IPs
                if self._looks_like_hash(host):
                    logger.debug(
                        f"  Skipping hash-like value from IP pivot: {host[:20]}..."
                    )
                    continue

                # Determine IOC type
                if self._looks_like_ip(host):
                    ioc_type = IOCType.IPV4
                else:
                    ioc_type = IOCType.DOMAIN

                new_ioc = IOC(
                    value=host,
                    ioc_type=ioc_type,
                    is_seed=False,
                    discovered_via="shared_ip_pivot",
                    connected_to_seed=source.value
                )

                # Score based on co-tenancy
                if cotenancy <= 5:
                    score = 0.95
                elif cotenancy <= 15:
                    score = 0.85
                else:
                    score = 0.75

                self._add_new_ioc(
                    ioc=new_ioc,
                    discovered_via="shared_ip_pivot",
                    connected_to=source.value,
                    score=score,
                    tier=1,
                    evidence={"shared_ip": ip, "cotenancy": cotenancy}
                )

        return connections

    def analyze_shared_hash(
        self,
        source_result: EnrichmentResult,
        all_results: Dict[str, EnrichmentResult]
    ) -> List[Connection]:
        """
        Tier 1b: Analyze shared host response fingerprints.
        """
        # Skip if hash queries were disabled due to permission error
        if self._skip_hash_queries:
            return []

        source = source_result.ioc
        hash_queries = 0

        for fp in source_result.host_fingerprints:
            # Check hash type weight - skip low-value hashes
            weight = HASH_TYPE_WEIGHTS.get(fp.hash_type, 0.5)
            if weight < MIN_HASH_WEIGHT:
                logger.debug(
                    f"  Skipping low-weight hash {fp.hash_value[:16]}... "
                    f"(type={fp.hash_type}, weight={weight})"
                )
                continue

            # Limit queries per IOC
            if hash_queries >= MAX_HASH_QUERIES_PER_IOC:
                logger.debug(
                    f"  Reached max hash queries ({MAX_HASH_QUERIES_PER_IOC}) for {source.value}"
                )
                break

            # Get full pivot data (timestamps + backend IPs)
            hash_queries += 1
            try:
                pivot_data = self.engine.get_hash_pivot_data(fp.hash_value)
            except ValidinAuthError:
                logger.warning("Hash pivot queries not permitted - skipping hash analysis")
                self._skip_hash_queries = True
                return []

            connectivity = pivot_data.connectivity
            if connectivity == 0:
                continue

            # Check noise
            noise_result = self.noise_filter.check_connectivity(
                connectivity, fp.hash_type
            )
            if noise_result.should_exclude:
                logger.debug(
                    f"  Skipping hash {fp.hash_value[:16]}... - "
                    f"too many connections ({connectivity})"
                )
                continue

            # Calculate base score from connectivity
            pivot_score = self.noise_filter.get_pivotability_score(
                connectivity, fp.hash_type
            )

            # Determine connection type
            if 'HEADER' in fp.hash_type.upper():
                conn_type = ConnectionType.SHARED_HEADER_HASH
            elif 'BANNER' in fp.hash_type.upper():
                conn_type = ConnectionType.SHARED_BANNER_HASH
            elif 'BODY' in fp.hash_type.upper():
                conn_type = ConnectionType.SHARED_BODY_HASH
            elif 'CERT' in fp.hash_type.upper():
                conn_type = ConnectionType.SHARED_CERT
            elif 'FAVICON' in fp.hash_type.upper():
                conn_type = ConnectionType.SHARED_FAVICON
            elif 'CLASS' in fp.hash_type.upper():
                conn_type = ConnectionType.SHARED_CLASS_HASH
            elif 'TITLE' in fp.hash_type.upper():
                conn_type = ConnectionType.SHARED_TITLE
            else:
                conn_type = ConnectionType.SHARED_HEADER_HASH

            # source's first_seen for this hash comes from its HostFingerprint record
            source_hash_first = fp.first_seen

            # Connect to other known IOCs
            for host in pivot_data.hosts:
                if host == source.value:
                    continue

                # Check if this is an existing IOC
                if host in all_results:
                    target = all_results[host].ioc

                    # Determine tier based on connectivity and hash type
                    if connectivity <= 20 and weight >= 0.9:
                        tier = 1
                        score = min(1.0, pivot_score * weight * 1.1)
                    elif connectivity <= MAX_HASH_CONNECTIVITY:
                        tier = 1
                        score = pivot_score * weight
                    else:
                        tier = 2
                        score = pivot_score * weight * 0.8

                    evidence: Dict[str, Any] = {
                        "hash_value": fp.hash_value,
                        "hash_type": fp.hash_type,
                        "connectivity": connectivity,
                        "weight": weight,
                    }

                    # Temporal co-deployment detection
                    target_hash_first = pivot_data.host_timestamps.get(host, (0, 0))[0]
                    co_deployment_hours: Optional[float] = None
                    co_deployed = False
                    if source_hash_first > 0 and target_hash_first > 0:
                        co_deployment_hours = abs(source_hash_first - target_hash_first) / 3600
                        co_deployed = co_deployment_hours <= HASH_COLOCAL_WINDOW_HOURS
                        evidence["source_hash_first_seen"] = source_hash_first
                        evidence["target_hash_first_seen"] = target_hash_first
                        evidence["co_deployment_hours"] = round(co_deployment_hours, 1)
                        evidence["co_deployment_signal"] = co_deployed

                    # Backend IP observations (non-CDN IPs that also carry this hash)
                    if pivot_data.backend_ips:
                        evidence["backend_ips"] = pivot_data.backend_ips
                        if pivot_data.ip_timestamps:
                            evidence["backend_ip_timestamps"] = {
                                ip: list(ts)
                                for ip, ts in pivot_data.ip_timestamps.items()
                            }

                    notes = f"{fp.hash_type} with {connectivity} connections"
                    if co_deployed and co_deployment_hours is not None:
                        notes += f" [co-deployed within {co_deployment_hours:.0f}h]"
                    elif pivot_data.backend_ips:
                        notes += f" [backend IPs: {', '.join(pivot_data.backend_ips[:3])}]"

                    self._add_connection(
                        source=source,
                        target=target,
                        conn_type=conn_type,
                        tier=tier,
                        score=round(score, 2),
                        evidence=evidence,
                        pivot_path=[
                            source.value,
                            f"-> {fp.hash_type} {fp.hash_value[:16]}...",
                            host
                        ],
                        has_overlap=co_deployed,
                        notes=notes,
                    )
                else:
                    # New IOC discovered - determine type
                    if self._looks_like_ip(host):
                        ioc_type = IOCType.IPV4
                    elif self._looks_like_hash(host):
                        # Skip hash/fingerprint values - they're not valid IOCs
                        logger.debug(
                            f"  Skipping hash-like value from pivot: {host[:20]}..."
                        )
                        continue
                    else:
                        ioc_type = IOCType.DOMAIN

                    new_ioc = IOC(
                        value=host,
                        ioc_type=ioc_type,
                        is_seed=False,
                        discovered_via=f"hash_pivot:{fp.hash_type}",
                        connected_to_seed=source.value
                    )

                    # Determine tier for new IOC
                    if connectivity <= 20 and weight >= 0.9:
                        tier = 1
                        score = min(1.0, pivot_score * weight * 1.1)
                    elif connectivity <= MAX_HASH_CONNECTIVITY:
                        tier = 1
                        score = pivot_score * weight
                    else:
                        tier = 2
                        score = pivot_score * weight * 0.7

                    new_evidence: Dict[str, Any] = {
                        "hash_value": fp.hash_value,
                        "hash_type": fp.hash_type,
                        "connectivity": connectivity,
                    }
                    if pivot_data.backend_ips:
                        new_evidence["backend_ips"] = pivot_data.backend_ips

                    self._add_new_ioc(
                        ioc=new_ioc,
                        discovered_via=f"hash_pivot:{fp.hash_type}",
                        connected_to=source.value,
                        score=round(score, 2),
                        tier=tier,
                        evidence=new_evidence,
                    )

    def analyze_shared_cert(
        self,
        source_result: EnrichmentResult,
        all_results: Dict[str, EnrichmentResult]
    ) -> List[Connection]:
        """
        Tier 1c: Analyze shared TLS certificates.
        """
        source = source_result.ioc

        for cert in source_result.certificates:
            # Check issuer
            issuer_check = self.noise_filter.check_cert_issuer(cert.issuer)
            if issuer_check.should_exclude:
                continue

            # Self-signed certs are more reliable for attribution
            if cert.is_self_signed:
                base_score = 0.95
                notes = "Self-signed certificate"
            elif issuer_check.is_noisy:
                base_score = 0.5
                notes = f"Common issuer: {issuer_check.provider}"
            else:
                base_score = 0.85
                notes = f"Certificate from {cert.issuer[:50]}"

            # Check if other IOCs share this cert
            for target_key, target_result in all_results.items():
                if target_key == source.value:
                    continue

                for target_cert in target_result.certificates:
                    if target_cert.sha1 == cert.sha1:
                        self._add_connection(
                            source=source,
                            target=target_result.ioc,
                            conn_type=ConnectionType.SHARED_CERT,
                            tier=1,
                            score=base_score,
                            evidence={
                                "cert_sha1": cert.sha1,
                                "issuer": cert.issuer,
                                "is_self_signed": cert.is_self_signed
                            },
                            pivot_path=[
                                source.value,
                                f"-> CERT {cert.sha1[:16]}...",
                                target_key
                            ],
                            notes=notes
                        )

    def analyze_shared_location_domain(
        self,
        source_result: EnrichmentResult,
        all_results: Dict[str, EnrichmentResult]
    ):
        """
        Tier 1d: Analyze shared redirect location domains.

        Domains that redirect to the same target domain (HOST-LOCATION_DOMAIN)
        are likely related infrastructure.
        """
        # Skip if disabled in config
        if not ENABLE_LOCATION_DOMAIN_PIVOTS:
            return

        # Skip if location domain queries were disabled due to auth error
        if self._skip_location_domain_queries:
            return

        source = source_result.ioc
        location_queries = 0
        max_location_queries = MAX_HASH_QUERIES_PER_IOC  # Reuse same limit

        for ld in source_result.location_domains:
            # Limit queries per IOC
            if location_queries >= max_location_queries:
                logger.debug(
                    f"  Reached max location domain queries ({max_location_queries}) "
                    f"for {source.value}"
                )
                break

            # Get connectivity for this location domain
            location_queries += 1
            try:
                connectivity, hosts = self.engine.get_location_domain_connectivity(
                    ld.location
                )
            except ValidinAuthError:
                logger.warning(
                    "Location domain pivot queries not permitted - skipping"
                )
                self._skip_location_domain_queries = True
                return

            if connectivity == 0:
                continue

            # Check noise - high connectivity means common redirect target
            if connectivity > MAX_LOCATION_DOMAIN_CONNECTIVITY:
                logger.debug(
                    f"  Skipping location domain {ld.location} - "
                    f"too many connections ({connectivity})"
                )
                continue

            # Calculate score based on connectivity and weight
            weight = LOCATION_DOMAIN_WEIGHT
            if connectivity <= 20:
                pivot_score = 0.95 * weight
            elif connectivity <= 50:
                pivot_score = 0.85 * weight
            elif connectivity <= 100:
                pivot_score = 0.75 * weight
            else:
                pivot_score = 0.6 * weight

            # Connect to other known IOCs or discover new ones
            for host in hosts:
                if host == source.value:
                    continue

                # Check if this is an existing IOC
                if host in all_results:
                    target = all_results[host].ioc

                    # Determine tier based on connectivity
                    if connectivity <= 20:
                        tier = 1
                        score = pivot_score
                    elif connectivity <= 100:
                        tier = 1
                        score = pivot_score * 0.9
                    else:
                        tier = 2
                        score = pivot_score * 0.7

                    self._add_connection(
                        source=source,
                        target=target,
                        conn_type=ConnectionType.SHARED_LOCATION_DOMAIN,
                        tier=tier,
                        score=round(score, 2),
                        evidence={
                            "location_domain": ld.location,
                            "connectivity": connectivity
                        },
                        pivot_path=[
                            source.value,
                            f"-> redirects to {ld.location}",
                            host
                        ],
                        notes=f"Both redirect to {ld.location} ({connectivity} hosts)"
                    )
                else:
                    # New IOC discovered
                    new_ioc = IOC(
                        value=host,
                        ioc_type=IOCType.DOMAIN,
                        is_seed=False,
                        discovered_via=f"location_domain_pivot:{ld.location}",
                        connected_to_seed=source.value
                    )

                    # Determine tier for new IOC
                    if connectivity <= 20:
                        tier = 1
                        score = min(1.0, pivot_score * 1.1)
                    elif connectivity <= 100:
                        tier = 1
                        score = pivot_score
                    else:
                        tier = 2
                        score = pivot_score * 0.7

                    self._add_new_ioc(
                        ioc=new_ioc,
                        discovered_via=f"location_domain_pivot:{ld.location}",
                        connected_to=source.value,
                        score=round(score, 2),
                        tier=tier,
                        evidence={
                            "location_domain": ld.location,
                            "connectivity": connectivity
                        }
                    )

    # =========================================================================
    # Tier 2: Moderate Connections
    # =========================================================================

    def analyze_registration_patterns(
        self,
        source_result: EnrichmentResult,
        all_results: Dict[str, EnrichmentResult]
    ):
        """
        Tier 2a: Analyze shared registration patterns.
        """
        source = source_result.ioc
        source_reg = source_result.registration

        if not source_reg or not source_reg.registrar:
            return

        for target_key, target_result in all_results.items():
            if target_key == source.value:
                continue

            target_reg = target_result.registration
            if not target_reg or not target_reg.registrar:
                continue

            # Same registrar? (handle registrar being str or list)
            def normalize_registrar(r):
                if isinstance(r, list):
                    return r[0].lower() if r else ""
                return r.lower() if r else ""

            if normalize_registrar(source_reg.registrar) != normalize_registrar(target_reg.registrar):
                continue

            # Check registration date proximity
            date_proximity = False
            days_apart = None
            if source_reg.created_date and target_reg.created_date:
                days_apart = abs(source_reg.created_date - target_reg.created_date) / 86400
                date_proximity = days_apart <= REG_WINDOW_DAYS

            # Calculate score
            if date_proximity:
                score = 0.6
                tier = 2
                notes = f"Same registrar + {days_apart:.0f} days apart"
            else:
                score = 0.4
                tier = 2
                notes = f"Same registrar ({source_reg.registrar})"

            self._add_connection(
                source=source,
                target=target_result.ioc,
                conn_type=ConnectionType.SHARED_REGISTRAR,
                tier=tier,
                score=score,
                evidence={
                    "registrar": source_reg.registrar,
                    "source_created": source_reg.created_date,
                    "target_created": target_reg.created_date,
                    "days_apart": days_apart
                },
                pivot_path=[source.value, f"-> Registrar", target_key],
                notes=notes
            )

    def analyze_shared_nameservers(
        self,
        source_result: EnrichmentResult,
        all_results: Dict[str, EnrichmentResult]
    ):
        """
        Tier 2b: Analyze shared non-default nameservers.
        """
        source = source_result.ioc
        source_reg = source_result.registration

        if not source_reg or not source_reg.nameservers:
            return

        # Filter out noisy nameservers
        source_ns, _ = self.noise_filter.filter_nameservers(source_reg.nameservers)
        if not source_ns:
            return

        for target_key, target_result in all_results.items():
            if target_key == source.value:
                continue

            target_reg = target_result.registration
            if not target_reg or not target_reg.nameservers:
                continue

            target_ns, _ = self.noise_filter.filter_nameservers(target_reg.nameservers)
            if not target_ns:
                continue

            # Find shared nameservers
            shared_ns = set(source_ns) & set(target_ns)
            if not shared_ns:
                continue

            self._add_connection(
                source=source,
                target=target_result.ioc,
                conn_type=ConnectionType.SHARED_NS,
                tier=2,
                score=0.6,
                evidence={
                    "shared_nameservers": list(shared_ns),
                    "source_ns": source_ns,
                    "target_ns": target_ns
                },
                pivot_path=[source.value, f"-> NS", target_key],
                notes=f"Shared nameservers: {', '.join(list(shared_ns)[:2])}"
            )

    def analyze_subnet(
        self,
        source_result: EnrichmentResult,
        all_results: Dict[str, EnrichmentResult]
    ):
        """
        Tier 2c: Analyze same /24 subnet connections.
        """
        source = source_result.ioc

        # Get /24 subnets from source A records
        source_subnets = set()
        for record in source_result.dns_records:
            if record.record_type == 'A':
                parts = record.value.split('.')
                if len(parts) == 4:
                    subnet = '.'.join(parts[:3])
                    source_subnets.add((subnet, record.value))

        for target_key, target_result in all_results.items():
            if target_key == source.value:
                continue

            for record in target_result.dns_records:
                if record.record_type == 'A':
                    parts = record.value.split('.')
                    if len(parts) == 4:
                        target_subnet = '.'.join(parts[:3])
                        for src_subnet, src_ip in source_subnets:
                            if src_subnet == target_subnet and src_ip != record.value:
                                self._add_connection(
                                    source=source,
                                    target=target_result.ioc,
                                    conn_type=ConnectionType.SAME_SUBNET,
                                    tier=2,
                                    score=0.5,
                                    evidence={
                                        "subnet": f"{src_subnet}.0/24",
                                        "source_ip": src_ip,
                                        "target_ip": record.value
                                    },
                                    pivot_path=[
                                        source.value,
                                        f"-> /24 {src_subnet}.0/24",
                                        target_key
                                    ],
                                    notes=f"Same /24 subnet ({src_subnet}.0/24)"
                                )

    # =========================================================================
    # Tier 3: Contextual Connections
    # =========================================================================

    def analyze_osint_cooccurrence(
        self,
        source_result: EnrichmentResult,
        all_results: Dict[str, EnrichmentResult]
    ):
        """
        Tier 3a: Analyze OSINT/threat feed co-occurrence.
        """
        source = source_result.ioc

        if not source_result.osint_hits:
            return

        source_feeds = {hit.feed_name for hit in source_result.osint_hits}

        for target_key, target_result in all_results.items():
            if target_key == source.value:
                continue

            if not target_result.osint_hits:
                continue

            target_feeds = {hit.feed_name for hit in target_result.osint_hits}
            shared_feeds = source_feeds & target_feeds

            if shared_feeds:
                self._add_connection(
                    source=source,
                    target=target_result.ioc,
                    conn_type=ConnectionType.OSINT_COOCCURRENCE,
                    tier=3,
                    score=0.3,
                    evidence={
                        "shared_feeds": list(shared_feeds),
                        "source_feeds": list(source_feeds),
                        "target_feeds": list(target_feeds)
                    },
                    pivot_path=[source.value, "-> OSINT", target_key],
                    notes=f"Shared threat feeds: {', '.join(list(shared_feeds)[:2])}"
                )

    def analyze_naming_patterns(
        self,
        source_result: EnrichmentResult,
        all_results: Dict[str, EnrichmentResult]
    ):
        """
        Tier 3b: Analyze domain naming pattern similarity.
        """
        source = source_result.ioc

        if source.ioc_type != IOCType.DOMAIN:
            return

        source_name = source.value.split('.')[0]  # Get domain name without TLD

        for target_key, target_result in all_results.items():
            if target_key == source.value:
                continue

            target = target_result.ioc
            if target.ioc_type != IOCType.DOMAIN:
                continue

            target_name = target.value.split('.')[0]

            # Calculate similarity
            similarity = SequenceMatcher(None, source_name, target_name).ratio()

            # Only flag if moderately similar (not identical, not completely different)
            if 0.5 <= similarity < 0.95:
                self._add_connection(
                    source=source,
                    target=target,
                    conn_type=ConnectionType.NAMING_PATTERN,
                    tier=3,
                    score=round(0.1 + similarity * 0.2, 2),
                    evidence={
                        "source_name": source_name,
                        "target_name": target_name,
                        "similarity": round(similarity, 2)
                    },
                    pivot_path=[source.value, "-> naming", target_key],
                    notes=f"Naming similarity: {similarity:.0%}"
                )

    # =========================================================================
    # Multi-Indicator Pivot Analysis
    # =========================================================================

    def find_multi_indicator_matches(
        self,
        seed_result: EnrichmentResult,
    ) -> List[MultiIndicatorMatch]:
        """
        Fan out from every indicator on a single seed and invert the result into a
        per-host view: for each host discovered via any indicator, record *all* the
        indicators it shares with the seed.

        Pivots on:
        - Host fingerprint hashes (banner, header, body, cert, favicon, class)
        - HOST-LOCATION_DOMAIN redirect targets
        - Shared IPs (co-tenancy, below noise threshold)

        Results are sorted by (indicator_count DESC, quality_score DESC) so the
        strongest multi-pivot matches surface first.
        """
        seed = seed_result.ioc.value
        # host -> accumulated hits
        host_hits: Dict[str, List[IndicatorHit]] = {}

        def record(
            host: str,
            indicator_type: str,
            indicator_value: str,
            connectivity: int,
            weight: float,
            first_seen: int = 0,
            last_seen: int = 0,
            backend_ips: Optional[List[str]] = None,
        ):
            if not host or host == seed:
                return
            if self._looks_like_hash(host):
                return
            hits = host_hits.setdefault(host, [])
            # Deduplicate by indicator TYPE — one entry per type, keep the
            # rarest (lowest connectivity) value so quality scores reflect the
            # best available signal for that indicator category.
            for i, existing in enumerate(hits):
                if existing.indicator_type == indicator_type:
                    if connectivity < existing.connectivity:
                        hits[i] = IndicatorHit(
                            indicator_type=indicator_type,
                            indicator_value=indicator_value,
                            connectivity=connectivity,
                            weight=weight,
                            first_seen=first_seen,
                            last_seen=last_seen,
                            backend_ips=backend_ips or [],
                        )
                    return
            hits.append(IndicatorHit(
                indicator_type=indicator_type,
                indicator_value=indicator_value,
                connectivity=connectivity,
                weight=weight,
                first_seen=first_seen,
                last_seen=last_seen,
                backend_ips=backend_ips or [],
            ))

        # --- Hash fingerprints ---
        # Group by hash type before querying so that a verbose type
        # (e.g. 37 HOST-BODY_SHA1 records) cannot starve other types.
        # Each type is queried independently up to MULTI_INDICATOR_MAX_PER_HASH_TYPE.
        from collections import defaultdict
        by_type: Dict[str, list] = defaultdict(list)
        for fp in seed_result.host_fingerprints:
            weight = HASH_TYPE_WEIGHTS.get(fp.hash_type, 0.5)
            if weight >= MIN_HASH_WEIGHT:
                by_type[fp.hash_type].append(fp)

        total_queries = 0
        auth_failed = False
        for hash_type, fps in by_type.items():
            if auth_failed or total_queries >= MULTI_INDICATOR_MAX_HASH_QUERIES:
                break
            weight = HASH_TYPE_WEIGHTS.get(hash_type, 0.5)
            for fp in fps[:MULTI_INDICATOR_MAX_PER_HASH_TYPE]:
                if total_queries >= MULTI_INDICATOR_MAX_HASH_QUERIES:
                    break
                total_queries += 1
                try:
                    pivot_data = self.engine.get_hash_pivot_data(fp.hash_value)
                except ValidinAuthError:
                    logger.warning("Hash pivot not permitted — skipping fingerprint pivots")
                    auth_failed = True
                    break
                connectivity = pivot_data.connectivity
                if connectivity > MULTI_INDICATOR_MAX_CONNECTIVITY:
                    logger.debug(
                        f"  [multi-indicator] skipping {fp.hash_type} "
                        f"(conn={connectivity} > {MULTI_INDICATOR_MAX_CONNECTIVITY})"
                    )
                    continue
                for host in pivot_data.hosts:
                    if self._looks_like_ip(host):
                        continue
                    if self.noise_filter.check_domain(host).should_exclude:
                        continue
                    ts = pivot_data.host_timestamps.get(host, (0, 0))
                    record(
                        host, fp.hash_type, fp.hash_value, connectivity, weight,
                        first_seen=ts[0], last_seen=ts[1],
                        backend_ips=pivot_data.backend_ips or None,
                    )
        logger.info(
            f"  [multi-indicator] queried {total_queries} hashes across "
            f"{len(by_type)} types for {seed}"
        )

        # --- HOST-LOCATION_DOMAIN ---
        # Use hash_pivots (via get_hash_connectivity) on the location domain
        # string — string_pivots often returns no HOST records for redirect
        # targets. Instead look up the location domain itself as a seed to find
        # all hosts that share the same redirect target.
        if ENABLE_LOCATION_DOMAIN_PIVOTS and not self._skip_location_domain_queries:
            for ld in seed_result.location_domains:
                try:
                    connectivity, hosts = self.engine.get_location_domain_connectivity(
                        ld.location
                    )
                except ValidinAuthError:
                    logger.warning("Location domain pivot not permitted")
                    self._skip_location_domain_queries = True
                    break
                if connectivity == 0 or connectivity > MAX_LOCATION_DOMAIN_CONNECTIVITY:
                    logger.debug(
                        f"  [multi-indicator] skipping location domain {ld.location} "
                        f"(conn={connectivity})"
                    )
                    continue
                logger.debug(
                    f"  [multi-indicator] HOST-LOCATION_DOMAIN {ld.location} "
                    f"→ {connectivity} hosts"
                )
                for host in hosts:
                    if self._looks_like_ip(host):
                        continue
                    if self.noise_filter.check_domain(host).should_exclude:
                        continue
                    record(
                        host, "HOST-LOCATION_DOMAIN", ld.location,
                        connectivity, LOCATION_DOMAIN_WEIGHT,
                    )

        # --- Shared IP co-tenancy ---
        if not self._skip_ip_cotenancy_queries:
            seen_ips: Set[str] = set()
            for rec in seed_result.dns_records:
                if rec.record_type != 'A' or not is_valid_ipv4(rec.value):
                    continue
                if rec.value in seen_ips:
                    continue
                seen_ips.add(rec.value)
                try:
                    cotenancy, domains = self.engine.get_ip_cotenancy(rec.value)
                except ValidinAuthError:
                    logger.warning("IP cotenancy not permitted")
                    self._skip_ip_cotenancy_queries = True
                    break
                if cotenancy > MAX_COTENANCY * 2:
                    continue
                # Weight scales down with more co-tenants
                ip_weight = round(
                    max(0.2, 1.0 - cotenancy / max(MAX_COTENANCY * 2, 1)), 2
                )
                for domain in domains:
                    if self.noise_filter.check_domain(domain).should_exclude:
                        continue
                    record(domain, "shared_ip", rec.value, cotenancy, ip_weight)

        # Build and rank MultiIndicatorMatch objects
        matches: List[MultiIndicatorMatch] = []
        for host, hits in host_hits.items():
            ioc_type = IOCType.IPV4 if self._looks_like_ip(host) else IOCType.DOMAIN
            quality = sum(
                hit.weight * _connectivity_rarity(hit.connectivity)
                for hit in hits
            )
            matches.append(MultiIndicatorMatch(
                host=host,
                ioc_type=ioc_type,
                indicator_hits=hits,
                quality_score=round(quality, 3),
            ))

        matches.sort(key=lambda m: (-m.indicator_count, -m.quality_score))
        multi_count = sum(1 for m in matches if m.indicator_count >= 2)
        logger.info(
            f"find_multi_indicator_matches({seed}): {len(matches)} hosts total, "
            f"{multi_count} share 2+ indicators"
        )
        return matches

    # =========================================================================
    # Main Analysis Pipeline
    # =========================================================================

    def _looks_like_ip(self, value: str) -> bool:
        """Quick check if value looks like an IP."""
        parts = value.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _looks_like_hash(self, value: str) -> bool:
        """
        Check if value looks like a hash/fingerprint rather than a domain.

        Hashes are hex strings of specific lengths:
        - MD5: 32 chars
        - SHA1: 40 chars
        - SHA256: 64 chars
        - Truncated hashes: 16-24 chars (common in API responses)
        """
        # Must be all hex characters
        if not all(c in '0123456789abcdefABCDEF' for c in value):
            return False

        # Common hash lengths (including truncated versions)
        hash_lengths = {16, 20, 24, 32, 40, 64}
        if len(value) in hash_lengths:
            return True

        # Also catch other hex-only strings that are clearly not domains
        # (no dots, all hex, length > 12)
        if len(value) > 12 and '.' not in value:
            return True

        return False

    def analyze_all(
        self,
        enrichment_results: Dict[str, EnrichmentResult],
        pivot_depth: int = 1
    ) -> Tuple[List[Connection], List[NewIOC]]:
        """
        Run all connection analyses on enrichment results.

        Args:
            enrichment_results: Dict of IOC value -> EnrichmentResult
            pivot_depth: How deep to pivot

        Returns:
            Tuple of (connections, new_iocs)
        """
        self._connections = []
        self._new_iocs = []
        self._seen_connections = set()

        logger.info(f"Analyzing {len(enrichment_results)} enriched IOCs...")

        for ioc_key, result in enrichment_results.items():
            logger.debug(f"Analyzing connections for: {ioc_key}")

            # Tier 1 analyses
            self.analyze_shared_ip(result, enrichment_results)
            self.analyze_shared_hash(result, enrichment_results)
            self.analyze_shared_cert(result, enrichment_results)
            self.analyze_shared_location_domain(result, enrichment_results)

            # Tier 2 analyses
            self.analyze_registration_patterns(result, enrichment_results)
            self.analyze_shared_nameservers(result, enrichment_results)
            self.analyze_subnet(result, enrichment_results)

            # Tier 3 analyses
            self.analyze_osint_cooccurrence(result, enrichment_results)
            self.analyze_naming_patterns(result, enrichment_results)

        # Sort connections by score
        self._connections.sort(key=lambda c: (-c.confidence_tier, -c.confidence_score))

        # Sort new IOCs by score
        self._new_iocs.sort(key=lambda n: (-n.confidence_tier, -n.confidence_score))

        logger.info(
            f"Analysis complete: {len(self._connections)} connections, "
            f"{len(self._new_iocs)} new IOCs"
        )

        # Summary by tier
        tier_counts = {1: 0, 2: 0, 3: 0}
        for conn in self._connections:
            tier_counts[conn.confidence_tier] += 1
        for tier, count in tier_counts.items():
            logger.info(f"  Tier {tier}: {count} connections")

        return self._connections, self._new_iocs

    # =========================================================================
    # Corpus Mode
    # =========================================================================

    def analyze_corpus(
        self,
        enrichment_results: Dict[str, EnrichmentResult],
        min_coverage: int = CORPUS_MIN_COVERAGE,
    ) -> List[CorpusSignature]:
        """
        Find parameters shared across >= min_coverage seeds. These are the
        "CorpusSignatures" that characterize the operation's infrastructure.

        Uses connectivity captured during seed enrichment when available
        (HostFingerprint.connectivity) to score rarity; otherwise falls back
        to per-param-type defaults.
        """
        total_seeds = len(enrichment_results)
        if total_seeds < min_coverage:
            logger.warning(
                f"Corpus has {total_seeds} seeds — below min_coverage={min_coverage}. "
                "No signatures will be produced."
            )
            return []

        # (param_type, value) -> {supporting_seeds, min_connectivity, hash_type}
        buckets: Dict[Tuple[str, str], Dict[str, Any]] = {}

        def bump(
            param_type: str,
            value: str,
            seed: str,
            connectivity: Optional[int] = None,
            hash_type: Optional[str] = None,
        ):
            if not value:
                return
            key = (param_type, value)
            b = buckets.setdefault(
                key,
                {"seeds": set(), "connectivity": None, "hash_type": hash_type},
            )
            b["seeds"].add(seed)
            if connectivity is not None and connectivity > 0:
                # Use the minimum observed connectivity (rarest reading) for scoring
                if b["connectivity"] is None or connectivity < b["connectivity"]:
                    b["connectivity"] = connectivity

        for seed_value, result in enrichment_results.items():
            # --- Host fingerprints (hashes) ---
            seen_in_this_seed: Set[Tuple[str, str]] = set()
            for fp in result.host_fingerprints:
                param_type = _HASH_TYPE_TO_PARAM.get(fp.hash_type)
                if not param_type:
                    continue
                k = (param_type, fp.hash_value)
                if k in seen_in_this_seed:
                    continue
                seen_in_this_seed.add(k)
                bump(
                    param_type, fp.hash_value, seed_value,
                    connectivity=fp.connectivity or None,
                    hash_type=fp.hash_type,
                )

            # --- Certificates ---
            for cert in result.certificates:
                issuer_check = self.noise_filter.check_cert_issuer(cert.issuer)
                if not issuer_check.should_exclude and cert.sha1:
                    bump("cert_sha1", cert.sha1, seed_value, hash_type="HOST-CERT_SHA1")
                for san in cert.domains or []:
                    san_check = self.noise_filter.check_domain(san)
                    if san_check.should_exclude:
                        continue
                    if san == seed_value:
                        continue
                    bump("san_domain", san.lower(), seed_value)

            # --- Registration ---
            reg = result.registration
            if reg:
                for val in _as_strings(reg.registrar):
                    bump("registrar", val.strip().lower(), seed_value)
                for name in _as_strings(reg.registrant_name):
                    name = name.strip()
                    if name and not self._is_generic_registrant(name):
                        bump("registrant_name", name, seed_value)
                for org in _as_strings(reg.registrant_org):
                    org = org.strip()
                    if org and not self._is_generic_registrant(org):
                        bump("registrant_org", org, seed_value)
                ns_list = reg.nameservers if isinstance(reg.nameservers, list) else _as_strings(reg.nameservers)
                pivotable_ns, _ = self.noise_filter.filter_nameservers(ns_list)
                for ns in pivotable_ns:
                    if isinstance(ns, str) and ns.strip():
                        bump("nameserver", ns.strip().lower(), seed_value)

            # --- DNS A records (shared IPs + /24) ---
            ips_seen: Set[str] = set()
            for rec in result.dns_records:
                if rec.record_type not in ("A", "AAAA") or not is_valid_ipv4(rec.value):
                    continue
                if rec.value in ips_seen:
                    continue
                ips_seen.add(rec.value)
                bump("shared_ip", rec.value, seed_value)
                subnet = ".".join(rec.value.split(".")[:3]) + ".0/24"
                bump("subnet_24", subnet, seed_value)

            # --- OSINT co-occurrence ---
            tags_seen: Set[str] = set()
            for hit in result.osint_hits:
                tag = f"{hit.feed_name}:{hit.category}".strip(":")
                if tag in tags_seen or not tag:
                    continue
                tags_seen.add(tag)
                bump("osint_tag", tag, seed_value)

            # --- HOST-LOCATION_DOMAIN (redirect targets) ---
            for ld in result.location_domains:
                loc = ld.location.strip().lower() if ld.location else ""
                if not loc or loc == seed_value:
                    continue
                if self.noise_filter.check_domain(loc).should_exclude:
                    continue
                bump("location_domain", loc, seed_value)

        # Materialise signatures
        signatures: List[CorpusSignature] = []
        for (param_type, value), b in buckets.items():
            if len(b["seeds"]) < min_coverage:
                continue
            coverage_ratio = len(b["seeds"]) / total_seeds
            connectivity = b["connectivity"]
            if param_type in CORPUS_HASH_PARAM_TYPES and connectivity is not None:
                rarity = _connectivity_rarity(connectivity)
            else:
                rarity = _default_param_rarity(param_type)
            signatures.append(CorpusSignature(
                param_type=param_type,
                value=value,
                supporting_seeds=b["seeds"],
                coverage_ratio=coverage_ratio,
                rarity_score=rarity,
                source_connectivity=connectivity,
                hash_type=b["hash_type"],
            ))

        signatures.sort(key=lambda s: -s.signal_score)
        logger.info(
            f"analyze_corpus: {len(signatures)} signatures from {total_seeds} seeds "
            f"(min_coverage={min_coverage})"
        )
        return signatures

    @staticmethod
    def _is_generic_registrant(name: str) -> bool:
        """Filter out privacy-service / placeholder registrants that would poison signatures."""
        n = name.lower()
        needles = (
            "redacted", "privacy", "whoisguard", "withheld", "data protected",
            "domain administrator", "domains by proxy", "contact privacy",
            "gdpr masked", "not disclosed", "n/a",
        )
        return any(needle in n for needle in needles)

    def expand_via_signatures(
        self,
        signatures: List[CorpusSignature],
        enrichment_results: Dict[str, EnrichmentResult],
        max_signatures: int = CORPUS_MAX_SIGNATURES_TO_EXPAND,
        max_per_sig: int = CORPUS_MAX_PIVOTS_PER_SIG,
        min_signal: float = CORPUS_SIG_MIN_SIGNAL,
    ) -> Dict[str, NewIOC]:
        """
        For each high-signal signature, query the matching pivot endpoint and
        attribute each discovered host back to the signature(s) that surfaced it.

        Returns: map value -> NewIOC with source_signatures populated.
        """
        seed_values = set(enrichment_results.keys())
        discovered: Dict[str, NewIOC] = {}
        expanded_count = 0

        for sig in signatures:
            if expanded_count >= max_signatures:
                logger.info(
                    f"  Reached CORPUS_MAX_SIGNATURES_TO_EXPAND={max_signatures}; "
                    "skipping remaining signatures"
                )
                break
            if sig.signal_score < min_signal:
                continue

            hosts = self._expand_signature(sig, max_per_sig)
            sig.expanded = True
            expanded_count += 1

            for host in hosts:
                if not host or host in seed_values:
                    continue
                if self._looks_like_hash(host):
                    continue
                host_norm = host.lower().strip()
                if not host_norm:
                    continue

                if self._looks_like_ip(host_norm):
                    ioc_type = IOCType.IPV4
                else:
                    # Skip clearly-noisy domains
                    if self.noise_filter.check_domain(host_norm).should_exclude:
                        continue
                    ioc_type = IOCType.DOMAIN

                existing = discovered.get(host_norm)
                connected_seed = sorted(sig.supporting_seeds)[0] if sig.supporting_seeds else ""

                if existing is None:
                    new_ioc = IOC(
                        value=host_norm,
                        ioc_type=ioc_type,
                        is_seed=False,
                        discovered_via=f"corpus_sig:{sig.param_type}",
                        connected_to_seed=connected_seed,
                    )
                    base_score = sig.signal_score if sig.signal_score > 0 else 0.4
                    # Scale into a [0.4, 0.9] preliminary band; promotion may override.
                    pre_score = round(min(0.9, 0.4 + 0.5 * base_score), 2)
                    tier = 1 if pre_score >= 0.7 else (2 if pre_score >= 0.5 else 3)
                    discovered[host_norm] = NewIOC(
                        ioc=new_ioc,
                        discovered_via=f"corpus_sig:{sig.param_type}",
                        connected_to_seed=connected_seed,
                        confidence_score=pre_score,
                        confidence_tier=tier,
                        evidence={
                            "first_signature": sig.signature_id,
                            "first_signature_value": sig.value,
                            "first_signature_coverage": len(sig.supporting_seeds),
                        },
                        source_signatures=[sig.signature_id],
                    )
                else:
                    if sig.signature_id not in existing.source_signatures:
                        existing.source_signatures.append(sig.signature_id)
                        # Bump score slightly per additional matching signature
                        bump_val = round(min(1.0, existing.confidence_score + 0.05), 2)
                        existing.confidence_score = bump_val

                sig.discovered_iocs.append(host_norm)

        logger.info(
            f"expand_via_signatures: expanded {expanded_count}/{len(signatures)} signatures, "
            f"discovered {len(discovered)} candidate IOCs"
        )
        return discovered

    def _expand_signature(
        self, sig: CorpusSignature, max_per_sig: int
    ) -> List[str]:
        """Call the appropriate pivot endpoint for this signature and return a host list."""
        try:
            if sig.param_type in CORPUS_HASH_PARAM_TYPES:
                connectivity, hosts = self.engine.get_hash_connectivity(sig.value)
                if sig.source_connectivity is None:
                    sig.source_connectivity = connectivity
                return hosts[:max_per_sig]

            if sig.param_type == "shared_ip":
                cotenancy, domains = self.engine.get_ip_cotenancy(sig.value)
                if sig.source_connectivity is None:
                    sig.source_connectivity = cotenancy
                if cotenancy > MAX_COTENANCY * 4:
                    logger.debug(f"  Skipping IP {sig.value} — cotenancy {cotenancy} too high")
                    return []
                return domains[:max_per_sig]

            if sig.param_type in ("registrant_name", "registrant_org", "nameserver"):
                try:
                    pivots = self.engine.client.string_pivots(sig.value, limit=max_per_sig)
                except ValidinAuthError:
                    logger.warning(
                        f"string_pivots not permitted — skipping {sig.param_type}"
                    )
                    return []
                hosts: List[str] = []
                for _, records in pivots.get("records", {}).items():
                    for r in records:
                        v = r.get("value") or r.get("key") or ""
                        if v and v not in hosts:
                            hosts.append(v)
                return hosts[:max_per_sig]

            if sig.param_type == "san_domain":
                # A SAN shared across seed certs IS itself a host we want to lift.
                # Return the SAN as its own discovery; downstream enrich will fan out.
                return [sig.value]

            if sig.param_type == "location_domain":
                if not ENABLE_LOCATION_DOMAIN_PIVOTS or self._skip_location_domain_queries:
                    return []
                try:
                    connectivity, hosts = self.engine.get_location_domain_connectivity(sig.value)
                    if sig.source_connectivity is None:
                        sig.source_connectivity = connectivity
                    if connectivity > MAX_LOCATION_DOMAIN_CONNECTIVITY:
                        logger.debug(
                            f"  Skipping location_domain {sig.value} — connectivity {connectivity} too high"
                        )
                        return []
                    return hosts[:max_per_sig]
                except Exception:
                    self._skip_location_domain_queries = True
                    return []

            # registrar / subnet_24 / asn / osint_tag — recorded but not expanded
            return []
        except ValidinAPIError as e:
            logger.warning(f"Signature expansion failed for {sig.signature_id}: {e}")
            return []

    def promote_multi_signature_hits(
        self,
        discovered: Dict[str, NewIOC],
        min_sigs: int = CORPUS_MIN_SIGS_FOR_PROMOTION,
        confidence_floor: float = CORPUS_PROMOTION_CONFIDENCE,
    ) -> List[NewIOC]:
        """
        Any IOC attributed to >= min_sigs distinct signatures is promoted to
        Tier 1 with confidence >= confidence_floor, regardless of per-signature scores.
        """
        promoted: List[NewIOC] = []
        for ioc in discovered.values():
            if len(ioc.source_signatures) >= min_sigs:
                ioc.promoted = True
                ioc.confidence_score = max(ioc.confidence_score, confidence_floor)
                ioc.confidence_tier = 1
                ioc.evidence["multi_signature_match"] = True
                ioc.evidence["signatures_matched"] = list(ioc.source_signatures)
                promoted.append(ioc)
        promoted.sort(key=lambda n: (-len(n.source_signatures), -n.confidence_score))
        logger.info(
            f"promote_multi_signature_hits: {len(promoted)}/{len(discovered)} "
            f"IOCs promoted (min_sigs={min_sigs})"
        )
        return promoted

    def build_corpus_connections(
        self,
        signatures: List[CorpusSignature],
        discovered: Dict[str, NewIOC],
    ) -> List[Connection]:
        """
        Turn signature attributions into Connection objects linking each
        supporting seed to each discovered host via the signature's native type.
        Uses SHARED_* ConnectionTypes so existing reporting still renders them.
        """
        connections: List[Connection] = []
        seen: Set[Tuple[str, str, str]] = set()

        for sig in signatures:
            if not sig.discovered_iocs:
                continue
            conn_type = _PARAM_TO_CONNECTION_TYPE.get(
                sig.param_type, ConnectionType.CORPUS_SIGNATURE_MATCH
            )
            for seed in sig.supporting_seeds:
                for host in sig.discovered_iocs:
                    new_ioc = discovered.get(host)
                    if new_ioc is None:
                        continue
                    key = (min(seed, host), max(seed, host), conn_type.value)
                    if key in seen:
                        continue
                    seen.add(key)
                    src = IOC(value=seed, ioc_type=IOCType.DOMAIN, is_seed=True)
                    tier = 1 if new_ioc.promoted else new_ioc.confidence_tier
                    score = new_ioc.confidence_score
                    connections.append(Connection(
                        source_ioc=src,
                        target_ioc=new_ioc.ioc,
                        connection_type=conn_type,
                        confidence_tier=tier,
                        confidence_score=score,
                        evidence={
                            "signature": sig.signature_id,
                            "signature_value": sig.value,
                            "seeds_covered": len(sig.supporting_seeds),
                            "rarity": sig.rarity_score,
                            "multi_signature": new_ioc.promoted,
                        },
                        pivot_path=[seed, f"-> {sig.signature_id}", host],
                        notes=(
                            f"Corpus signature ({len(sig.supporting_seeds)} seeds share)"
                            + (" [PROMOTED]" if new_ioc.promoted else "")
                        ),
                    ))
        return connections

    def run_corpus_hunt(
        self,
        enrichment_results: Dict[str, EnrichmentResult],
    ) -> Tuple[List[CorpusSignature], Dict[str, NewIOC], List[NewIOC], List[Connection]]:
        """
        End-to-end corpus pipeline: analyze -> expand -> promote -> build connections.
        """
        signatures = self.analyze_corpus(enrichment_results)
        discovered = self.expand_via_signatures(signatures, enrichment_results)
        promoted = self.promote_multi_signature_hits(discovered)
        connections = self.build_corpus_connections(signatures, discovered)
        return signatures, discovered, promoted, connections

    def get_high_confidence_connections(
        self, min_score: float = 0.7
    ) -> List[Connection]:
        """Get connections above a confidence threshold."""
        return [c for c in self._connections if c.confidence_score >= min_score]

    def get_tier1_connections(self) -> List[Connection]:
        """Get only Tier 1 (strong) connections."""
        return [c for c in self._connections if c.confidence_tier == 1]


# =============================================================================
# CLI for Testing
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("Connection Analyzer - Unit Tests")
    print("=" * 50)

    # Test timestamp overlap
    print("\nTimestamp overlap tests:")
    cases = [
        ((100, 200, 150, 250), True, "Overlapping"),
        ((100, 200, 300, 400), False, "Non-overlapping"),
        ((100, 300, 150, 250), True, "Contained"),
        ((100, 200, 200, 300), True, "Adjacent"),
    ]
    for (a1, a2, b1, b2), expected, desc in cases:
        result = timestamps_overlap(a1, a2, b1, b2)
        status = "PASS" if result == expected else "FAIL"
        print(f"  {status}: {desc} - overlap={result}")

    # Test overlap ratio
    print("\nOverlap ratio tests:")
    ratio = calculate_overlap_ratio(100, 200, 150, 250)
    print(f"  (100-200) vs (150-250): {ratio:.2f}")

    ratio = calculate_overlap_ratio(100, 300, 150, 250)
    print(f"  (100-300) vs (150-250): {ratio:.2f}")
