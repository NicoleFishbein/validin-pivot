"""Noise filtering for CDN, cloud, parking, and common infrastructure."""

import re
import logging
from typing import Optional, Tuple, List, Set
from dataclasses import dataclass
from enum import Enum

from config import (
    NOISY_NS_PATTERNS, NOISY_ASNS, FLAGGED_ASNS,
    EXCLUDED_DOMAINS, PARKING_INDICATORS, COMMON_CERT_ISSUERS
)

logger = logging.getLogger(__name__)


class NoiseType(Enum):
    """Types of noise classification."""
    CLEAN = "clean"                     # Not noisy
    CDN_CLOUD = "cdn_cloud"             # CDN or major cloud provider
    COMMON_NS = "common_ns"             # Common nameserver provider
    PARKING = "parking"                 # Parked or sinkholed domain
    COMMON_CERT = "common_cert"         # Common certificate issuer
    EXCLUDED_DOMAIN = "excluded_domain" # Explicitly excluded domain
    HIGH_CONNECTIVITY = "high_connectivity"  # Too many connections
    FLAGGED = "flagged"                 # Flagged but not excluded (e.g., DigitalOcean)


@dataclass
class NoiseResult:
    """Result of noise classification."""
    is_noisy: bool
    noise_type: NoiseType
    reason: str = ""
    should_exclude: bool = False  # True = skip entirely, False = flag only
    provider: str = ""            # Identified provider name


class NoiseFilter:
    """
    Filter and classify noisy infrastructure.

    Usage:
        filter = NoiseFilter()
        result = filter.check_ip("104.21.234.56")
        if result.is_noisy:
            logger.info(f"Noisy IP: {result.reason}")
    """

    def __init__(self):
        # Compile NS patterns
        self._ns_patterns = [re.compile(p, re.IGNORECASE) for p in NOISY_NS_PATTERNS]

        # Build domain suffix set for faster lookups
        self._excluded_suffixes = set()
        for domain in EXCLUDED_DOMAINS:
            self._excluded_suffixes.add(domain.lower())
            self._excluded_suffixes.add('.' + domain.lower())

    def check_domain(self, domain: str) -> NoiseResult:
        """Check if a domain should be filtered as noise."""
        domain_lower = domain.lower()

        # Check against exclusion list
        for suffix in self._excluded_suffixes:
            if domain_lower == suffix.lstrip('.') or domain_lower.endswith(suffix):
                return NoiseResult(
                    is_noisy=True,
                    noise_type=NoiseType.EXCLUDED_DOMAIN,
                    reason=f"Excluded domain: {suffix.lstrip('.')}",
                    should_exclude=True,
                    provider=suffix.lstrip('.')
                )

        return NoiseResult(is_noisy=False, noise_type=NoiseType.CLEAN)

    def check_nameserver(self, ns: str) -> NoiseResult:
        """Check if a nameserver is from a common provider."""
        ns_lower = ns.lower()

        for pattern in self._ns_patterns:
            if pattern.match(ns_lower):
                # Extract provider from pattern
                if 'cloudflare' in ns_lower:
                    provider = 'Cloudflare'
                elif 'awsdns' in ns_lower:
                    provider = 'AWS Route53'
                elif 'domaincontrol' in ns_lower:
                    provider = 'GoDaddy'
                elif 'google' in ns_lower:
                    provider = 'Google Cloud DNS'
                elif 'registrar-servers' in ns_lower:
                    provider = 'Namecheap'
                elif 'hichina' in ns_lower:
                    provider = 'Alibaba'
                elif 'dnspod' in ns_lower:
                    provider = 'DNSPod/Tencent'
                else:
                    provider = 'Common NS Provider'

                return NoiseResult(
                    is_noisy=True,
                    noise_type=NoiseType.COMMON_NS,
                    reason=f"Common nameserver: {provider}",
                    should_exclude=True,  # Don't pivot on common NS
                    provider=provider
                )

        return NoiseResult(is_noisy=False, noise_type=NoiseType.CLEAN)

    def check_asn(self, asn: int) -> NoiseResult:
        """Check if an ASN belongs to a CDN or major cloud provider."""
        # Check fully noisy ASNs (CDNs, major clouds)
        if asn in NOISY_ASNS:
            return NoiseResult(
                is_noisy=True,
                noise_type=NoiseType.CDN_CLOUD,
                reason=f"CDN/Cloud ASN: {NOISY_ASNS[asn]}",
                should_exclude=True,
                provider=NOISY_ASNS[asn]
            )

        # Check flagged ASNs (commonly used by actors, flag but don't exclude)
        if asn in FLAGGED_ASNS:
            return NoiseResult(
                is_noisy=True,
                noise_type=NoiseType.FLAGGED,
                reason=f"Flagged hosting provider: {FLAGGED_ASNS[asn]}",
                should_exclude=False,  # Don't auto-exclude, just flag
                provider=FLAGGED_ASNS[asn]
            )

        return NoiseResult(is_noisy=False, noise_type=NoiseType.CLEAN)

    def check_cert_issuer(self, issuer: str) -> NoiseResult:
        """Check if certificate issuer is too common for reliable pivoting."""
        issuer_lower = issuer.lower()

        for common_issuer in COMMON_CERT_ISSUERS:
            if common_issuer.lower() in issuer_lower:
                # Let's Encrypt is particularly common
                if 'let' in issuer_lower and 'encrypt' in issuer_lower:
                    return NoiseResult(
                        is_noisy=True,
                        noise_type=NoiseType.COMMON_CERT,
                        reason="Let's Encrypt certificate (very common)",
                        should_exclude=True,
                        provider="Let's Encrypt"
                    )
                return NoiseResult(
                    is_noisy=True,
                    noise_type=NoiseType.COMMON_CERT,
                    reason=f"Common certificate issuer: {common_issuer}",
                    should_exclude=False,  # Flag but don't auto-exclude
                    provider=common_issuer
                )

        return NoiseResult(is_noisy=False, noise_type=NoiseType.CLEAN)

    def check_page_title(self, title: str) -> NoiseResult:
        """Check if page title indicates parking or placeholder."""
        title_lower = title.lower()

        for parking_title in PARKING_INDICATORS['titles']:
            if parking_title in title_lower:
                return NoiseResult(
                    is_noisy=True,
                    noise_type=NoiseType.PARKING,
                    reason=f"Parking page detected: {parking_title}",
                    should_exclude=True,
                    provider="Parking"
                )

        return NoiseResult(is_noisy=False, noise_type=NoiseType.CLEAN)

    def check_body_hash(self, body_hash: str) -> NoiseResult:
        """Check if body hash matches known parking pages."""
        if body_hash in PARKING_INDICATORS['body_hashes']:
            return NoiseResult(
                is_noisy=True,
                noise_type=NoiseType.PARKING,
                reason="Known parking page body hash",
                should_exclude=True,
                provider="Parking"
            )
        return NoiseResult(is_noisy=False, noise_type=NoiseType.CLEAN)

    def check_connectivity(
        self, connectivity: int, hash_type: str = None
    ) -> NoiseResult:
        """
        Check if hash connectivity is too high for reliable pivoting.

        Args:
            connectivity: Number of hosts sharing this hash
            hash_type: Type of hash (affects threshold)
        """
        # Default thresholds
        thresholds = {
            'very_high': 1000,
            'high': 500,
            'moderate': 100,
        }

        # Adjust for hash type - favicon needs stricter threshold
        if hash_type and 'FAVICON' in hash_type.upper():
            thresholds = {'very_high': 500, 'high': 200, 'moderate': 50}
        elif hash_type and 'TITLE' in hash_type.upper():
            thresholds = {'very_high': 200, 'high': 100, 'moderate': 25}

        if connectivity >= thresholds['very_high']:
            return NoiseResult(
                is_noisy=True,
                noise_type=NoiseType.HIGH_CONNECTIVITY,
                reason=f"Very high connectivity: {connectivity} hosts",
                should_exclude=True,
                provider=""
            )
        elif connectivity >= thresholds['high']:
            return NoiseResult(
                is_noisy=True,
                noise_type=NoiseType.HIGH_CONNECTIVITY,
                reason=f"High connectivity: {connectivity} hosts",
                should_exclude=False,  # Flag but don't exclude
                provider=""
            )

        return NoiseResult(is_noisy=False, noise_type=NoiseType.CLEAN)

    def filter_nameservers(self, nameservers: List[str]) -> Tuple[List[str], List[str]]:
        """
        Separate nameservers into pivotable and noisy.

        Returns:
            Tuple of (pivotable_ns, noisy_ns)
        """
        pivotable = []
        noisy = []

        for ns in nameservers:
            result = self.check_nameserver(ns)
            if result.is_noisy:
                noisy.append(ns)
                logger.debug(f"Filtered NS: {ns} ({result.reason})")
            else:
                pivotable.append(ns)

        return pivotable, noisy

    def filter_domains(self, domains: List[str]) -> Tuple[List[str], List[str]]:
        """
        Separate domains into relevant and excluded.

        Returns:
            Tuple of (relevant_domains, excluded_domains)
        """
        relevant = []
        excluded = []

        for domain in domains:
            result = self.check_domain(domain)
            if result.should_exclude:
                excluded.append(domain)
                logger.debug(f"Filtered domain: {domain} ({result.reason})")
            else:
                relevant.append(domain)

        return relevant, excluded

    def get_pivotability_score(
        self,
        connectivity: int,
        hash_type: str = None,
        is_self_signed_cert: bool = False
    ) -> float:
        """
        Calculate a pivotability score (0.0 - 1.0) based on connectivity.

        Lower connectivity = higher score = more reliable pivot.

        Args:
            connectivity: Number of hosts sharing this hash/cert
            hash_type: Type of hash (affects scoring)
            is_self_signed_cert: Whether cert is self-signed (boosts score)

        Returns:
            Score from 0.0 (unreliable) to 1.0 (highly reliable)
        """
        if connectivity <= 0:
            return 0.0

        # Base score calculation
        if connectivity <= 5:
            base_score = 1.0
        elif connectivity <= 20:
            base_score = 0.9
        elif connectivity <= 50:
            base_score = 0.8
        elif connectivity <= 100:
            base_score = 0.7
        elif connectivity <= 200:
            base_score = 0.5
        elif connectivity <= 500:
            base_score = 0.3
        else:
            base_score = 0.1

        # Apply hash type modifier
        type_modifier = 1.0
        if hash_type:
            hash_type_upper = hash_type.upper()
            if 'HEADER' in hash_type_upper or 'BANNER' in hash_type_upper:
                type_modifier = 1.0  # Most reliable
            elif 'BODY' in hash_type_upper or 'CERT' in hash_type_upper:
                type_modifier = 0.95
            elif 'FAVICON' in hash_type_upper:
                type_modifier = 0.7  # Less reliable due to defaults
            elif 'CLASS' in hash_type_upper:
                type_modifier = 0.6
            elif 'TITLE' in hash_type_upper:
                type_modifier = 0.4  # Weak on its own

        # Self-signed cert boost
        cert_boost = 0.1 if is_self_signed_cert else 0.0

        final_score = min(1.0, (base_score * type_modifier) + cert_boost)
        return round(final_score, 2)


# =============================================================================
# Convenience Functions
# =============================================================================

_default_filter = None


def get_filter() -> NoiseFilter:
    """Get singleton NoiseFilter instance."""
    global _default_filter
    if _default_filter is None:
        _default_filter = NoiseFilter()
    return _default_filter


def is_noisy_domain(domain: str) -> bool:
    """Quick check if domain is noisy."""
    return get_filter().check_domain(domain).is_noisy


def is_noisy_ns(ns: str) -> bool:
    """Quick check if nameserver is noisy."""
    return get_filter().check_nameserver(ns).is_noisy


def is_noisy_connectivity(connectivity: int, hash_type: str = None) -> bool:
    """Quick check if connectivity is too high."""
    return get_filter().check_connectivity(connectivity, hash_type).should_exclude


# =============================================================================
# CLI for Testing
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    filter = NoiseFilter()

    print("Noise Filter Tests")
    print("=" * 50)

    # Test domains
    test_domains = [
        "evil-domain.com",
        "googleapis.com",
        "cdn.google.com",
        "fast-eda.my",
    ]
    print("\nDomain checks:")
    for domain in test_domains:
        result = filter.check_domain(domain)
        status = "NOISY" if result.is_noisy else "CLEAN"
        print(f"  {domain}: {status} - {result.reason or 'OK'}")

    # Test nameservers
    test_ns = [
        "ns1.cloudflare.com",
        "ns-123.awsdns-45.org",
        "ns1.custom-hosting.net",
        "dns1.registrar-servers.com",
    ]
    print("\nNameserver checks:")
    for ns in test_ns:
        result = filter.check_nameserver(ns)
        status = "NOISY" if result.is_noisy else "CLEAN"
        print(f"  {ns}: {status} - {result.reason or 'OK'}")

    # Test connectivity scores
    print("\nConnectivity scores:")
    for conn in [5, 20, 50, 100, 500, 1000]:
        score = filter.get_pivotability_score(conn, "HEADER_HASH")
        print(f"  {conn} connections (HEADER_HASH): {score}")

    # Test cert issuers
    print("\nCertificate issuer checks:")
    test_issuers = [
        "Let's Encrypt Authority X3",
        "DigiCert Inc",
        "Self-signed Certificate",
    ]
    for issuer in test_issuers:
        result = filter.check_cert_issuer(issuer)
        status = "NOISY" if result.is_noisy else "CLEAN"
        print(f"  {issuer}: {status}")
