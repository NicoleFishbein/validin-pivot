"""Enrichment engine for IOC data collection via Validin API."""

import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime

from models import (
    IOC, IOCType, EnrichmentResult, DNSRecord, HostFingerprint,
    CertificateInfo, RegistrationInfo, OSINTHit, NewIOC, LocationDomain,
    HashPivotData,
)
from validin_client import ValidinClient, ValidinAPIError, ValidinAuthError
from noise_filter import NoiseFilter, is_noisy_domain
from config import MAX_COTENANCY, MAX_HASH_CONNECTIVITY, PIVOT_DEPTH, CDN_IP_PREFIXES

logger = logging.getLogger(__name__)


class EnrichmentEngine:
    """
    Orchestrates API queries to enrich IOCs with infrastructure data.

    Usage:
        engine = EnrichmentEngine()
        result = engine.enrich_domain(domain_ioc)
    """

    def __init__(self, client: ValidinClient = None, noise_filter: NoiseFilter = None):
        self.client = client or ValidinClient()
        self.noise_filter = noise_filter or NoiseFilter()
        self._enriched_cache: Dict[str, EnrichmentResult] = {}

    def _is_valid_domain(self, value: str) -> bool:
        """
        Check if value is a valid domain (not an IP or hash).

        Returns False for:
        - IP addresses (e.g., 1.2.3.4)
        - Hex hashes (e.g., e4e0cbc746609fabe773)
        """
        import re

        # Check for IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return False

        # Check for hex hash (all hex chars, common hash lengths or >12 chars with no dots)
        if re.match(r'^[0-9a-fA-F]+$', value):
            if len(value) in {16, 20, 24, 32, 40, 64} or (len(value) > 12 and '.' not in value):
                return False

        # Must have at least one dot for a domain
        if '.' not in value:
            return False

        return True

    def _parse_dns_records(
        self, response: Dict[str, Any], record_types: List[str] = None
    ) -> List[DNSRecord]:
        """Parse DNS records from API response."""
        records = []
        api_records = response.get('records', {})

        for record_type, record_list in api_records.items():
            if record_types and record_type not in record_types:
                continue
            for r in record_list:
                records.append(DNSRecord(
                    key=r.get('key', ''),
                    value=r.get('value', ''),
                    value_type=r.get('value_type', ''),
                    record_type=record_type,
                    first_seen=r.get('first_seen', 0),
                    last_seen=r.get('last_seen', 0)
                ))
        return records

    def _parse_host_fingerprints(
        self, response: Dict[str, Any], host: str
    ) -> List[HostFingerprint]:
        """Parse host response fingerprints from pivots response."""
        fingerprints = []
        api_records = response.get('records', {})

        # Hash types we care about
        hash_types = [
            'HOST-HEADER_HASH', 'HOST-BANNER_0_HASH', 'HOST-BODY_SHA1',
            'HOST-CERT_SHA1', 'HOST-FAVICON_HASH', 'HOST-CLASS_0_HASH',
            'HOST-CLASS_1_HASH', 'TITLE-HOST'
        ]

        for record_type, record_list in api_records.items():
            # Normalize record type to match our hash types
            normalized_type = record_type.replace('-', '_').upper()
            if any(ht.replace('-', '_').upper() in normalized_type for ht in hash_types):
                for r in record_list:
                    fingerprints.append(HostFingerprint(
                        hash_value=r.get('value', r.get('key', '')),
                        hash_type=record_type,
                        host=host,
                        first_seen=r.get('first_seen', 0),
                        last_seen=r.get('last_seen', 0),
                        connectivity=0  # Will be populated by pivot query
                    ))
        return fingerprints

    def _parse_location_domains(
        self, response: Dict[str, Any], host: str
    ) -> List[LocationDomain]:
        """Parse HOST-LOCATION_DOMAIN records from API response."""
        locations = []
        api_records = response.get('records', {})

        for record_type, record_list in api_records.items():
            if record_type == 'HOST-LOCATION_DOMAIN':
                for r in record_list:
                    location = r.get('value', '')
                    # Skip self-redirects (domain redirecting to itself)
                    if location and location != host:
                        locations.append(LocationDomain(
                            location=location,
                            host=host,
                            first_seen=r.get('first_seen', 0),
                            last_seen=r.get('last_seen', 0),
                            connectivity=0  # Will be populated by pivot query
                        ))
        return locations

    def _parse_certificates(self, response: Dict[str, Any]) -> List[CertificateInfo]:
        """Parse certificate data from API response."""
        certs = []
        api_records = response.get('records', {})

        for record_type, record_list in api_records.items():
            if 'CERT' in record_type.upper():
                for r in record_list:
                    certs.append(CertificateInfo(
                        sha1=r.get('value', r.get('key', '')),
                        subject=r.get('subject', ''),
                        issuer=r.get('issuer', ''),
                        not_before=r.get('not_before'),
                        not_after=r.get('not_after'),
                        is_self_signed=r.get('issuer', '') == r.get('subject', ''),
                        domains=r.get('domains', [])
                    ))
        return certs

    @staticmethod
    def _parse_date_to_ts(value: Any) -> Optional[int]:
        """Coerce a registration date value to a Unix timestamp int."""
        if value is None:
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
                try:
                    return int(datetime.strptime(value, fmt).timestamp())
                except ValueError:
                    continue
        return None

    def _parse_registration(
        self, response: Dict[str, Any], domain: str
    ) -> Optional[RegistrationInfo]:
        """Parse registration data from API response."""
        api_records = response.get('records', {})

        # Look for registration/WHOIS data
        for record_type, record_list in api_records.items():
            if record_list:
                r = record_list[0]  # Take most recent
                raw_date = r.get('date') or r.get('created_date') or r.get('creation_date')
                return RegistrationInfo(
                    domain=domain,
                    registrar=r.get('registrar', ''),
                    created_date=self._parse_date_to_ts(raw_date),
                    updated_date=r.get('updated_date'),
                    expires_date=r.get('expires_date') or r.get('expiration_date'),
                    registrant_name=r.get('registrant_name', ''),
                    registrant_org=r.get('registrant_org', ''),
                    nameservers=r.get('nameservers', [])
                )
        return None

    def _parse_osint(self, response: Dict[str, Any], indicator: str) -> List[OSINTHit]:
        """Parse OSINT/threat feed data from API response."""
        hits = []
        api_records = response.get('records', {})

        for feed_name, record_list in api_records.items():
            for r in record_list:
                hits.append(OSINTHit(
                    indicator=indicator,
                    feed_name=feed_name,
                    category=r.get('category', ''),
                    first_seen=r.get('first_seen'),
                    last_seen=r.get('last_seen'),
                    tags=r.get('tags', [])
                ))
        return hits

    def enrich_domain(self, ioc: IOC, depth: int = 0) -> EnrichmentResult:
        """
        Enrich a domain IOC with all available data.

        Args:
            ioc: Domain IOC to enrich
            depth: Current pivot depth (0 = seed only)

        Returns:
            EnrichmentResult with all collected data
        """
        domain = ioc.value
        cache_key = f"domain:{domain}"

        if cache_key in self._enriched_cache:
            return self._enriched_cache[cache_key]

        logger.info(f"Enriching domain: {domain} (depth={depth})")
        result = EnrichmentResult(ioc=ioc)

        try:
            # 1. Combined connections (primary endpoint)
            logger.debug(f"  Querying combined connections for {domain}")
            combined = self.client.domain_combined_connections(domain)
            result.raw_responses['combined'] = combined

            # Parse DNS records
            result.dns_records.extend(self._parse_dns_records(combined))

            # Parse host fingerprints
            result.host_fingerprints.extend(
                self._parse_host_fingerprints(combined, domain)
            )

        except ValidinAuthError:
            raise
        except ValidinAPIError as e:
            logger.warning(f"Combined query failed for {domain}: {e}")
            result.errors.append(f"combined: {str(e)}")

        try:
            # 2. DNS History (for complete record)
            logger.debug(f"  Querying DNS history for {domain}")
            dns_history = self.client.domain_dns_history(domain)
            result.raw_responses['dns_history'] = dns_history

            # Add any records not in combined
            for record in self._parse_dns_records(dns_history):
                if record not in result.dns_records:
                    result.dns_records.append(record)

        except ValidinAuthError:
            raise
        except ValidinAPIError as e:
            logger.warning(f"DNS history query failed for {domain}: {e}")
            result.errors.append(f"dns_history: {str(e)}")

        try:
            # 3. Host response pivots
            logger.debug(f"  Querying pivots for {domain}")
            pivots = self.client.domain_pivots(domain)
            result.raw_responses['pivots'] = pivots

            # Parse additional fingerprints
            for fp in self._parse_host_fingerprints(pivots, domain):
                if fp.hash_value not in [f.hash_value for f in result.host_fingerprints]:
                    result.host_fingerprints.append(fp)

            # Parse location domains (redirect targets)
            for ld in self._parse_location_domains(pivots, domain):
                if ld.location not in [l.location for l in result.location_domains]:
                    result.location_domains.append(ld)

        except ValidinAuthError:
            raise
        except ValidinAPIError as e:
            logger.warning(f"Pivots query failed for {domain}: {e}")
            result.errors.append(f"pivots: {str(e)}")

        try:
            # 4. Registration history
            logger.debug(f"  Querying registration history for {domain}")
            registration = self.client.domain_registration_history(domain)
            result.raw_responses['registration'] = registration
            result.registration = self._parse_registration(registration, domain)

        except ValidinAuthError:
            raise
        except ValidinAPIError as e:
            logger.warning(f"Registration query failed for {domain}: {e}")
            result.errors.append(f"registration: {str(e)}")

        try:
            # 5. Certificates
            logger.debug(f"  Querying certificates for {domain}")
            certs = self.client.domain_certificates(domain)
            result.raw_responses['certificates'] = certs
            result.certificates.extend(self._parse_certificates(certs))

        except ValidinAuthError:
            raise
        except ValidinAPIError as e:
            logger.warning(f"Certificates query failed for {domain}: {e}")
            result.errors.append(f"certificates: {str(e)}")

        try:
            # 6. OSINT
            logger.debug(f"  Querying OSINT for {domain}")
            osint = self.client.domain_osint_history(domain)
            result.raw_responses['osint'] = osint
            result.osint_hits.extend(self._parse_osint(osint, domain))

        except ValidinAuthError:
            raise
        except ValidinAPIError as e:
            logger.warning(f"OSINT query failed for {domain}: {e}")
            result.errors.append(f"osint: {str(e)}")

        # 7. Subdomains - only query for actual domains (not IPs or hashes)
        if self._is_valid_domain(domain):
            try:
                logger.debug(f"  Querying subdomains for {domain}")
                subdomains = self.client.domain_subdomains(domain)
                result.raw_responses['subdomains'] = subdomains

                for record_type, records in subdomains.get('records', {}).items():
                    for r in records:
                        subdomain = r.get('key', r.get('value', ''))
                        if subdomain and subdomain not in result.subdomains:
                            result.subdomains.append(subdomain)

            except ValidinAuthError:
                raise
            except ValidinAPIError as e:
                logger.warning(f"Subdomains query failed for {domain}: {e}")
                result.errors.append(f"subdomains: {str(e)}")
        else:
            logger.debug(f"  Skipping subdomains query - {domain} is not a valid domain")

        self._enriched_cache[cache_key] = result
        logger.info(
            f"  Enriched {domain}: {len(result.dns_records)} DNS records, "
            f"{len(result.host_fingerprints)} fingerprints, "
            f"{len(result.certificates)} certs"
        )

        return result

    def enrich_ip(self, ioc: IOC, depth: int = 0) -> EnrichmentResult:
        """
        Enrich an IP IOC with all available data.

        Args:
            ioc: IP IOC to enrich
            depth: Current pivot depth

        Returns:
            EnrichmentResult with all collected data
        """
        ip = ioc.value
        cache_key = f"ip:{ip}"

        if cache_key in self._enriched_cache:
            return self._enriched_cache[cache_key]

        logger.info(f"Enriching IP: {ip} (depth={depth})")
        result = EnrichmentResult(ioc=ioc)

        try:
            # 1. Reverse DNS (domains on this IP)
            logger.debug(f"  Querying DNS history for {ip}")
            dns_history = self.client.ip_dns_history(ip)
            result.raw_responses['dns_history'] = dns_history
            result.dns_records.extend(self._parse_dns_records(dns_history))

        except ValidinAuthError:
            raise
        except ValidinAPIError as e:
            logger.warning(f"DNS history query failed for {ip}: {e}")
            result.errors.append(f"dns_history: {str(e)}")

        try:
            # 2. Host response pivots
            logger.debug(f"  Querying pivots for {ip}")
            pivots = self.client.ip_pivots(ip)
            result.raw_responses['pivots'] = pivots
            result.host_fingerprints.extend(self._parse_host_fingerprints(pivots, ip))

        except ValidinAuthError:
            raise
        except ValidinAPIError as e:
            logger.warning(f"Pivots query failed for {ip}: {e}")
            result.errors.append(f"pivots: {str(e)}")

        try:
            # 3. OSINT
            logger.debug(f"  Querying OSINT for {ip}")
            osint = self.client.ip_osint_history(ip)
            result.raw_responses['osint'] = osint
            result.osint_hits.extend(self._parse_osint(osint, ip))

        except ValidinAuthError:
            raise
        except ValidinAPIError as e:
            logger.warning(f"OSINT query failed for {ip}: {e}")
            result.errors.append(f"osint: {str(e)}")

        self._enriched_cache[cache_key] = result
        logger.info(
            f"  Enriched {ip}: {len(result.dns_records)} DNS records, "
            f"{len(result.host_fingerprints)} fingerprints"
        )

        return result

    @staticmethod
    def _is_cdn_ip(ip: str) -> bool:
        """Heuristic CDN IP check via known prefix ranges (non-exhaustive)."""
        return any(ip.startswith(p) for p in CDN_IP_PREFIXES)

    def get_hash_pivot_data(self, hash_value: str) -> HashPivotData:
        """
        Full hash pivot: domains, per-host timestamps, and non-CDN IP observations.

        Returns a HashPivotData with:
          - hosts: domains that share this hash
          - host_timestamps: {domain -> (first_seen, last_seen)} from the pivot record
          - backend_ips: IPs with this hash that are NOT in CDN_IP_PREFIXES
          - ip_timestamps: {ip -> (first_seen, last_seen)} for backend_ips only
        """
        try:
            pivots = self.client.hash_pivots(hash_value)
            hosts: List[str] = []
            host_ts: Dict[str, Tuple[int, int]] = {}
            backend_ips: List[str] = []
            ip_ts: Dict[str, Tuple[int, int]] = {}

            for record_type, records in pivots.get('records', {}).items():
                is_host = record_type.endswith('-HOST')
                is_ip = record_type.endswith('-IP')
                for r in records:
                    val = r.get('value', '')
                    if not val:
                        continue
                    fs = r.get('first_seen', 0)
                    ls = r.get('last_seen', 0)
                    if is_host and val not in hosts:
                        hosts.append(val)
                        host_ts[val] = (fs, ls)
                    elif is_ip and val not in backend_ips and not self._is_cdn_ip(val):
                        backend_ips.append(val)
                        ip_ts[val] = (fs, ls)

            return HashPivotData(
                connectivity=len(hosts),
                hosts=hosts,
                host_timestamps=host_ts,
                backend_ips=backend_ips,
                ip_timestamps=ip_ts,
            )
        except ValidinAuthError:
            raise
        except ValidinAPIError as e:
            logger.warning(f"Hash pivots query failed for {hash_value}: {e}")
            return HashPivotData(0, [], {}, [], {})

    def get_hash_connectivity(self, hash_value: str) -> Tuple[int, List[str]]:
        """Thin wrapper — returns (connectivity, hosts) without timestamp data."""
        data = self.get_hash_pivot_data(hash_value)
        return data.connectivity, data.hosts

    def get_ip_cotenancy(self, ip: str) -> Tuple[int, List[str]]:
        """
        Get co-tenancy count and domains for an IP.

        Returns:
            Tuple of (domain_count, list_of_domains)
        """
        try:
            dns_history = self.client.ip_dns_history(ip)
            domains = []
            for record_type, records in dns_history.get('records', {}).items():
                for r in records:
                    domain = r.get('key', r.get('value', ''))
                    if domain and domain not in domains and not is_noisy_domain(domain):
                        domains.append(domain)
            return len(domains), domains
        except ValidinAuthError:
            raise
        except ValidinAPIError as e:
            logger.warning(f"IP DNS history query failed for {ip}: {e}")
            return 0, []

    def get_location_domain_connectivity(
        self, location_domain: str
    ) -> Tuple[int, List[str]]:
        """
        Get connectivity count and hosts that redirect to a location domain.

        Queries domain_pivots on the location domain itself and reads the
        LOCATION_DOMAIN-HOST records, which list every host that redirects
        to this domain. This is the correct pivot direction: we want
        "who else redirects to timesync.io?", not string search results.

        Args:
            location_domain: The domain being redirected to (e.g., timesync.io)

        Returns:
            Tuple of (host_count, list_of_hosts_redirecting_to_location)
        """
        try:
            pivots = self.client.domain_pivots(location_domain, limit=1000)
            hosts = []
            for record_type, records in pivots.get('records', {}).items():
                # LOCATION_DOMAIN-HOST: hosts that redirect to this location domain
                if record_type == 'LOCATION_DOMAIN-HOST':
                    for r in records:
                        host = r.get('value', r.get('key', ''))
                        if host and host != location_domain and host not in hosts:
                            if self._is_valid_domain(host):
                                hosts.append(host)
            return len(hosts), hosts
        except ValidinAuthError:
            raise
        except ValidinAPIError as e:
            logger.warning(
                f"Location domain pivots query failed for {location_domain}: {e}"
            )
            return 0, []

    def pivot_from_ip(
        self, ip: str, source_ioc: IOC, depth: int
    ) -> List[Tuple[IOC, Dict[str, Any]]]:
        """
        Pivot from an IP to discover new domain IOCs.

        Args:
            ip: IP address to pivot from
            source_ioc: The IOC that led us to this IP
            depth: Current pivot depth

        Returns:
            List of (new_ioc, evidence) tuples
        """
        if depth >= PIVOT_DEPTH:
            return []

        cotenancy, domains = self.get_ip_cotenancy(ip)
        logger.info(f"IP {ip} has {cotenancy} co-tenants")

        # Only pivot if co-tenancy is reasonable
        if cotenancy > MAX_COTENANCY * 2:  # Allow some flexibility
            logger.info(f"  Skipping pivot - too many co-tenants ({cotenancy})")
            return []

        new_iocs = []
        for domain in domains[:50]:  # Limit to prevent explosion
            if domain == source_ioc.value:
                continue

            new_ioc = IOC(
                value=domain,
                ioc_type=IOCType.DOMAIN,
                is_seed=False,
                discovered_via="shared_ip_pivot",
                connected_to_seed=source_ioc.value
            )
            evidence = {
                "shared_ip": ip,
                "cotenancy": cotenancy,
                "source_domain": source_ioc.value
            }
            new_iocs.append((new_ioc, evidence))

        return new_iocs

    def pivot_from_hash(
        self, hash_value: str, hash_type: str, source_ioc: IOC, depth: int
    ) -> List[Tuple[IOC, Dict[str, Any]]]:
        """
        Pivot from a hash to discover new IOCs.

        Args:
            hash_value: Hash to pivot from
            hash_type: Type of hash
            source_ioc: The IOC that led us to this hash
            depth: Current pivot depth

        Returns:
            List of (new_ioc, evidence) tuples
        """
        if depth >= PIVOT_DEPTH:
            return []

        connectivity, hosts = self.get_hash_connectivity(hash_value)
        logger.info(f"Hash {hash_value[:16]}... ({hash_type}) has {connectivity} connections")

        # Only pivot if connectivity is reasonable
        if connectivity > MAX_HASH_CONNECTIVITY * 2:
            logger.info(f"  Skipping pivot - too many connections ({connectivity})")
            return []

        new_iocs = []
        for host in hosts[:50]:
            if host == source_ioc.value:
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
                discovered_via=f"hash_pivot:{hash_type}",
                connected_to_seed=source_ioc.value
            )
            evidence = {
                "shared_hash": hash_value,
                "hash_type": hash_type,
                "connectivity": connectivity,
                "source": source_ioc.value
            }
            new_iocs.append((new_ioc, evidence))

        return new_iocs

    def _looks_like_ip(self, value: str) -> bool:
        """Quick check if value looks like an IP address."""
        parts = value.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def enrich_ioc(self, ioc: IOC, depth: int = 0) -> EnrichmentResult:
        """
        Enrich any IOC type.

        Args:
            ioc: IOC to enrich
            depth: Current pivot depth

        Returns:
            EnrichmentResult
        """
        if ioc.ioc_type == IOCType.DOMAIN:
            return self.enrich_domain(ioc, depth)
        elif ioc.ioc_type in [IOCType.IPV4, IOCType.IPV6]:
            return self.enrich_ip(ioc, depth)
        else:
            # For hashes/URLs/emails, create minimal result
            logger.info(f"Minimal enrichment for {ioc.ioc_type.value}: {ioc.value}")
            return EnrichmentResult(ioc=ioc)

    def check_threat_intel(self, threat_name: str) -> Dict[str, Any]:
        """
        Check Validin's built-in threat intelligence for a threat group.

        Args:
            threat_name: Name of threat group (e.g., "APT28", "Lazarus")

        Returns:
            Dict with summary, indicators, and reports
        """
        result = {
            "name": threat_name,
            "found": False,
            "summary": None,
            "indicators": [],
            "reports": []
        }

        try:
            # Check if threat exists
            summary = self.client.threat_group_summary(threat_name)
            if summary.get('status') != 'not_found':
                result['found'] = True
                result['summary'] = summary

                # Get indicators
                indicators = self.client.threat_group_indicators(threat_name)
                result['indicators'] = indicators.get('records', {})

                # Get reports
                reports = self.client.threat_group_reports(threat_name)
                result['reports'] = reports.get('records', {})

        except ValidinAuthError:
            raise
        except ValidinAPIError as e:
            logger.warning(f"Threat intel query failed for {threat_name}: {e}")

        return result


# =============================================================================
# CLI for Testing
# =============================================================================

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    from config import VALIDIN_API_KEY

    if not VALIDIN_API_KEY:
        print("ERROR: VALIDIN_API_KEY environment variable not set")
        sys.exit(1)

    engine = EnrichmentEngine()

    test_domain = "example.com"
    print(f"Testing enrichment for: {test_domain}")
    print("=" * 60)

    ioc = IOC(value=test_domain, ioc_type=IOCType.DOMAIN, is_seed=True)
    result = engine.enrich_ioc(ioc)

    print(f"\nDNS Records: {len(result.dns_records)}")
    for record in result.dns_records[:5]:
        print(f"  {record.record_type}: {record.value} "
              f"(seen: {record.first_seen_dt.date()} - {record.last_seen_dt.date()})")

    print(f"\nHost Fingerprints: {len(result.host_fingerprints)}")
    for fp in result.host_fingerprints[:5]:
        print(f"  {fp.hash_type}: {fp.hash_value[:32]}...")

    print(f"\nCertificates: {len(result.certificates)}")
    for cert in result.certificates[:3]:
        print(f"  {cert.sha1[:16]}... (self-signed: {cert.is_self_signed})")

    if result.registration:
        print(f"\nRegistration:")
        print(f"  Registrar: {result.registration.registrar}")
        print(f"  Nameservers: {result.registration.nameservers}")

    print(f"\nOSINT Hits: {len(result.osint_hits)}")
    for hit in result.osint_hits[:3]:
        print(f"  {hit.feed_name}: {hit.category}")

    print(f"\nSubdomains: {len(result.subdomains)}")
    for sub in result.subdomains[:5]:
        print(f"  {sub}")

    if result.errors:
        print(f"\nErrors encountered: {len(result.errors)}")
        for err in result.errors:
            print(f"  {err}")

    # Test threat intel
    print("\n" + "=" * 60)
    print("Testing threat intelligence lookup...")
    test_threat = "APT28"
    intel = engine.check_threat_intel(test_threat)
    if intel['found']:
        print(f"  {test_threat}: FOUND")
    else:
        print(f"  {test_threat}: Not found in Validin threat intel")
