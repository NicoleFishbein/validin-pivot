"""Validin API client with rate limiting, caching, and error handling."""

import json
import hashlib
import logging
import time
from pathlib import Path
from typing import Optional, Dict, Any, List
from urllib.parse import quote

import requests

from config import (
    VALIDIN_API_KEY, VALIDIN_BASE_URL, RATE_LIMIT_RPS,
    REQUEST_TIMEOUT, MAX_RETRIES, RETRY_BACKOFF_BASE,
    CACHE_DIR, LOG_API_CALLS
)

logger = logging.getLogger(__name__)


class ValidinAPIError(Exception):
    """Base exception for Validin API errors."""
    def __init__(self, message: str, status_code: int = None, response: dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class ValidinRateLimitError(ValidinAPIError):
    """Rate limit exceeded."""
    pass


class ValidinAuthError(ValidinAPIError):
    """Authentication error."""
    pass


class ValidinClient:
    """
    Validin API client with rate limiting, caching, and retry logic.

    Usage:
        client = ValidinClient()
        result = client.domain_dns_history("example.com")
    """

    def __init__(
        self,
        api_key: str = None,
        base_url: str = None,
        rate_limit_rps: float = None,
        use_cache: bool = True,
        cache_dir: Path = None
    ):
        self.api_key = api_key or VALIDIN_API_KEY
        self.base_url = (base_url or VALIDIN_BASE_URL).rstrip('/')
        self.rate_limit_rps = rate_limit_rps or RATE_LIMIT_RPS
        self.use_cache = use_cache
        self.cache_dir = cache_dir or CACHE_DIR

        self._last_request_time = 0.0
        self._request_count = 0

        if not self.api_key:
            logger.warning("No API key provided. Set VALIDIN_API_KEY environment variable.")

        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'BEARER {self.api_key}',
            'Accept': 'application/json',
            'User-Agent': 'ValidinInfraHunter/1.0'
        })

    def _get_cache_key(self, endpoint: str, params: Dict[str, Any] = None) -> str:
        """Generate cache key from endpoint and params."""
        key_data = f"{endpoint}:{json.dumps(params or {}, sort_keys=True)}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]

    def _get_cached(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached response if available."""
        if not self.use_cache:
            return None
        cache_path = self.cache_dir / f"{cache_key}.json"
        if cache_path.exists():
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return None
        return None

    def _save_cache(self, cache_key: str, data: Dict[str, Any]):
        """Save response to cache."""
        if not self.use_cache:
            return
        cache_path = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(data, f)
        except IOError as e:
            logger.warning(f"Failed to cache response: {e}")

    def _rate_limit(self):
        """Enforce rate limiting."""
        if self.rate_limit_rps <= 0:
            return
        min_interval = 1.0 / self.rate_limit_rps
        elapsed = time.time() - self._last_request_time
        if elapsed < min_interval:
            sleep_time = min_interval - elapsed
            time.sleep(sleep_time)
        self._last_request_time = time.time()

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Dict[str, Any] = None,
        data: Dict[str, Any] = None,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Make API request with rate limiting, caching, and retry logic.

        Args:
            method: HTTP method (GET, POST)
            endpoint: API endpoint path
            params: Query parameters
            data: POST body data
            use_cache: Whether to use cache for this request

        Returns:
            API response as dictionary

        Raises:
            ValidinAPIError: On API errors
        """
        # Check cache for GET requests
        if method == 'GET' and use_cache and self.use_cache:
            cache_key = self._get_cache_key(endpoint, params)
            cached = self._get_cached(cache_key)
            if cached is not None:
                if LOG_API_CALLS:
                    logger.debug(f"Cache hit: {endpoint}")
                return cached

        url = f"{self.base_url}{endpoint}"

        for attempt in range(MAX_RETRIES):
            self._rate_limit()
            self._request_count += 1

            try:
                if LOG_API_CALLS:
                    logger.debug(f"API request #{self._request_count}: {method} {url} params={params}")

                if method == 'GET':
                    response = self.session.get(
                        url, params=params, timeout=REQUEST_TIMEOUT
                    )
                elif method == 'POST':
                    response = self.session.post(
                        url, params=params, json=data, timeout=REQUEST_TIMEOUT
                    )
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")

                # Handle response codes
                if response.status_code == 200:
                    result = response.json()
                    # Cache successful GET responses
                    if method == 'GET' and use_cache and self.use_cache:
                        self._save_cache(cache_key, result)
                    return result

                elif response.status_code == 401:
                    logger.debug(f"AUTH FAILED (401): {method} {url} params={params}")
                    raise ValidinAuthError(
                        f"Authentication failed. Check your API key. Query: {method} {endpoint} params={params}",
                        status_code=401
                    )

                elif response.status_code == 403:
                    logger.debug(f"FORBIDDEN (403): {method} {url} params={params}")
                    raise ValidinAuthError(
                        f"Access forbidden. Insufficient permissions. Query: {method} {endpoint} params={params}",
                        status_code=403
                    )

                elif response.status_code == 404:
                    # Not found is normal for IOCs with no data
                    if LOG_API_CALLS:
                        logger.debug(f"No data found for {endpoint}")
                    return {"status": "not_found", "records": {}}

                elif response.status_code == 429:
                    # Rate limited - back off and retry
                    backoff = RETRY_BACKOFF_BASE ** attempt
                    logger.warning(f"Rate limited. Backing off {backoff}s (attempt {attempt + 1})")
                    time.sleep(backoff)
                    continue

                elif response.status_code >= 500:
                    # Server error - retry with backoff
                    backoff = RETRY_BACKOFF_BASE ** attempt
                    logger.warning(
                        f"Server error {response.status_code}. "
                        f"Backing off {backoff}s (attempt {attempt + 1})"
                    )
                    time.sleep(backoff)
                    continue

                else:
                    raise ValidinAPIError(
                        f"API error: {response.status_code}",
                        status_code=response.status_code,
                        response=response.text
                    )

            except requests.RequestException as e:
                if attempt < MAX_RETRIES - 1:
                    backoff = RETRY_BACKOFF_BASE ** attempt
                    logger.warning(f"Request failed: {e}. Retrying in {backoff}s")
                    time.sleep(backoff)
                    continue
                raise ValidinAPIError(f"Request failed after {MAX_RETRIES} attempts: {e}")

        raise ValidinAPIError(f"Max retries exceeded for {endpoint}")

    # =========================================================================
    # Domain Endpoints
    # =========================================================================

    def domain_combined_connections(
        self, domain: str, limit: int = 1000, **kwargs
    ) -> Dict[str, Any]:
        """
        V2 Domain Combined Connections - PRIMARY endpoint for domain enrichment.
        Returns combined DNS + host response connections in one call.
        """
        endpoint = f"/v2/domain/combined/connections/{quote(domain, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    def domain_dns_history(
        self, domain: str, record_type: str = None, limit: int = 1000, **kwargs
    ) -> Dict[str, Any]:
        """Get DNS history for domain. Optionally filter by record type (A, AAAA, NS, NS_FOR)."""
        if record_type:
            endpoint = f"/axon/domain/dns/history/{quote(domain, safe='')}/{record_type}"
        else:
            endpoint = f"/axon/domain/dns/history/{quote(domain, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    def domain_pivots(
        self, domain: str, category: str = None, limit: int = 1000, **kwargs
    ) -> Dict[str, Any]:
        """Get host response pivots for domain. Optionally filter by category."""
        if category:
            endpoint = f"/axon/domain/pivots/{quote(domain, safe='')}/{category}"
        else:
            endpoint = f"/axon/domain/pivots/{quote(domain, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    def domain_registration_history(self, domain: str, **kwargs) -> Dict[str, Any]:
        """Get WHOIS/RDAP registration history."""
        endpoint = f"/axon/domain/registration/history/{quote(domain, safe='')}"
        return self._request('GET', endpoint, params=kwargs)

    def domain_certificates(self, domain: str, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """Get certificate transparency data."""
        endpoint = f"/axon/domain/certificates/{quote(domain, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    def domain_osint_history(self, domain: str, **kwargs) -> Dict[str, Any]:
        """Get OSINT/threat feed appearances."""
        endpoint = f"/axon/domain/osint/history/{quote(domain, safe='')}"
        return self._request('GET', endpoint, params=kwargs)

    def domain_subdomains(self, domain: str, limit: int = 1000, **kwargs) -> Dict[str, Any]:
        """Get known subdomains."""
        endpoint = f"/axon/domain/subdomains/{quote(domain, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    def domain_crawl_history(self, domain: str, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """Get HTTP/S crawl response data."""
        endpoint = f"/axon/domain/crawl/history/{quote(domain, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    def domain_reputation_quick(self, domain: str) -> Dict[str, Any]:
        """Get quick reputation check."""
        endpoint = f"/axon/domain/reputation/quick/{quote(domain, safe='')}"
        return self._request('GET', endpoint)

    def domain_lookalike(self, domain: str, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """Get typosquatting/lookalike domains."""
        endpoint = f"/axon/domain/lookalike/{quote(domain, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    # =========================================================================
    # IP Endpoints
    # =========================================================================

    def ip_dns_history(
        self, ip: str, cidr: int = None, limit: int = 1000, **kwargs
    ) -> Dict[str, Any]:
        """Get all domains that resolved to this IP (reverse DNS)."""
        if cidr:
            endpoint = f"/axon/ip/dns/history/{quote(ip, safe='')}/{cidr}"
        else:
            endpoint = f"/axon/ip/dns/history/{quote(ip, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    def ip_pivots(
        self, ip: str, category: str = None, limit: int = 1000, **kwargs
    ) -> Dict[str, Any]:
        """Get host response pivots for IP."""
        if category:
            endpoint = f"/axon/ip/pivots/{quote(ip, safe='')}/{category}"
        else:
            endpoint = f"/axon/ip/pivots/{quote(ip, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    def ip_osint_history(self, ip: str, **kwargs) -> Dict[str, Any]:
        """Get OSINT/threat feed appearances for IP."""
        endpoint = f"/axon/ip/osint/history/{quote(ip, safe='')}"
        return self._request('GET', endpoint, params=kwargs)

    def ip_crawl_history(self, ip: str, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """Get HTTP/S crawl response data for IP."""
        endpoint = f"/axon/ip/crawl/history/{quote(ip, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    def ip_reputation_quick(self, ip: str) -> Dict[str, Any]:
        """Get quick reputation check for IP."""
        endpoint = f"/axon/ip/reputation/quick/{quote(ip, safe='')}"
        return self._request('GET', endpoint)

    # =========================================================================
    # Hash Endpoints (Host Response Hashes)
    # =========================================================================

    def hash_pivots(
        self, hash_value: str, category: str = None, limit: int = 1000, **kwargs
    ) -> Dict[str, Any]:
        """
        Get all domains/IPs sharing a hash.
        CRITICAL for infrastructure pivoting.
        """
        if category:
            endpoint = f"/axon/hash/pivots/{quote(hash_value, safe='')}/{category}"
        else:
            endpoint = f"/axon/hash/pivots/{quote(hash_value, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    def hash_crawl_history(self, hash_value: str, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """Get crawl data associated with a hash."""
        endpoint = f"/axon/hash/crawl/history/{quote(hash_value, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    def hash_content_html_sha1(self, hash_value: str) -> Dict[str, Any]:
        """Retrieve actual HTML content for a body hash."""
        endpoint = f"/axon/hash/content/html/sha1/{quote(hash_value, safe='')}"
        return self._request('GET', endpoint)

    def hash_content_favicon_md5(self, hash_value: str) -> Dict[str, Any]:
        """Retrieve actual favicon content."""
        endpoint = f"/axon/hash/content/favicon/md5/{quote(hash_value, safe='')}"
        return self._request('GET', endpoint)

    def hash_content_certificate_sha1(self, hash_value: str) -> Dict[str, Any]:
        """Retrieve certificate content."""
        endpoint = f"/axon/hash/content/certificate/sha1/{quote(hash_value, safe='')}"
        return self._request('GET', endpoint)

    # =========================================================================
    # String Endpoints
    # =========================================================================

    def string_pivots(self, search_string: str, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """Pivot from a string (e.g., registrant name)."""
        endpoint = f"/axon/string/pivots/v2/{quote(search_string, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    def string_registration_history(
        self, search_string: str, limit: int = 100, **kwargs
    ) -> Dict[str, Any]:
        """Get registration records matching string."""
        endpoint = f"/axon/string/registration/history/v2/{quote(search_string, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    # =========================================================================
    # Threat Intelligence Endpoints
    # =========================================================================

    def threat_names(self) -> Dict[str, Any]:
        """List known threat groups."""
        return self._request('GET', "/axon/threat/names")

    def threat_group_summary(self, name: str) -> Dict[str, Any]:
        """Get summary for a named threat group."""
        endpoint = f"/axon/threat/group/summary/{quote(name, safe='')}"
        return self._request('GET', endpoint)

    def threat_group_indicators(self, name: str, limit: int = 1000, **kwargs) -> Dict[str, Any]:
        """Get indicators associated with a threat group."""
        endpoint = f"/axon/threat/group/indicators/{quote(name, safe='')}"
        params = {"limit": limit, **kwargs}
        return self._request('GET', endpoint, params=params)

    def threat_group_reports(self, name: str, **kwargs) -> Dict[str, Any]:
        """Get reports associated with a threat group."""
        endpoint = f"/axon/threat/group/reports/{quote(name, safe='')}"
        return self._request('GET', endpoint, params=kwargs)

    # =========================================================================
    # Bulk Endpoints
    # =========================================================================

    def bulk_osint_context(self, indicators: List[str]) -> Dict[str, Any]:
        """Bulk query OSINT for multiple indicators."""
        endpoint = "/axon/bulk/osint/context"
        return self._request('POST', endpoint, data={"indicators": indicators})

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def test_connection(self) -> bool:
        """Test API connection and authentication."""
        try:
            # Use a simple domain lookup as connection test
            result = self.domain_dns_history("google.com")
            # Success if we got a valid response structure
            return result.get('status') in ('finished', 'not_found') or 'records' in result
        except ValidinAuthError:
            return False
        except ValidinAPIError as e:
            logger.error(f"Connection test failed: {e}")
            return False

    def get_request_count(self) -> int:
        """Return total number of API requests made."""
        return self._request_count

    def clear_cache(self):
        """Clear all cached responses."""
        for cache_file in self.cache_dir.glob('*.json'):
            cache_file.unlink()
        logger.info("Cache cleared")


# =============================================================================
# CLI for Testing
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    client = ValidinClient()

    print("Testing Validin API connection...")
    print("=" * 50)

    if not VALIDIN_API_KEY:
        print("ERROR: VALIDIN_API_KEY environment variable not set")
        exit(1)

    if client.test_connection():
        print("Connection successful!")
    else:
        print("Connection failed!")
        exit(1)

    # Test with a domain
    test_domain = "example.com"
    print(f"\nTesting domain query: {test_domain}")
    print("-" * 50)

    try:
        result = client.domain_combined_connections(test_domain, limit=10)
        print(f"Status: {result.get('status', 'unknown')}")
        print(f"Records returned: {result.get('records_returned', 0)}")
        if result.get('records'):
            for record_type, records in result['records'].items():
                print(f"  {record_type}: {len(records)} records")
    except ValidinAPIError as e:
        print(f"Query failed: {e}")

    print(f"\nTotal API requests: {client.get_request_count()}")
