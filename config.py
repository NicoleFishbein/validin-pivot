"""Configuration for Validin Infrastructure Hunter."""

import os
from pathlib import Path

# =============================================================================
# API Configuration
# =============================================================================

VALIDIN_API_KEY = os.environ.get("VALIDIN_API_KEY", "")
VALIDIN_BASE_URL = "https://pilot.validin.com/api"

# Rate limiting: requests per second
RATE_LIMIT_RPS = 2
REQUEST_TIMEOUT = 30  # seconds

# Retry configuration
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # Exponential backoff base (2^attempt seconds)

# =============================================================================
# Connection Thresholds
# =============================================================================

# Tier 1: Strong connections
MAX_COTENANCY = 25              # Max domains on shared IP for Tier 1 score
MAX_HASH_CONNECTIVITY = 100     # Max hash connections for Tier 1 score

# Tier 2: Moderate connections
REG_WINDOW_DAYS = 7             # Registration date proximity for Tier 2

# Hash connectivity thresholds for scoring
HASH_CONNECTIVITY_THRESHOLDS = {
    "very_low": 20,     # Score 1.0
    "low": 50,          # Score 0.9
    "moderate": 100,    # Score 0.7
    "high": 500,        # Score 0.5
    "very_high": 1000,  # Score 0.3
}

# Hash type reliability weights (higher = more reliable)
HASH_TYPE_WEIGHTS = {
    "HOST-HEADER_HASH": 1.0,
    "HOST-BANNER_0_HASH": 1.0,
    "HOST-BODY_SHA1": 0.9,
    "HOST-CERT_SHA1": 0.9,
    "HOST-FAVICON_HASH": 0.6,
    "HOST-CLASS_0_HASH": 0.9,
    "HOST-CLASS_1_HASH": 0.9,
    "TITLE-HOST": 0.3,
}

# Hash pivot query limits
MIN_HASH_WEIGHT = 0.8  # Only query hashes with weight >= this value
MAX_HASH_QUERIES_PER_IOC = 10  # Max hash pivot queries per IOC (pairwise analysis)

# Multi-indicator pivot analysis limits (find_multi_indicator_matches)
# We group fingerprints by hash type and query each type independently so that
# no single verbose type (e.g. 37 BODY_SHA1 records) starves the others.
MULTI_INDICATOR_MAX_PER_HASH_TYPE = 25  # Max queries per hash type (e.g. all 22 banner hashes)
MULTI_INDICATOR_MAX_HASH_QUERIES = 150  # Global safety cap across all types
MULTI_INDICATOR_MAX_CONNECTIVITY = 200  # Skip indicators shared by more than this many hosts

# Co-deployment detection: flag when two hosts first seen with same hash within this window
HASH_COLOCAL_WINDOW_HOURS = 48
# Co-deployment detection: flag when the same IP first appeared on two seeds within this window
IP_COLOCAL_WINDOW_HOURS = 48

# Heuristic CDN IP prefix set for backend-IP detection (non-exhaustive, covers major CDNs)
CDN_IP_PREFIXES: frozenset = frozenset([
    # Cloudflare
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71.",
    "162.158.", "162.159.", "190.93.", "188.114.", "198.41.", "197.234.",
    # Akamai
    "23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.", "23.38.", "23.39.",
    "23.40.", "23.41.", "23.42.", "23.43.", "23.44.", "23.45.", "23.46.", "23.47.",
    "104.64.", "104.65.", "104.66.", "104.67.", "104.68.", "104.69.", "104.70.", "104.71.",
    # Fastly
    "151.101.", "199.27.", "199.232.",
    # AWS CloudFront
    "54.182.", "54.192.", "54.230.", "54.239.", "52.84.", "52.85.",
    # Google
    "74.125.", "172.217.", "216.58.", "142.250.",
])

# Location domain pivot settings
ENABLE_LOCATION_DOMAIN_PIVOTS = True  # Enable pivoting on redirect targets
MAX_LOCATION_DOMAIN_CONNECTIVITY = 500  # Skip if location has more than this many redirects
LOCATION_DOMAIN_WEIGHT = 0.9  # Weight for location domain pivot scoring

# Certificate issuer categories
COMMON_CERT_ISSUERS = [
    "Let's Encrypt",
    "DigiCert",
    "Comodo",
    "GoDaddy",
    "GlobalSign",
    "Sectigo",
]

# =============================================================================
# Pivot Configuration
# =============================================================================

PIVOT_DEPTH = 1                 # Default pivot depth (0=enrich only, 1=one hop, 2=two hops)
MAX_PIVOT_RESULTS = 1000        # Max results to process per pivot query

# =============================================================================
# Corpus Mode Configuration
# =============================================================================
# Corpus mode takes a SET of seeds known to belong to one operation, finds
# parameters shared across >=N of them ("CorpusSignature"), then expands by
# querying pivot endpoints for each signature. IOCs matching >=M signatures
# are promoted to Tier 1 regardless of individual per-signature score.

CORPUS_MIN_COVERAGE = 2                 # Min seeds that must share a param for it to be a signature
CORPUS_MIN_SIGS_FOR_PROMOTION = 2       # Discovered IOC matching this many sigs -> promoted
CORPUS_MAX_PIVOTS_PER_SIG = 50          # Max hosts pulled per signature expansion
CORPUS_SIG_MIN_SIGNAL = 0.05            # Minimum signal_score (coverage*rarity) to expand
CORPUS_PROMOTION_CONFIDENCE = 0.9       # Confidence floor for promoted IOCs
CORPUS_MAX_SIGNATURES_TO_EXPAND = 30    # Cap total pivot queries across the corpus
# Which param types count as "hash-backed" (use hash_pivots). Others use string_pivots.
CORPUS_HASH_PARAM_TYPES = {
    "header_hash", "banner_hash", "body_hash", "cert_sha1",
    "favicon_hash", "class_hash", "title_hash",
}

# =============================================================================
# Noise Filter - NS Patterns (regex)
# =============================================================================

NOISY_NS_PATTERNS = [
    r"ns\d*\.cloudflare\.com",
    r"ns-\d+\.awsdns-\d+\.\w+",
    r"ns\d*\.domaincontrol\.com",
    r"ns-cloud-\w+\.google\.com",
    r"dns\d*\.registrar-servers\.com",
    r"ns\d*\.hichina\.com",
    r"ns\d*\.dnspod\.net",
    r"ns\d*\.dnsv\d*\.com",
    r"pdns\d*\.ultradns\.\w+",
    r"ns\d*\.p\d+\.dynect\.net",
]

# =============================================================================
# Noise Filter - CDN/Cloud ASNs
# =============================================================================

NOISY_ASNS = {
    13335: "Cloudflare",
    16509: "Amazon (AWS)",
    14618: "Amazon (AWS)",
    20940: "Akamai",
    54113: "Fastly",
    15169: "Google",
    8075: "Microsoft Azure",
    # Note: DigitalOcean (14061) is flagged but not auto-excluded
}

# ASNs that are flagged but not auto-excluded (commonly used by actors)
FLAGGED_ASNS = {
    14061: "DigitalOcean",
    16276: "OVH",
    24940: "Hetzner",
    197540: "Netcup",
}

# =============================================================================
# Noise Filter - Excluded Domains
# =============================================================================

# Domains to never flag as IOCs (false positive prevention)
EXCLUDED_DOMAINS = [
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "microsoft.com",
    "windows.net",
    "azure.com",
    "amazon.com",
    "amazonaws.com",
    "cloudflare.com",
    "cloudflare-dns.com",
    "akamai.com",
    "akamaiedge.net",
    "fastly.net",
    "github.com",
    "githubusercontent.com",
    "twitter.com",
    "facebook.com",
    "linkedin.com",
    "youtube.com",
    "apple.com",
    "icloud.com",
    # Common security/research domains
    "virustotal.com",
    "urlscan.io",
    "shodan.io",
    "censys.io",
    "validin.com",
]

# Parking/sinkhole indicators (body hash patterns, page titles, etc.)
PARKING_INDICATORS = {
    "titles": [
        "domain for sale",
        "parked domain",
        "this domain is for sale",
        "buy this domain",
        "domain parking",
        "coming soon",
        "under construction",
    ],
    "body_hashes": [
        # Add known parking page hashes here as discovered
    ],
}

# =============================================================================
# IOC Extraction Configuration
# =============================================================================

# Known TLDs (subset - add more as needed)
VALID_TLDS = {
    # Generic
    "com", "net", "org", "info", "biz", "name", "pro",
    # Country codes
    "ru", "by", "kz", "ua", "uz", "am", "az", "ge", "md", "kg", "tj", "tm",
    # Common
    "io", "co", "me", "tv", "cc", "ws", "ly", "to", "fm", "am", "la",
    # New gTLDs
    "online", "site", "website", "tech", "xyz", "top", "club", "shop", "app",
    "dev", "cloud", "digital", "network", "systems", "solutions", "services",
    "my", "su",
}

# User agent for fetching reports
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# =============================================================================
# File Paths
# =============================================================================

BASE_DIR = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "reports"
FETCHED_DIR = REPORTS_DIR / "fetched"
OUTPUT_DIR = BASE_DIR / "output"
CACHE_DIR = BASE_DIR / "cache"

# Ensure directories exist
for dir_path in [REPORTS_DIR, FETCHED_DIR, OUTPUT_DIR, CACHE_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# =============================================================================
# Logging Configuration
# =============================================================================

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_API_CALLS = True  # Log all API calls for debugging

# =============================================================================
# Validation
# =============================================================================

def validate_config():
    """Validate configuration and return any warnings."""
    warnings = []

    if not VALIDIN_API_KEY:
        warnings.append("VALIDIN_API_KEY environment variable not set")

    return warnings


if __name__ == "__main__":
    # Print configuration summary when run directly
    print("Validin Infrastructure Hunter — Configuration")
    print("=" * 40)
    print(f"API Key Set: {'Yes' if VALIDIN_API_KEY else 'NO - SET VALIDIN_API_KEY'}")
    print(f"Base URL: {VALIDIN_BASE_URL}")
    print(f"Rate Limit: {RATE_LIMIT_RPS} req/sec")
    print(f"Pivot Depth: {PIVOT_DEPTH}")
    print(f"Max Cotenancy: {MAX_COTENANCY}")
    print(f"Max Hash Connectivity: {MAX_HASH_CONNECTIVITY}")
    print(f"Reports Dir: {REPORTS_DIR}")
    print(f"Cache Dir: {CACHE_DIR}")

    warnings = validate_config()
    if warnings:
        print("\nWarnings:")
        for w in warnings:
            print(f"  - {w}")
