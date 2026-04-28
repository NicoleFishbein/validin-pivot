"""IOC extraction from threat reports with defanging support."""

import re
import hashlib
import logging
from pathlib import Path
from typing import List, Set, Tuple, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from models import IOC, IOCType
from config import (
    REPORTS_DIR, FETCHED_DIR, USER_AGENT, VALID_TLDS,
    EXCLUDED_DOMAINS, REQUEST_TIMEOUT
)

logger = logging.getLogger(__name__)


# =============================================================================
# Defanging Patterns
# =============================================================================

DEFANG_REPLACEMENTS = [
    (r'\[\.\]', '.'),
    (r'\[dot\]', '.', re.IGNORECASE),
    (r'\(\.\)', '.'),
    (r'\[:\]', ':'),
    (r'\[://\]', '://'),
    (r'hxxps://', 'https://'),
    (r'hxxp://', 'http://'),
    (r'hXXps://', 'https://'),
    (r'hXXp://', 'http://'),
    (r'\[@\]', '@'),
    (r'\[at\]', '@', re.IGNORECASE),
    (r'\(at\)', '@', re.IGNORECASE),
]


def refang(text: str) -> str:
    """Convert defanged indicators back to their original form."""
    result = text
    for pattern in DEFANG_REPLACEMENTS:
        if len(pattern) == 2:
            regex, replacement = pattern
            flags = 0
        else:
            regex, replacement, flags = pattern
        result = re.sub(regex, replacement, result, flags=flags)
    return result


# =============================================================================
# IOC Regex Patterns
# =============================================================================

# IPv4 - handles defanged [.] notation
IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\.)){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# IPv6 - standard pattern
IPV6_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|'
    r'\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b'
)

# Domain - handles defanged notation
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?:\[\.\]|\.))+[a-zA-Z]{2,}\b'
)

# URL - handles hxxp and defanged notation
URL_PATTERN = re.compile(
    r'(?:hxxps?|https?|ftp)(?:\[?://\]?|://)'
    r'[^\s<>\"\'\)\]]+',
    re.IGNORECASE
)

# Email - handles [@] and [at] defanging
EMAIL_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+-]+(?:@|\[@\]|\[at\])[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    re.IGNORECASE
)

# Hash patterns - strict hex matching
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')


# =============================================================================
# Validation Functions
# =============================================================================

def is_valid_ipv4(ip: str) -> bool:
    """Validate IPv4 address (each octet 0-255)."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """Validate domain has known TLD and isn't excluded."""
    domain_lower = domain.lower()

    # Check against exclusion list
    for excluded in EXCLUDED_DOMAINS:
        if domain_lower == excluded or domain_lower.endswith('.' + excluded):
            return False

    # Extract TLD
    parts = domain_lower.split('.')
    if len(parts) < 2:
        return False

    tld = parts[-1]
    return tld in VALID_TLDS


def is_valid_hash(value: str, expected_length: int) -> bool:
    """Validate hash is proper hex and correct length."""
    if len(value) != expected_length:
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def is_likely_hash_context(text: str, match_start: int, match_end: int) -> bool:
    """Check if the matched string is likely a hash based on context."""
    # Get surrounding context
    context_start = max(0, match_start - 50)
    context_end = min(len(text), match_end + 50)
    context = text[context_start:context_end].lower()

    # Hash-related keywords
    hash_keywords = [
        'hash', 'md5', 'sha', 'sha1', 'sha256', 'sha-256', 'sha-1',
        'checksum', 'ioc', 'indicator', 'malware', 'sample', 'file',
        'payload', 'dropper', 'loader', 'backdoor', 'trojan'
    ]

    return any(keyword in context for keyword in hash_keywords)


# =============================================================================
# Extraction Functions
# =============================================================================

def get_context(text: str, start: int, end: int, context_size: int = 100) -> str:
    """Extract surrounding context for an IOC match."""
    ctx_start = max(0, start - context_size)
    ctx_end = min(len(text), end + context_size)
    context = text[ctx_start:ctx_end]
    # Clean up whitespace
    context = ' '.join(context.split())
    return context


def extract_iocs_from_text(text: str, source_file: str = "") -> List[IOC]:
    """Extract all IOCs from text content."""
    iocs = []
    seen: Set[Tuple[str, IOCType]] = set()

    def add_ioc(value: str, ioc_type: IOCType, original: str, context: str):
        """Add IOC if not already seen."""
        key = (value.lower() if ioc_type in [IOCType.DOMAIN, IOCType.EMAIL] else value, ioc_type)
        if key not in seen:
            seen.add(key)
            iocs.append(IOC(
                value=value,
                ioc_type=ioc_type,
                original=original,
                source_file=source_file,
                context=context,
                is_seed=True
            ))

    # Extract URLs first (they contain domains)
    for match in URL_PATTERN.finditer(text):
        original = match.group(0)
        refanged = refang(original)
        # Clean trailing punctuation
        refanged = re.sub(r'[.,;:!?\)\]]+$', '', refanged)
        context = get_context(text, match.start(), match.end())
        add_ioc(refanged, IOCType.URL, original, context)

        # Extract domain from URL
        try:
            parsed = urlparse(refanged)
            if parsed.netloc:
                domain = parsed.netloc.split(':')[0]  # Remove port
                if is_valid_domain(domain):
                    add_ioc(domain, IOCType.DOMAIN, domain, context)
        except Exception:
            pass

    # Extract standalone domains (not already captured in URLs)
    for match in DOMAIN_PATTERN.finditer(text):
        original = match.group(0)
        refanged = refang(original)
        if is_valid_domain(refanged):
            context = get_context(text, match.start(), match.end())
            add_ioc(refanged, IOCType.DOMAIN, original, context)

    # Extract IPv4
    for match in IPV4_PATTERN.finditer(text):
        original = match.group(0)
        refanged = refang(original)
        if is_valid_ipv4(refanged):
            context = get_context(text, match.start(), match.end())
            add_ioc(refanged, IOCType.IPV4, original, context)

    # Extract IPv6
    for match in IPV6_PATTERN.finditer(text):
        original = match.group(0)
        context = get_context(text, match.start(), match.end())
        add_ioc(original, IOCType.IPV6, original, context)

    # Extract emails
    for match in EMAIL_PATTERN.finditer(text):
        original = match.group(0)
        refanged = refang(original)
        context = get_context(text, match.start(), match.end())
        add_ioc(refanged, IOCType.EMAIL, original, context)

    # Extract hashes (with context checking to reduce false positives)
    # SHA256 first (longest)
    for match in SHA256_PATTERN.finditer(text):
        value = match.group(0)
        if is_valid_hash(value, 64):
            if is_likely_hash_context(text, match.start(), match.end()):
                context = get_context(text, match.start(), match.end())
                add_ioc(value.lower(), IOCType.SHA256, value, context)

    # SHA1
    for match in SHA1_PATTERN.finditer(text):
        value = match.group(0)
        if is_valid_hash(value, 40):
            # Skip if this is part of a SHA256
            if not any(ioc.value.lower().startswith(value.lower()) or
                      ioc.value.lower().endswith(value.lower())
                      for ioc in iocs if ioc.ioc_type == IOCType.SHA256):
                if is_likely_hash_context(text, match.start(), match.end()):
                    context = get_context(text, match.start(), match.end())
                    add_ioc(value.lower(), IOCType.SHA1, value, context)

    # MD5
    for match in MD5_PATTERN.finditer(text):
        value = match.group(0)
        if is_valid_hash(value, 32):
            # Skip if this is part of a longer hash
            if not any(ioc.value.lower().startswith(value.lower()) or
                      ioc.value.lower().endswith(value.lower())
                      for ioc in iocs if ioc.ioc_type in [IOCType.SHA1, IOCType.SHA256]):
                if is_likely_hash_context(text, match.start(), match.end()):
                    context = get_context(text, match.start(), match.end())
                    add_ioc(value.lower(), IOCType.MD5, value, context)

    return iocs


# =============================================================================
# Report Fetching
# =============================================================================

def sanitize_url_slug(url: str) -> str:
    """Create a safe filename slug from URL."""
    # Remove protocol and common prefixes
    slug = re.sub(r'^https?://', '', url)
    # Replace unsafe chars with underscores
    slug = re.sub(r'[^\w\-.]', '_', slug)
    # Truncate if too long
    if len(slug) > 100:
        slug = slug[:100] + '_' + hashlib.md5(url.encode()).hexdigest()[:8]
    return slug + '.txt'


def fetch_report_url(url: str, force: bool = False) -> Optional[str]:
    """Fetch report URL and extract text content. Returns cached if available."""
    cache_path = FETCHED_DIR / sanitize_url_slug(url)

    # Check cache
    if cache_path.exists() and not force:
        logger.info(f"Using cached content for {url}")
        return cache_path.read_text(encoding='utf-8')

    # Skip PDFs
    if url.lower().endswith('.pdf'):
        logger.warning(f"Skipping PDF URL (manual extraction required): {url}")
        return None

    logger.info(f"Fetching {url}")
    try:
        response = requests.get(
            url,
            headers={'User-Agent': USER_AGENT},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True
        )
        response.raise_for_status()

        # Check content type
        content_type = response.headers.get('content-type', '').lower()
        if 'pdf' in content_type:
            logger.warning(f"Skipping PDF content: {url}")
            return None

        # Parse HTML and extract text
        soup = BeautifulSoup(response.content, 'lxml')

        # Remove script, style, nav, footer, sidebar elements
        for tag in soup.find_all(['script', 'style', 'nav', 'footer', 'aside',
                                  'header', 'noscript', 'iframe']):
            tag.decompose()

        # Try to find main content area
        main_content = (
            soup.find('article') or
            soup.find('main') or
            soup.find('div', class_=re.compile(r'content|article|post|entry', re.I)) or
            soup.find('div', id=re.compile(r'content|article|post|entry', re.I)) or
            soup.body
        )

        if main_content:
            text = main_content.get_text(separator='\n', strip=True)
        else:
            text = soup.get_text(separator='\n', strip=True)

        # Clean up excessive whitespace
        text = re.sub(r'\n{3,}', '\n\n', text)

        # Cache the result
        cache_path.write_text(text, encoding='utf-8')
        logger.info(f"Cached content to {cache_path}")

        # Check if content seems too short (might be JS-rendered)
        if len(text) < 500:
            logger.warning(
                f"Content from {url} is very short ({len(text)} chars). "
                "Page may be JavaScript-rendered. Consider manual IOC extraction."
            )

        return text

    except requests.RequestException as e:
        logger.error(f"Failed to fetch {url}: {e}")
        return None


def load_report_urls(reports_file: Path = None) -> List[str]:
    """Load URLs from reports.txt file."""
    if reports_file is None:
        reports_file = REPORTS_DIR / 'reports.txt'

    if not reports_file.exists():
        logger.warning(f"Reports file not found: {reports_file}")
        return []

    urls = []
    with open(reports_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # Skip comments and blank lines
            if not line or line.startswith('#'):
                continue
            urls.append(line)

    logger.info(f"Loaded {len(urls)} URLs from {reports_file}")
    return urls


# =============================================================================
# Main Extraction Pipeline
# =============================================================================

def extract_from_reports(
    reports_dir: Path = None,
    fetch_urls: bool = True,
    force_fetch: bool = False
) -> List[IOC]:
    """
    Extract IOCs from all reports in directory and fetched URLs.

    Args:
        reports_dir: Directory containing report files
        fetch_urls: Whether to fetch URLs from reports.txt
        force_fetch: Force re-fetch of URLs even if cached

    Returns:
        Deduplicated list of IOCs
    """
    if reports_dir is None:
        reports_dir = REPORTS_DIR

    all_iocs: List[IOC] = []
    seen: Set[Tuple[str, IOCType]] = set()

    def add_iocs(iocs: List[IOC]):
        for ioc in iocs:
            key = (ioc.value.lower() if ioc.ioc_type in [IOCType.DOMAIN, IOCType.EMAIL]
                   else ioc.value, ioc.ioc_type)
            if key not in seen:
                seen.add(key)
                all_iocs.append(ioc)

    # Process local files (txt, md, html)
    for ext in ['*.txt', '*.md', '*.html']:
        for file_path in reports_dir.glob(ext):
            # Skip reports.txt and fetched directory
            if file_path.name == 'reports.txt' or 'fetched' in str(file_path):
                continue
            logger.info(f"Processing local file: {file_path}")
            try:
                content = file_path.read_text(encoding='utf-8')
                iocs = extract_iocs_from_text(content, source_file=str(file_path))
                add_iocs(iocs)
                logger.info(f"  Found {len(iocs)} IOCs in {file_path.name}")
            except Exception as e:
                logger.error(f"Error processing {file_path}: {e}")

    # Process manual_iocs.txt if it exists
    manual_file = reports_dir / 'manual_iocs.txt'
    if manual_file.exists():
        logger.info(f"Processing manual IOCs from {manual_file}")
        try:
            content = manual_file.read_text(encoding='utf-8')
            iocs = extract_iocs_from_text(content, source_file=str(manual_file))
            add_iocs(iocs)
            logger.info(f"  Found {len(iocs)} IOCs in manual_iocs.txt")
        except Exception as e:
            logger.error(f"Error processing manual_iocs.txt: {e}")

    # Fetch and process URLs
    if fetch_urls:
        urls = load_report_urls(reports_dir / 'reports.txt')
        for url in urls:
            content = fetch_report_url(url, force=force_fetch)
            if content:
                iocs = extract_iocs_from_text(content, source_file=url)
                add_iocs(iocs)
                logger.info(f"  Found {len(iocs)} IOCs from {url}")

    # Process fetched cache (in case URLs were fetched in previous runs)
    for cache_file in FETCHED_DIR.glob('*.txt'):
        if cache_file.name not in [sanitize_url_slug(u) for u in load_report_urls()]:
            # This is an orphaned cache file, skip it
            continue

    logger.info(f"Total unique IOCs extracted: {len(all_iocs)}")

    # Summary by type
    type_counts = {}
    for ioc in all_iocs:
        type_counts[ioc.ioc_type.value] = type_counts.get(ioc.ioc_type.value, 0) + 1
    for ioc_type, count in sorted(type_counts.items()):
        logger.info(f"  {ioc_type}: {count}")

    return all_iocs


# =============================================================================
# CLI for Testing
# =============================================================================

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Test with sample defanged text
    test_text = """
    Known C2 infrastructure:
    - 199.59.243[.]228
    - 94.103.3[.]82
    - hxxps://fast-eda[.]my/dostavka/lavka/kategorii

    File hashes (SHA256):
    - 0506a6fcee0d4bf731f1825484582180978995a8f9b84fc59b6e631f720915da
    - 74fab6adc77307ef9767e710d97c885352763e68518b2109d860bb45e9d0a8eb

    Contact: researcher[@]example.com
    """

    print("Testing IOC extraction with sample text...")
    print("=" * 50)
    iocs = extract_iocs_from_text(test_text, source_file="test")
    for ioc in iocs:
        print(f"  [{ioc.ioc_type.value}] {ioc.value}")
        print(f"    Original: {ioc.original}")
    print()

    # Run full extraction if reports exist
    if REPORTS_DIR.exists():
        print("Running full extraction from reports/...")
        print("=" * 50)
        all_iocs = extract_from_reports()
        print(f"\nExtracted {len(all_iocs)} total IOCs")
