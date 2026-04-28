#!/usr/bin/env python3
"""
Validin Infrastructure Hunter

CLI tool for automated infrastructure pivoting using the Validin API.
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

from models import IOC, IOCType, EnrichmentResult, NewIOC, CorpusHuntResult
from config import (
    VALIDIN_API_KEY, REPORTS_DIR, OUTPUT_DIR, PIVOT_DEPTH,
    validate_config
)
from ioc_extractor import extract_from_reports, extract_iocs_from_text
from validin_client import ValidinClient, ValidinAPIError, ValidinAuthError
from enrichment import EnrichmentEngine
from connection_analyzer import ConnectionAnalyzer
from noise_filter import NoiseFilter
from output import ReportGenerator, create_hunt_result


def setup_logging(verbose: bool = False, debug: bool = False):
    """Configure logging based on verbosity level."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def cmd_extract(args):
    """Extract IOCs from reports."""
    logger = logging.getLogger(__name__)
    logger.info("Extracting IOCs from reports...")

    iocs = extract_from_reports(
        reports_dir=Path(args.input) if args.input else REPORTS_DIR,
        fetch_urls=not args.no_fetch,
        force_fetch=args.force_fetch
    )

    print(f"\nExtracted {len(iocs)} IOCs:")
    print("-" * 40)

    # Group by type
    by_type: Dict[str, List[IOC]] = {}
    for ioc in iocs:
        type_name = ioc.ioc_type.value
        if type_name not in by_type:
            by_type[type_name] = []
        by_type[type_name].append(ioc)

    for ioc_type, type_iocs in sorted(by_type.items()):
        print(f"\n{ioc_type.upper()} ({len(type_iocs)}):")
        for ioc in type_iocs[:10]:  # Show first 10
            print(f"  {ioc.value}")
        if len(type_iocs) > 10:
            print(f"  ... and {len(type_iocs) - 10} more")

    # Save to file if requested
    if args.output:
        output_path = Path(args.output)
        with open(output_path, 'w', encoding='utf-8') as f:
            for ioc in iocs:
                f.write(f"{ioc.ioc_type.value},{ioc.value}\n")
        print(f"\nSaved to: {output_path}")


def cmd_enrich(args):
    """Enrich IOCs without connection analysis."""
    logger = logging.getLogger(__name__)

    # Get IOCs
    if args.ioc:
        # Single IOC provided
        ioc_type = detect_ioc_type(args.ioc)
        if not ioc_type:
            print(f"ERROR: Could not determine IOC type for: {args.ioc}")
            sys.exit(1)
        iocs = [IOC(value=args.ioc, ioc_type=ioc_type, is_seed=True)]
    else:
        # Extract from reports
        iocs = extract_from_reports(
            reports_dir=Path(args.input) if args.input else REPORTS_DIR
        )

    if not iocs:
        print("No IOCs to enrich.")
        sys.exit(1)

    print(f"Enriching {len(iocs)} IOCs...")

    # Initialize engine
    client = ValidinClient()
    if not client.test_connection():
        print("ERROR: Failed to connect to Validin API. Check your API key.")
        sys.exit(1)

    engine = EnrichmentEngine(client=client)

    # Enrich each IOC
    results: Dict[str, EnrichmentResult] = {}
    for i, ioc in enumerate(iocs):
        print(f"[{i+1}/{len(iocs)}] Enriching {ioc.value}...")
        try:
            result = engine.enrich_ioc(ioc, depth=0)
            results[ioc.value] = result
        except Exception as e:
            logger.error(f"Failed to enrich {ioc.value}: {e}")

    # Generate output
    print(f"\nEnrichment complete. Results for {len(results)} IOCs.")

    for ioc_value, result in results.items():
        print(f"\n{'='*60}")
        print(f"IOC: {ioc_value}")
        print(f"{'='*60}")
        print(f"  DNS Records: {len(result.dns_records)}")
        print(f"  Host Fingerprints: {len(result.host_fingerprints)}")
        print(f"  Certificates: {len(result.certificates)}")
        print(f"  OSINT Hits: {len(result.osint_hits)}")
        print(f"  Subdomains: {len(result.subdomains)}")
        if result.registration:
            print(f"  Registrar: {result.registration.registrar}")

    print(f"\nTotal API requests: {client.get_request_count()}")


def save_intermediate_results(phase: str, enrichment_results: dict, connections: list = None, new_iocs: list = None, output_dir: Path = None):
    """Save intermediate results after each phase."""
    import json

    output_dir = output_dir or OUTPUT_DIR
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save enrichment results
    enrichment_file = output_dir / f"{phase}_enrichment.json"
    enrichment_data = {}
    for key, result in enrichment_results.items():
        enrichment_data[key] = {
            "ioc": result.ioc.value,
            "ioc_type": result.ioc.ioc_type.value if result.ioc.ioc_type else None,
            "dns_records": len(result.dns_records),
            "fingerprints": len(result.host_fingerprints),
            "certificates": len(result.certificates),
            "raw_responses": result.raw_responses
        }

    with open(enrichment_file, 'w') as f:
        json.dump(enrichment_data, f, indent=2, default=str)
    print(f"  -> Saved intermediate results to {enrichment_file}")

    # Save connections if available
    if connections:
        conn_file = output_dir / f"{phase}_connections.json"
        conn_data = [
            {
                "source": c.source_ioc.value,
                "target": c.target_ioc.value,
                "type": c.connection_type.value if c.connection_type else None,
                "confidence": c.confidence_score,
                "tier": c.confidence_tier
            }
            for c in connections
        ]
        with open(conn_file, 'w') as f:
            json.dump(conn_data, f, indent=2)
        print(f"  -> Saved connections to {conn_file}")

    # Save new IOCs if available
    if new_iocs:
        iocs_file = output_dir / f"{phase}_new_iocs.json"
        iocs_data = [
            {
                "value": n.ioc.value,
                "type": n.ioc.ioc_type.value if n.ioc.ioc_type else None,
                "confidence": n.confidence_score,
                "discovered_via": n.discovered_via,
                "connected_to_seed": n.connected_to_seed
            }
            for n in new_iocs
        ]
        with open(iocs_file, 'w') as f:
            json.dump(iocs_data, f, indent=2)
        print(f"  -> Saved new IOCs to {iocs_file}")


def cmd_hunt(args):
    """Run full hunting pipeline."""
    logger = logging.getLogger(__name__)

    # Get IOCs
    if args.ioc:
        ioc_type = detect_ioc_type(args.ioc)
        if not ioc_type:
            print(f"ERROR: Could not determine IOC type for: {args.ioc}")
            sys.exit(1)
        iocs = [IOC(value=args.ioc, ioc_type=ioc_type, is_seed=True)]
    else:
        iocs = extract_from_reports(
            reports_dir=Path(args.input) if args.input else REPORTS_DIR
        )

    if not iocs:
        print("No IOCs to hunt from.")
        sys.exit(1)

    # Filter to only domains and IPs for pivoting
    # Also extract domains from URLs since reports often contain full URLs
    pivotable_iocs = []
    seen_values = set()

    for ioc in iocs:
        if ioc.ioc_type in [IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6]:
            if ioc.value not in seen_values:
                pivotable_iocs.append(ioc)
                seen_values.add(ioc.value)
        elif ioc.ioc_type == IOCType.URL:
            # Extract domain from URL
            from urllib.parse import urlparse
            try:
                # Handle defanged URLs
                url = ioc.value.replace('hxxp', 'http').replace('[.]', '.')
                parsed = urlparse(url)
                domain = parsed.hostname
                if domain and domain not in seen_values:
                    domain_ioc = IOC(
                        value=domain,
                        ioc_type=IOCType.DOMAIN,
                        original=ioc.original,
                        source_file=ioc.source_file,
                        context=f"Extracted from URL: {ioc.value}",
                        is_seed=True
                    )
                    pivotable_iocs.append(domain_ioc)
                    seen_values.add(domain)
            except Exception:
                pass  # Skip malformed URLs

    print(f"Starting hunt with {len(pivotable_iocs)} pivotable IOCs...")
    print(f"Pivot depth: {args.depth}")

    # Create run-specific output folder
    base_output_dir = Path(args.output) if args.output else OUTPUT_DIR
    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Use first IOC value (sanitized) in folder name for easier identification
    first_ioc = pivotable_iocs[0].value if pivotable_iocs else "unknown"
    safe_ioc_name = "".join(c if c.isalnum() or c in ".-_" else "_" for c in first_ioc)[:30]
    run_dir = Path(base_output_dir) / f"hunt_{safe_ioc_name}_{run_timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output folder: {run_dir}")

    # Initialize components
    client = ValidinClient()
    if not client.test_connection():
        print("ERROR: Failed to connect to Validin API. Check your API key.")
        sys.exit(1)

    engine = EnrichmentEngine(client=client)
    analyzer = ConnectionAnalyzer(engine=engine)
    generator = ReportGenerator(output_dir=run_dir)

    # Phase 1: Enrich all seed IOCs
    print("\n[Phase 1] Enriching seed IOCs...")
    enrichment_results: Dict[str, EnrichmentResult] = {}

    for i, ioc in enumerate(pivotable_iocs):
        print(f"  [{i+1}/{len(pivotable_iocs)}] {ioc.value}")
        try:
            result = engine.enrich_ioc(ioc, depth=0)
            enrichment_results[ioc.value] = result
        except Exception as e:
            logger.error(f"  Failed to enrich {ioc.value}: {e}")

    # Save after Phase 1
    save_intermediate_results("phase1", enrichment_results, output_dir=run_dir)

    # Phase 1b: Multi-indicator pivot analysis
    print("\n[Phase 1b] Multi-indicator pivot analysis...")
    multi_indicator_matches = {}
    for ioc_key, seed_result in enrichment_results.items():
        if seed_result.ioc.ioc_type not in [IOCType.DOMAIN, IOCType.IPV4]:
            continue
        print(f"  Pivoting from all indicators of: {ioc_key}")
        matches = analyzer.find_multi_indicator_matches(seed_result)
        multi_indicator_matches[ioc_key] = matches

        multi = [m for m in matches if m.indicator_count >= 2]
        print(f"  -> {len(matches)} hosts found, {len(multi)} share 2+ indicators\n")

        if matches:
            header = f"  {'HOST':<40} {'INDS':>4}  {'QUALITY':>7}  INDICATOR TYPES"
            print(header)
            print(f"  {'-'*40}  {'-'*4}  {'-'*7}  {'-'*40}")
            for m in matches[:25]:
                types_str = " | ".join(
                    f"{h.indicator_type}[conn={h.connectivity}]"
                    for h in m.indicator_hits
                )
                host_col = m.host if len(m.host) <= 40 else m.host[:37] + "..."
                print(
                    f"  {host_col:<40} {m.indicator_count:>4}  "
                    f"{m.quality_score:>7.3f}  {types_str}"
                )
            if len(matches) > 25:
                print(f"  ... and {len(matches) - 25} more single-indicator hosts (see report)")
        print()

    # Phase 2: Analyze connections
    print("\n[Phase 2] Analyzing connections...")
    connections, new_iocs = analyzer.analyze_all(
        enrichment_results,
        pivot_depth=args.depth
    )

    # Save after Phase 2
    save_intermediate_results("phase2", enrichment_results, connections, new_iocs, output_dir=run_dir)

    # Phase 3: Optionally enrich high-confidence new IOCs
    if args.depth > 0 and new_iocs:
        high_conf_new = [n for n in new_iocs if n.confidence_score >= 0.8][:20]
        if high_conf_new:
            print(f"\n[Phase 3] Enriching {len(high_conf_new)} high-confidence discoveries...")
            for i, new_ioc in enumerate(high_conf_new):
                if new_ioc.ioc.value not in enrichment_results:
                    print(f"  [{i+1}/{len(high_conf_new)}] {new_ioc.ioc.value}")
                    try:
                        result = engine.enrich_ioc(new_ioc.ioc, depth=1)
                        enrichment_results[new_ioc.ioc.value] = result
                    except Exception as e:
                        logger.error(f"  Failed: {e}")

            # Re-analyze with new data
            print("\n[Phase 3b] Re-analyzing with enriched discoveries...")
            connections, new_iocs = analyzer.analyze_all(
                enrichment_results,
                pivot_depth=args.depth
            )

            # Save after Phase 3b
            save_intermediate_results("phase3b", enrichment_results, connections, new_iocs, output_dir=run_dir)

    # Phase 4: Generate reports
    print("\n[Phase 4] Generating reports...")

    hunt_result = create_hunt_result(
        seed_iocs=iocs,
        enrichment_results=enrichment_results,
        connections=connections,
        new_iocs=new_iocs,
        pivot_depth=args.depth,
        multi_indicator_matches=multi_indicator_matches,
        metadata={
            "api_requests": client.get_request_count(),
            "seed_count": len(iocs),
            "pivotable_count": len(pivotable_iocs)
        }
    )

    reports = generator.generate_all_reports(hunt_result)

    # Summary
    print("\n" + "=" * 60)
    print("HUNT COMPLETE")
    print("=" * 60)
    print(f"  Seed IOCs analyzed: {len(pivotable_iocs)}")

    # Multi-indicator summary
    total_mi = sum(len(m) for m in multi_indicator_matches.values())
    multi_mi = sum(
        sum(1 for m in matches if m.indicator_count >= 2)
        for matches in multi_indicator_matches.values()
    )
    print(f"  Multi-indicator pivot: {total_mi} hosts share ≥1 indicator, "
          f"{multi_mi} share ≥2 indicators")

    print(f"  Connections found (pairwise): {len(connections)}")
    print(f"    - Tier 1 (strong): {len([c for c in connections if c.confidence_tier == 1])}")
    print(f"    - Tier 2 (moderate): {len([c for c in connections if c.confidence_tier == 2])}")
    print(f"    - Tier 3 (contextual): {len([c for c in connections if c.confidence_tier == 3])}")
    print(f"  New IOCs discovered: {len(new_iocs)}")
    print(f"  API requests made: {client.get_request_count()}")
    print(f"\nReports saved to:")
    for fmt, path in reports.items():
        print(f"  {fmt}: {path}")


def _load_corpus_seeds(seeds_arg: str) -> List[IOC]:
    """
    Load seed list for corpus mode.

    Accepts either a path to a file (one IOC per line, '#' for comments) or a
    comma-separated string of IOC values. Only DOMAIN / IPV4 / IPV6 seeds are
    retained — corpus mode pivots on infra, not on hashes.
    """
    raw: List[str] = []
    p = Path(seeds_arg)
    if p.exists() and p.is_file():
        with open(p, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                raw.append(line)
    else:
        raw = [s.strip() for s in seeds_arg.split(',') if s.strip()]

    seeds: List[IOC] = []
    seen: set = set()
    for value in raw:
        # Defang handling
        value = value.replace('[.]', '.').replace('hxxp', 'http')
        ioc_type = detect_ioc_type(value)
        if ioc_type not in (IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6):
            continue
        if value in seen:
            continue
        seen.add(value)
        seeds.append(IOC(value=value, ioc_type=ioc_type, is_seed=True))
    return seeds


def cmd_corpus(args):
    """Run a corpus-mode hunt: extract shared signatures across a known seed set."""
    logger = logging.getLogger(__name__)

    seeds = _load_corpus_seeds(args.seeds)
    if len(seeds) < 2:
        print("ERROR: corpus mode requires at least 2 seeds (domains or IPs).")
        sys.exit(1)

    print(f"Corpus mode: {len(seeds)} seeds loaded")
    for s in seeds:
        print(f"  - {s.value} ({s.ioc_type.value})")

    # Output folder
    base_output_dir = Path(args.output) if args.output else OUTPUT_DIR
    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path(base_output_dir) / f"corpus_{run_timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output folder: {run_dir}")

    # Initialize
    client = ValidinClient()
    if not client.test_connection():
        print("ERROR: Failed to connect to Validin API. Check your API key.")
        sys.exit(1)

    engine = EnrichmentEngine(client=client)
    analyzer = ConnectionAnalyzer(engine=engine)
    generator = ReportGenerator(output_dir=run_dir)

    # Phase 1: enrich all seeds
    print("\n[Phase 1] Enriching seed corpus...")
    enrichment_results: Dict[str, EnrichmentResult] = {}
    for i, ioc in enumerate(seeds):
        print(f"  [{i+1}/{len(seeds)}] {ioc.value}")
        try:
            result = engine.enrich_ioc(ioc, depth=0)
            enrichment_results[ioc.value] = result
        except Exception as e:
            logger.error(f"  Failed to enrich {ioc.value}: {e}")

    save_intermediate_results("phase1", enrichment_results, output_dir=run_dir)

    # Phase 2: corpus signature analysis + expansion + promotion
    print("\n[Phase 2a] Extracting corpus signatures...")
    signatures, discovered, promoted, corpus_connections = analyzer.run_corpus_hunt(
        enrichment_results
    )

    print(f"  -> {len(signatures)} signatures (>={args.min_coverage or 2} seeds)")
    for sig in signatures[:10]:
        print(
            f"     {sig.param_type:>16}  seeds={len(sig.supporting_seeds)}  "
            f"rarity={sig.rarity_score:.2f}  signal={sig.signal_score:.2f}  "
            f"value={sig.value[:60]}"
        )

    print(f"\n[Phase 2b] Discovered {len(discovered)} candidate IOCs via signature expansion")
    print(f"[Phase 2c] Promoted {len(promoted)} IOCs (matched >=2 signatures)")
    for n in promoted[:10]:
        print(
            f"     {n.ioc.value}  score={n.confidence_score:.2f}  "
            f"sigs={len(n.source_signatures)}"
        )

    new_iocs_list = list(discovered.values())

    # Also run the standard pairwise analysis so report still contains tier2/3 context.
    print("\n[Phase 2d] Running pairwise analysis across seed corpus...")
    pairwise_connections, pairwise_new = analyzer.analyze_all(
        enrichment_results, pivot_depth=0
    )

    # Merge — pairwise_new may overlap with discovered; we prefer corpus discoveries.
    merged_new: Dict[str, NewIOC] = {n.ioc.value: n for n in new_iocs_list}
    for n in pairwise_new:
        if n.ioc.value not in merged_new:
            merged_new[n.ioc.value] = n
    all_connections = corpus_connections + [
        c for c in pairwise_connections
        if (c.source_ioc.value, c.target_ioc.value, c.connection_type.value)
        not in {(c2.source_ioc.value, c2.target_ioc.value, c2.connection_type.value)
                for c2 in corpus_connections}
    ]

    save_intermediate_results(
        "phase2", enrichment_results,
        connections=all_connections, new_iocs=list(merged_new.values()),
        output_dir=run_dir,
    )

    # Optional Phase 3: deep-enrich promoted IOCs
    if args.depth > 0 and promoted:
        print(f"\n[Phase 3] Deep-enriching {len(promoted)} promoted IOCs...")
        for i, new_ioc in enumerate(promoted[:args.max_deep_enrich]):
            if new_ioc.ioc.value in enrichment_results:
                continue
            print(f"  [{i+1}/{min(len(promoted), args.max_deep_enrich)}] {new_ioc.ioc.value}")
            try:
                result = engine.enrich_ioc(new_ioc.ioc, depth=1)
                enrichment_results[new_ioc.ioc.value] = result
            except Exception as e:
                logger.error(f"  Failed: {e}")

    # Phase 4: generate report
    print("\n[Phase 4] Generating corpus report...")
    corpus_result = CorpusHuntResult(
        timestamp=datetime.now().isoformat(),
        seed_iocs=seeds,
        enrichment_results=enrichment_results,
        connections=all_connections,
        new_iocs=list(merged_new.values()),
        signatures=signatures,
        promoted_iocs=promoted,
        pivot_depth=args.depth,
        metadata={
            "api_requests": client.get_request_count(),
            "seed_count": len(seeds),
            "signatures_expanded": sum(1 for s in signatures if s.expanded),
        },
    )
    reports = generator.generate_corpus_reports(corpus_result)

    # Summary
    print("\n" + "=" * 60)
    print("CORPUS HUNT COMPLETE")
    print("=" * 60)
    print(f"  Seeds:               {len(seeds)}")
    print(f"  Signatures:          {len(signatures)}")
    print(f"  Signatures expanded: {sum(1 for s in signatures if s.expanded)}")
    print(f"  Candidate IOCs:      {len(merged_new)}")
    print(f"  Promoted IOCs:       {len(promoted)}  (matched >= {2} signatures)")
    print(f"  API requests:        {client.get_request_count()}")
    print(f"\nReports saved to:")
    for fmt, path in reports.items():
        print(f"  {fmt}: {path}")


def cmd_threat_check(args):
    """Check Validin threat intelligence for a threat group."""
    client = ValidinClient()

    if not client.test_connection():
        print("ERROR: Failed to connect to Validin API. Check your API key.")
        sys.exit(1)

    print(f"Checking threat intelligence for: {args.name}")
    print("-" * 40)

    engine = EnrichmentEngine(client=client)
    intel = engine.check_threat_intel(args.name)

    if intel['found']:
        print(f"FOUND: {args.name}")
        if intel['summary']:
            print(f"\nSummary: {intel['summary']}")
        if intel['indicators']:
            print(f"\nIndicators: {len(intel['indicators'])} records")
        if intel['reports']:
            print(f"Reports: {len(intel['reports'])} records")
    else:
        print(f"NOT FOUND: '{args.name}' not in Validin threat intelligence")
        print("\nTip: Use 'python main.py threat-check --name <name>' to look up any threat group in Validin.")


def detect_ioc_type(value: str) -> Optional[IOCType]:
    """Detect IOC type from value."""
    import re

    # IPv4
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
        return IOCType.IPV4

    # IPv6
    if ':' in value and re.match(r'^[0-9a-fA-F:]+$', value):
        return IOCType.IPV6

    # URL
    if value.startswith(('http://', 'https://', 'hxxp://', 'hxxps://')):
        return IOCType.URL

    # Email
    if '@' in value and '.' in value:
        return IOCType.EMAIL

    # Hashes (by length)
    if re.match(r'^[a-fA-F0-9]+$', value):
        if len(value) == 32:
            return IOCType.MD5
        elif len(value) == 40:
            return IOCType.SHA1
        elif len(value) == 64:
            return IOCType.SHA256

    # Domain (default for remaining alphanumeric with dots)
    if '.' in value and re.match(r'^[a-zA-Z0-9\-\.]+$', value):
        return IOCType.DOMAIN

    return None


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Validin Infrastructure Hunter',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract IOCs from reports directory
  python main.py extract --input reports/

  # Run full pivot hunt from reports
  python main.py hunt --input reports/ --depth 1

  # Hunt from a single IOC
  python main.py hunt --ioc "evil-domain.com" --depth 1

  # Check threat intelligence for a named group
  python main.py threat-check --name "APT28"

  # Enrich a single IOC without pivot analysis
  python main.py enrich --ioc "suspicious-domain.com"

  # Corpus mode: find shared signatures across a known seed set
  python main.py corpus --seeds seeds.txt --depth 1
  python main.py corpus --seeds "a.com,b.com,c.com" --depth 1
        """
    )

    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract IOCs from reports')
    extract_parser.add_argument('--input', '-i', help='Input directory (default: reports/)')
    extract_parser.add_argument('--output', '-o', help='Output file for IOC list')
    extract_parser.add_argument('--no-fetch', action='store_true',
                               help='Skip fetching URLs from reports.txt')
    extract_parser.add_argument('--force-fetch', action='store_true',
                               help='Force re-fetch of cached URLs')

    # Enrich command
    enrich_parser = subparsers.add_parser('enrich', help='Enrich IOCs without analysis')
    enrich_parser.add_argument('--input', '-i', help='Input directory')
    enrich_parser.add_argument('--ioc', help='Single IOC to enrich')
    enrich_parser.add_argument('--output', '-o', help='Output directory')

    # Hunt command
    hunt_parser = subparsers.add_parser('hunt', help='Run full hunting pipeline')
    hunt_parser.add_argument('--input', '-i', help='Input directory')
    hunt_parser.add_argument('--ioc', help='Single IOC to hunt from')
    hunt_parser.add_argument('--depth', '-d', type=int, default=PIVOT_DEPTH,
                            help=f'Pivot depth (default: {PIVOT_DEPTH})')
    hunt_parser.add_argument('--output', '-o', help='Output directory')
    hunt_parser.add_argument('--no-cache', action='store_true',
                            help='Disable API response caching')

    # Corpus command
    corpus_parser = subparsers.add_parser(
        'corpus',
        help='Corpus mode: extract shared signatures across a known seed set'
    )
    corpus_parser.add_argument(
        '--seeds', required=True,
        help='Path to seed file (one IOC per line) OR comma-separated IOC list'
    )
    corpus_parser.add_argument(
        '--depth', '-d', type=int, default=PIVOT_DEPTH,
        help=f'Pivot depth for promoted IOC deep-enrichment (default: {PIVOT_DEPTH})'
    )
    corpus_parser.add_argument(
        '--min-coverage', type=int, default=None,
        help='Min seeds sharing a param for it to become a signature (default: 2)'
    )
    corpus_parser.add_argument(
        '--max-deep-enrich', type=int, default=20,
        help='Max promoted IOCs to deep-enrich in phase 3'
    )
    corpus_parser.add_argument('--output', '-o', help='Output directory')

    # Threat check command
    threat_parser = subparsers.add_parser('threat-check',
                                         help='Check Validin threat intelligence')
    threat_parser.add_argument('--name', '-n', required=True,
                              help='Threat group name to check')

    args = parser.parse_args()

    # Setup logging
    setup_logging(verbose=args.verbose, debug=args.debug)

    # Check configuration
    warnings = validate_config()
    if warnings:
        for warning in warnings:
            print(f"WARNING: {warning}")

    if not VALIDIN_API_KEY and args.command in ['enrich', 'hunt', 'corpus', 'threat-check']:
        print("ERROR: VALIDIN_API_KEY environment variable not set")
        print("Set it with: export VALIDIN_API_KEY=your_key_here")
        sys.exit(1)

    # Route to command handler
    try:
        if args.command == 'extract':
            cmd_extract(args)
        elif args.command == 'enrich':
            cmd_enrich(args)
        elif args.command == 'hunt':
            cmd_hunt(args)
        elif args.command == 'corpus':
            cmd_corpus(args)
        elif args.command == 'threat-check':
            cmd_threat_check(args)
        else:
            parser.print_help()
            sys.exit(1)
    except ValidinAuthError as e:
        print(f"\nError: {e}", file=sys.stderr)
        print("Your API key does not have permission for this query type.", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
