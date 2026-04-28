"""Report generation for infrastructure hunt results."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from models import (
    IOC, IOCType, Connection, EnrichmentResult, NewIOC, HuntResult,
    CorpusHuntResult, CorpusSignature, MultiIndicatorMatch,
)
from config import OUTPUT_DIR

logger = logging.getLogger(__name__)


def _fmt_ts(ts: int) -> str:
    """Format a unix timestamp as YYYY-MM-DD (UTC), or '—' if missing."""
    if not ts:
        return "—"
    return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")


def _backend_colocal(
    backend_ips: List[str],
    ip_ts: Dict[str, Any],
    window_h: float = 48.0,
) -> List[tuple]:
    """
    Return pairs of backend IPs whose first_seen differ by <= window_h hours,
    sorted by delta ascending. Each entry: (ip_a, ip_b, delta_h, ts_a, ts_b).
    """
    import itertools
    pairs = []
    for ip_a, ip_b in itertools.combinations(backend_ips[:20], 2):
        ta = ip_ts.get(ip_a) or [0, 0]
        tb = ip_ts.get(ip_b) or [0, 0]
        if ta[0] > 0 and tb[0] > 0:
            delta_h = abs(ta[0] - tb[0]) / 3600
            if delta_h <= window_h:
                pairs.append((ip_a, ip_b, delta_h, ta[0], tb[0]))
    pairs.sort(key=lambda x: x[2])
    return pairs


def _seed_dns_ips(enrichment_results: Dict[str, Any], seed_value: str) -> set:
    """Return the set of DNS A-record IPs observed for a given seed domain."""
    result = enrichment_results.get(seed_value)
    if not result:
        return set()
    return {r.value for r in result.dns_records if r.record_type == 'A'}


class ReportGenerator:
    """
    Generates reports from hunt results in various formats.

    Supported formats:
    - JSON: Complete structured data
    - Markdown: Human-readable summary
    - Graph: Node/edge data for visualization
    """

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_json_report(
        self,
        hunt_result: HuntResult,
        filename: str = None
    ) -> Path:
        """
        Generate complete JSON report.

        Args:
            hunt_result: HuntResult object with all data
            filename: Optional custom filename

        Returns:
            Path to generated file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"hunt_report_{timestamp}.json"

        filepath = self.output_dir / filename

        # Convert to dictionary
        report_data = hunt_result.to_dict()

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)

        logger.info(f"JSON report saved to: {filepath}")
        return filepath

    def generate_markdown_report(
        self,
        hunt_result: HuntResult,
        filename: str = None
    ) -> Path:
        """
        Generate human-readable Markdown report.

        Args:
            hunt_result: HuntResult object with all data
            filename: Optional custom filename

        Returns:
            Path to generated file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"hunt_report_{timestamp}.md"

        filepath = self.output_dir / filename

        lines = []

        # Header
        lines.append("# Validin Infrastructure Hunt Report")
        lines.append("")
        lines.append(f"**Generated:** {hunt_result.timestamp}")
        lines.append(f"**Pivot Depth:** {hunt_result.pivot_depth}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- **Seed IOCs analyzed:** {len(hunt_result.seed_iocs)}")
        lines.append(f"- **New IOCs discovered:** {len(hunt_result.new_iocs)}")
        lines.append(f"- **Total connections found:** {len(hunt_result.connections)}")
        lines.append("")

        # Connection breakdown by tier
        tier_counts = {1: 0, 2: 0, 3: 0}
        for conn in hunt_result.connections:
            tier_counts[conn.confidence_tier] = tier_counts.get(conn.confidence_tier, 0) + 1

        lines.append("### Connection Confidence Breakdown")
        lines.append("")
        lines.append(f"- **Tier 1 (Strong):** {tier_counts.get(1, 0)} connections")
        lines.append(f"- **Tier 2 (Moderate):** {tier_counts.get(2, 0)} connections")
        lines.append(f"- **Tier 3 (Contextual):** {tier_counts.get(3, 0)} connections")
        lines.append("")

        # Multi-indicator pivot analysis
        if hunt_result.multi_indicator_matches:
            lines.append("## Multi-Indicator Pivot Analysis")
            lines.append("")
            lines.append(
                "For each seed every indicator type (hashes, redirect targets, shared IPs) is "
                "pivoted independently. Results are then inverted to a per-host view: hosts that "
                "appear across multiple indicators are listed first. A host matching on 2+ "
                "distinct indicator types is a significantly stronger attribution signal than "
                "one found via a single pivot."
            )
            lines.append("")

            for seed_value, matches in hunt_result.multi_indicator_matches.items():
                lines.append(f"### {seed_value}")
                lines.append("")
                if not matches:
                    lines.append("_No hosts found via any indicator pivot._")
                    lines.append("")
                    continue

                multi = [m for m in matches if m.indicator_count >= 2]
                lines.append(
                    f"**{len(matches)} hosts** share at least one indicator with `{seed_value}`. "
                    f"**{len(multi)} share 2 or more indicators.**"
                )
                lines.append("")

                # Table: all matches, capped at 50
                lines.append("| Host | # Indicators | Quality | Indicator Types (connectivity) |")
                lines.append("|------|:------------:|:-------:|-------------------------------|")
                for m in matches[:50]:
                    ind_str = " · ".join(
                        f"`{h.indicator_type}` ({h.connectivity})"
                        for h in m.indicator_hits
                    )
                    promoted = "**" if m.indicator_count >= 2 else ""
                    lines.append(
                        f"| {promoted}`{m.host}`{promoted} | {m.indicator_count} | "
                        f"{m.quality_score:.3f} | {ind_str} |"
                    )
                if len(matches) > 50:
                    lines.append(
                        f"| _(+{len(matches) - 50} more single-indicator hosts — see JSON)_ "
                        f"| | | |"
                    )
                lines.append("")

        # Seed IOCs
        lines.append("## Seed IOCs")
        lines.append("")
        lines.append("| Type | Value | Source |")
        lines.append("|------|-------|--------|")
        for ioc in hunt_result.seed_iocs:
            source = ioc.source_file[:40] + "..." if len(ioc.source_file) > 40 else ioc.source_file
            lines.append(f"| {ioc.ioc_type.value} | `{ioc.value}` | {source} |")
        lines.append("")

        # High-confidence connections (Tier 1)
        tier1_conns = [c for c in hunt_result.connections if c.confidence_tier == 1]
        if tier1_conns:
            lines.append("## Strong Connections (Tier 1)")
            lines.append("")
            lines.append("These connections have high confidence and likely indicate operational relationships.")
            lines.append("")

            for conn in sorted(tier1_conns, key=lambda c: -c.confidence_score)[:20]:
                lines.append(f"### {conn.source_ioc.value} ↔ {conn.target_ioc.value}")
                lines.append("")
                lines.append(f"- **Type:** {conn.connection_type.value}")
                lines.append(f"- **Score:** {conn.confidence_score:.2f}")
                lines.append(f"- **Temporal Overlap:** {'Yes' if conn.timestamp_overlap else 'No'}")
                if conn.notes:
                    lines.append(f"- **Notes:** {conn.notes}")
                lines.append("")

                # Co-deployment callout
                ev = conn.evidence
                if ev.get("co_deployment_signal"):
                    hrs = ev.get("co_deployment_hours", 0)
                    lines.append(
                        f"> **Co-deployment signal:** same hash first observed on both hosts "
                        f"within **{hrs:.0f}h** of each other — strong indicator of "
                        f"coordinated infrastructure stand-up."
                    )
                    lines.append("")

                # Backend IP callout
                backend_ips = ev.get("backend_ips") if ev else None
                if backend_ips:
                    lines.append(
                        f"> **Backend IPs:** hash also observed on non-CDN IP(s): "
                        f"`{'`, `'.join(backend_ips[:5])}`"
                    )
                    lines.append("")

                # Evidence details (skip callout keys already rendered above)
                _callout_keys = {"co_deployment_signal", "co_deployment_hours",
                                 "source_hash_first_seen", "target_hash_first_seen",
                                 "backend_ips"}
                if ev:
                    remaining = {k: v for k, v in ev.items() if k not in _callout_keys}
                    if remaining:
                        lines.append("**Evidence:**")
                        for key, value in remaining.items():
                            if isinstance(value, (list, dict)):
                                value = json.dumps(value)
                            lines.append(f"- {key}: `{value}`")
                        lines.append("")

                lines.append(f"**Pivot Path:** {' → '.join(conn.pivot_path)}")
                lines.append("")
                lines.append("---")
                lines.append("")

        # Moderate connections (Tier 2) - summarized
        tier2_conns = [c for c in hunt_result.connections if c.confidence_tier == 2]
        if tier2_conns:
            lines.append("## Moderate Connections (Tier 2)")
            lines.append("")
            lines.append("| Source | Target | Type | Score |")
            lines.append("|--------|--------|------|-------|")
            for conn in sorted(tier2_conns, key=lambda c: -c.confidence_score)[:30]:
                lines.append(
                    f"| `{conn.source_ioc.value}` | `{conn.target_ioc.value}` | "
                    f"{conn.connection_type.value} | {conn.confidence_score:.2f} |"
                )
            lines.append("")

        # Newly discovered IOCs
        if hunt_result.new_iocs:
            lines.append("## Newly Discovered IOCs")
            lines.append("")
            lines.append("These indicators were discovered through pivoting and warrant further investigation.")
            lines.append("")

            # Group by confidence tier
            high_conf = [n for n in hunt_result.new_iocs if n.confidence_tier == 1]
            med_conf = [n for n in hunt_result.new_iocs if n.confidence_tier == 2]

            if high_conf:
                lines.append("### High Confidence Discoveries")
                lines.append("")
                lines.append("| Type | Value | Discovered Via | Connected To | Score |")
                lines.append("|------|-------|----------------|--------------|-------|")
                for new_ioc in sorted(high_conf, key=lambda n: -n.confidence_score)[:30]:
                    lines.append(
                        f"| {new_ioc.ioc.ioc_type.value} | `{new_ioc.ioc.value}` | "
                        f"{new_ioc.discovered_via} | `{new_ioc.connected_to_seed}` | "
                        f"{new_ioc.confidence_score:.2f} |"
                    )
                lines.append("")

            if med_conf:
                lines.append("### Moderate Confidence Discoveries")
                lines.append("")
                lines.append("| Type | Value | Discovered Via | Score |")
                lines.append("|------|-------|----------------|-------|")
                for new_ioc in sorted(med_conf, key=lambda n: -n.confidence_score)[:20]:
                    lines.append(
                        f"| {new_ioc.ioc.ioc_type.value} | `{new_ioc.ioc.value}` | "
                        f"{new_ioc.discovered_via} | {new_ioc.confidence_score:.2f} |"
                    )
                lines.append("")

        # Recommendations
        lines.append("## Recommendations for Further Investigation")
        lines.append("")

        if tier1_conns:
            lines.append("1. **High-priority domains** for deeper analysis:")
            seen = set()
            for conn in tier1_conns[:10]:
                for ioc in [conn.source_ioc, conn.target_ioc]:
                    if ioc.value not in seen and not ioc.is_seed:
                        lines.append(f"   - `{ioc.value}`")
                        seen.add(ioc.value)
                        if len(seen) >= 5:
                            break
                if len(seen) >= 5:
                    break
            lines.append("")

        if hunt_result.new_iocs:
            high_score_new = [n for n in hunt_result.new_iocs if n.confidence_score >= 0.8][:5]
            if high_score_new:
                lines.append("2. **Newly discovered IOCs** to block/monitor:")
                for new_ioc in high_score_new:
                    lines.append(f"   - `{new_ioc.ioc.value}` (score: {new_ioc.confidence_score:.2f})")
                lines.append("")

        lines.append("3. **Consider extending pivot depth** if:")
        lines.append("   - Multiple Tier 1 connections were found")
        lines.append("   - New IOCs discovered have low co-tenancy/connectivity")
        lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append("*Report generated by Validin Infrastructure Hunter*")

        # Write file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

        logger.info(f"Markdown report saved to: {filepath}")
        return filepath

    def generate_graph_data(
        self,
        hunt_result: HuntResult,
        filename: str = None
    ) -> Path:
        """
        Generate graph data (nodes and edges) for visualization.

        Args:
            hunt_result: HuntResult object with all data
            filename: Optional custom filename

        Returns:
            Path to generated file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"hunt_graph_{timestamp}.json"

        filepath = self.output_dir / filename

        # Build nodes
        nodes = []
        node_ids = set()

        # Add seed IOCs
        for ioc in hunt_result.seed_iocs:
            if ioc.value not in node_ids:
                nodes.append({
                    "id": ioc.value,
                    "type": ioc.ioc_type.value,
                    "is_seed": True,
                    "label": ioc.value
                })
                node_ids.add(ioc.value)

        # Add connected IOCs
        for conn in hunt_result.connections:
            for ioc in [conn.source_ioc, conn.target_ioc]:
                if ioc.value not in node_ids:
                    nodes.append({
                        "id": ioc.value,
                        "type": ioc.ioc_type.value,
                        "is_seed": ioc.is_seed,
                        "label": ioc.value
                    })
                    node_ids.add(ioc.value)

        # Add new IOCs
        for new_ioc in hunt_result.new_iocs:
            if new_ioc.ioc.value not in node_ids:
                nodes.append({
                    "id": new_ioc.ioc.value,
                    "type": new_ioc.ioc.ioc_type.value,
                    "is_seed": False,
                    "is_new": True,
                    "label": new_ioc.ioc.value,
                    "confidence": new_ioc.confidence_score
                })
                node_ids.add(new_ioc.ioc.value)

        # Build edges
        edges = []
        seen_edges = set()

        for conn in hunt_result.connections:
            edge_key = tuple(sorted([conn.source_ioc.value, conn.target_ioc.value]))
            if edge_key not in seen_edges:
                edges.append({
                    "source": conn.source_ioc.value,
                    "target": conn.target_ioc.value,
                    "type": conn.connection_type.value,
                    "tier": conn.confidence_tier,
                    "weight": conn.confidence_score,
                    "label": conn.connection_type.value
                })
                seen_edges.add(edge_key)

        graph_data = {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "timestamp": hunt_result.timestamp,
                "node_count": len(nodes),
                "edge_count": len(edges)
            }
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(graph_data, f, indent=2)

        logger.info(f"Graph data saved to: {filepath}")
        return filepath

    def generate_ioc_list(
        self,
        hunt_result: HuntResult,
        filename: str = None,
        min_score: float = 0.7,
        include_seeds: bool = True
    ) -> Path:
        """
        Generate a simple IOC list for blocklisting/detection.

        Args:
            hunt_result: HuntResult object
            filename: Optional custom filename
            min_score: Minimum confidence score for inclusion
            include_seeds: Whether to include seed IOCs

        Returns:
            Path to generated file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ioc_list_{timestamp}.txt"

        filepath = self.output_dir / filename

        iocs_by_type: Dict[str, List[str]] = {
            "domain": [],
            "ipv4": [],
            "ipv6": [],
            "url": [],
            "md5": [],
            "sha1": [],
            "sha256": [],
        }

        # Add seed IOCs
        if include_seeds:
            for ioc in hunt_result.seed_iocs:
                type_key = ioc.ioc_type.value
                if type_key in iocs_by_type and ioc.value not in iocs_by_type[type_key]:
                    iocs_by_type[type_key].append(ioc.value)

        # Add new IOCs above threshold
        for new_ioc in hunt_result.new_iocs:
            if new_ioc.confidence_score >= min_score:
                type_key = new_ioc.ioc.ioc_type.value
                if type_key in iocs_by_type and new_ioc.ioc.value not in iocs_by_type[type_key]:
                    iocs_by_type[type_key].append(new_ioc.ioc.value)

        # Write file
        lines = []
        lines.append(f"# Validin Infrastructure Hunter — IOC List")
        lines.append(f"# Generated: {hunt_result.timestamp}")
        lines.append(f"# Minimum confidence: {min_score}")
        lines.append("")

        for ioc_type, values in iocs_by_type.items():
            if values:
                lines.append(f"# {ioc_type.upper()}")
                for value in sorted(values):
                    lines.append(value)
                lines.append("")

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

        logger.info(f"IOC list saved to: {filepath}")
        return filepath

    # =========================================================================
    # Corpus Mode Reports
    # =========================================================================

    def generate_corpus_markdown(
        self,
        corpus_result: CorpusHuntResult,
        filename: str = None,
    ) -> Path:
        """
        Markdown report for corpus-mode hunts. Leads with the "Common
        Infrastructure Fingerprint" table — the table of signatures that
        characterize the operation — and the promoted IOCs (>=2 signatures).
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"corpus_report_{timestamp}.md"
        filepath = self.output_dir / filename

        seeds = corpus_result.seed_iocs
        signatures = corpus_result.signatures
        promoted = corpus_result.promoted_iocs
        total_seeds = len(seeds)
        total_sigs = len(signatures)
        seed_values = {s.value for s in seeds}

        lines: List[str] = []
        lines.append("# Corpus Infrastructure Hunt Report")
        lines.append("")
        lines.append(f"**Generated:** {corpus_result.timestamp}")
        lines.append(f"**Mode:** corpus ({total_seeds} seeds)")
        lines.append(f"**Pivot depth:** {corpus_result.pivot_depth}")
        lines.append("")

        # Pre-compute seed-to-seed pairwise connections (Tier 1 only)
        seed_seed_t1 = [
            c for c in corpus_result.connections
            if c.source_ioc.value in seed_values
            and c.target_ioc.value in seed_values
            and c.confidence_tier == 1
        ]

        # Co-deployment flags and backend co-location flags
        co_deployed_pairs: List[tuple] = []
        ip_co_deployed_pairs: List[tuple] = []
        backend_colocal_callouts: List[tuple] = []
        seen_backend_pair_keys: set = set()
        seen_ip_co_deploy_keys: set = set()
        for conn in seed_seed_t1:
            ev = conn.evidence or {}
            if ev.get("co_deployment_signal"):
                co_deployed_pairs.append((
                    conn.source_ioc.value,
                    conn.target_ioc.value,
                    ev.get("co_deployment_hours", 0),
                    ev.get("source_hash_first_seen", 0),
                    ev.get("target_hash_first_seen", 0),
                ))
            if ev.get("ip_co_deployment_signal"):
                pair_key = tuple(sorted([conn.source_ioc.value, conn.target_ioc.value])
                                 ) + (ev.get("shared_ip", ""),)
                if pair_key not in seen_ip_co_deploy_keys:
                    seen_ip_co_deploy_keys.add(pair_key)
                    ip_co_deployed_pairs.append((
                        conn.source_ioc.value,
                        conn.target_ioc.value,
                        ev.get("shared_ip", ""),
                        ev.get("ip_co_deployment_hours", 0),
                        ev.get("source_first_seen", 0),
                        ev.get("target_first_seen", 0),
                    ))
            bips = ev.get("backend_ips", [])
            ip_ts = ev.get("backend_ip_timestamps", {})
            if len(bips) >= 2 and ip_ts:
                for pair in _backend_colocal(bips, ip_ts):
                    pair_key = tuple(sorted([pair[0], pair[1]]))
                    if pair_key not in seen_backend_pair_keys:
                        seen_backend_pair_keys.add(pair_key)
                        backend_colocal_callouts.append((conn, pair))

        # ─── Executive Summary ────────────────────────────────────────────────
        expanded = sum(1 for s in signatures if s.expanded)
        full_cov_sigs = sum(
            1 for s in signatures if len(s.supporting_seeds) == total_seeds
        )
        best_promo_sigs = max(
            (len(n.source_signatures) for n in promoted), default=0
        )

        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- **Seeds:** {total_seeds}")
        lines.append(f"- **Signatures extracted:** {total_sigs}")
        lines.append(f"- **Signatures expanded via pivot:** {expanded}")
        lines.append(f"- **Candidate IOCs discovered:** {len(corpus_result.new_iocs)}")
        lines.append(
            f"- **Promoted IOCs (matched >=2 signatures):** {len(promoted)}"
        )
        lines.append("")

        # Seed cross-coverage block
        if total_sigs:
            lines.append("### Seed Cross-Coverage")
            lines.append("")
            if total_seeds == 2:
                s0, s1 = seeds[0].value, seeds[1].value
                lines.append(
                    f"`{s0}` and `{s1}` share **{full_cov_sigs}/{total_sigs} signatures** "
                    f"({full_cov_sigs / total_sigs * 100:.0f}% of the corpus fingerprint). "
                    "Every signature listed below is present on **both** seeds."
                )
            else:
                lines.append(
                    f"**{full_cov_sigs}/{total_sigs}** signatures have full {total_seeds}/{total_seeds} "
                    "seed coverage — shared by every seed in the corpus."
                )
            if promoted and total_sigs:
                lines.append(
                    f"Best promoted match covers **{best_promo_sigs}/{total_sigs} signatures** "
                    f"({best_promo_sigs / total_sigs * 100:.0f}%). "
                    "For comparison the seed pair itself shares all signatures at 100%."
                )
            lines.append("")

        # Co-deployment callout
        if co_deployed_pairs:
            lines.append("### Hash Co-deployment Signal")
            lines.append("")
            for src, tgt, hrs, src_ts, tgt_ts in co_deployed_pairs:
                lines.append(
                    f"> **Coordinated stand-up:** `{src}` and `{tgt}` first hosted the "
                    f"same hash fingerprint within **{hrs:.0f}h** of each other "
                    f"({_fmt_ts(src_ts)} on `{src}`, {_fmt_ts(tgt_ts)} on `{tgt}`). "
                    "This is a strong indicator of a timed, shared deployment."
                )
            lines.append("")

        if ip_co_deployed_pairs:
            lines.append("### Shared IP Co-deployment Signal")
            lines.append("")
            for src, tgt, ip, hrs, src_ts, tgt_ts in ip_co_deployed_pairs:
                lines.append(
                    f"> **Coordinated stand-up:** `{src}` and `{tgt}` both pointed to "
                    f"`{ip}` within **{hrs:.0f}h** of each other "
                    f"({_fmt_ts(src_ts)} on `{src}`, {_fmt_ts(tgt_ts)} on `{tgt}`). "
                    "Shared backend IP with close first-seen timestamps indicates a timed, shared deployment."
                )
            lines.append("")

        if backend_colocal_callouts:
            lines.append("### Backend IP Co-deployment")
            lines.append("")
            for conn, (ip_a, ip_b, delta_h, ts_a, ts_b) in backend_colocal_callouts:
                lines.append(
                    f"> **Non-CDN backends `{ip_a}` and `{ip_b}` went live within "
                    f"{delta_h:.0f}h of each other** ({_fmt_ts(ts_a)} vs {_fmt_ts(ts_b)}), "
                    f"discovered via `{conn.source_ioc.value}` ↔ `{conn.target_ioc.value}` "
                    "hash pivot."
                )
            lines.append("")

        # ─── Seed Corpus table ───────────────────────────────────────────────
        lines.append("## Seed Corpus")
        lines.append("")
        lines.append("| # | Value | Type |")
        lines.append("|---|-------|------|")
        for i, s in enumerate(seeds, 1):
            lines.append(f"| {i} | `{s.value}` | {s.ioc_type.value} |")
        lines.append("")

        # ─── Seed-to-Seed Infrastructure Ties ────────────────────────────────
        if seed_seed_t1:
            lines.append("## Seed-to-Seed Infrastructure Ties")
            lines.append("")
            lines.append(
                "Tier 1 connections directly linking the seed domains to each other "
                "via shared hash fingerprints. "
                "**Backend IPs** are non-CDN IPs that also carry the same fingerprint."
            )
            lines.append("")

            from collections import defaultdict as _dd
            pair_conns: Dict[tuple, List] = _dd(list)
            for conn in sorted(seed_seed_t1, key=lambda c: -c.confidence_score):
                pair_key = (
                    min(conn.source_ioc.value, conn.target_ioc.value),
                    max(conn.source_ioc.value, conn.target_ioc.value),
                )
                pair_conns[pair_key].append(conn)

            for (src_val, tgt_val), conns in pair_conns.items():
                lines.append(f"### `{src_val}` ↔ `{tgt_val}`")
                lines.append("")
                src_dns_ips = _seed_dns_ips(corpus_result.enrichment_results, src_val)
                tgt_dns_ips = _seed_dns_ips(corpus_result.enrichment_results, tgt_val)

                for conn in conns:
                    ev = conn.evidence or {}
                    lines.append(
                        f"**{conn.connection_type.value}** | score `{conn.confidence_score:.2f}` | "
                        f"tier {conn.confidence_tier}"
                    )
                    lines.append("")

                    hash_val = ev.get("hash_value", "")
                    hash_type = ev.get("hash_type", conn.connection_type.value)
                    connectivity = ev.get("connectivity", "?")
                    if hash_val:
                        trunc = hash_val[:32] + ("..." if len(hash_val) > 32 else "")
                        lines.append(
                            f"- **Hash:** `{trunc}` "
                            f"({hash_type}, connectivity={connectivity})"
                        )

                    if ev.get("co_deployment_signal"):
                        hrs = ev.get("co_deployment_hours", 0)
                        src_first = ev.get("source_hash_first_seen", 0)
                        tgt_first = ev.get("target_hash_first_seen", 0)
                        lines.append(
                            f"- **Co-deployment:** same hash appeared on both hosts within "
                            f"**{hrs:.0f}h** "
                            f"({_fmt_ts(src_first)} on `{src_val}`, "
                            f"{_fmt_ts(tgt_first)} on `{tgt_val}`)"
                        )

                    bips = ev.get("backend_ips", [])
                    ip_ts: Dict[str, Any] = ev.get("backend_ip_timestamps", {})
                    if bips:
                        lines.append("- **Non-CDN backend IPs:**")
                        for ip in bips[:10]:
                            ts_entry = ip_ts.get(ip) or [0, 0]
                            first_dt = _fmt_ts(ts_entry[0])
                            last_dt = _fmt_ts(ts_entry[1])
                            if ip in src_dns_ips:
                                attr = f" ← `{src_val}` DNS A"
                            elif ip in tgt_dns_ips:
                                attr = f" ← `{tgt_val}` DNS A"
                            else:
                                attr = ""
                            lines.append(
                                f"  - `{ip}` — first seen **{first_dt}**, "
                                f"last seen {last_dt}{attr}"
                            )
                        colocal = _backend_colocal(bips, ip_ts)
                        if colocal:
                            ip_a, ip_b, delta_h, clt_a, clt_b = colocal[0]
                            lines.append(
                                f"  - ⚡ **Backend co-deployment:** `{ip_a}` and `{ip_b}` "
                                f"went live within **{delta_h:.0f}h** of each other "
                                f"({_fmt_ts(clt_a)} vs {_fmt_ts(clt_b)})"
                            )
                    lines.append("")

        # ─── Common Infrastructure Fingerprint ───────────────────────────────
        lines.append("## Common Infrastructure Fingerprint")
        lines.append("")
        if signatures:
            lines.append(
                "Parameters shared across 2+ seeds, sorted by signal "
                "(coverage × rarity). High-signal rows are the operator's "
                "distinctive tells. "
                "**Scope:** `excl.` = shared only between seeds with no new hosts "
                "found via this sig; `↗ N` = expanded to N new candidate hosts."
            )
            lines.append("")
            lines.append(
                "| Param | Value | Seeds | Coverage | Rarity | Signal | Connectivity | Scope |"
            )
            lines.append(
                "|-------|-------|-------|----------|--------|--------|--------------|-------|"
            )
            for sig in signatures[:50]:
                val = sig.value if len(sig.value) <= 40 else sig.value[:37] + "..."
                conn_str = (
                    str(sig.source_connectivity)
                    if sig.source_connectivity is not None else "-"
                )
                scope = f"↗ {len(sig.discovered_iocs)}" if sig.discovered_iocs else "excl."
                lines.append(
                    f"| {sig.param_type} | `{val}` | "
                    f"{len(sig.supporting_seeds)}/{total_seeds} | "
                    f"{sig.coverage_ratio:.2f} | {sig.rarity_score:.2f} | "
                    f"**{sig.signal_score:.3f}** | {conn_str} | "
                    f"{scope} |"
                )
            lines.append("")
        else:
            lines.append("_No shared parameters met the coverage threshold._")
            lines.append("")

        # ─── Promoted IOCs ────────────────────────────────────────────────────
        lines.append("## Promoted IOCs (Multi-Signature Match)")
        lines.append("")
        if promoted:
            lines.append(
                "IOCs attributed to 2+ distinct signatures. Promotion overrides "
                "per-signature confidence because multi-parameter overlap is the "
                "strongest single indicator that a host belongs to this corpus. "
                f"**Sigs matched** shows N/{total_sigs} — for comparison the seed pair "
                "itself shares all signatures at 100%."
            )
            lines.append("")
            lines.append(
                f"| # | Value | Type | Score | Sigs matched (/{total_sigs}) | Signatures |"
            )
            lines.append(
                f"|---|-------|------|-------|------------------------------|------------|"
            )
            for i, n in enumerate(promoted[:100], 1):
                sigs_str = ", ".join(n.source_signatures[:4])
                if len(n.source_signatures) > 4:
                    sigs_str += f", +{len(n.source_signatures) - 4}"
                pct = (
                    f" ({n.source_signatures.__len__() / total_sigs * 100:.0f}%)"
                    if total_sigs else ""
                )
                lines.append(
                    f"| {i} | `{n.ioc.value}` | {n.ioc.ioc_type.value} | "
                    f"{n.confidence_score:.2f} | "
                    f"**{len(n.source_signatures)}/{total_sigs}**{pct} | "
                    f"{sigs_str} |"
                )
            lines.append("")
        else:
            lines.append(
                "_No IOC matched >= 2 distinct signatures. Widen min-coverage "
                "or add more seeds to the corpus._"
            )
            lines.append("")

        # ─── Single-signature candidates ─────────────────────────────────────
        single_sig = [
            n for n in corpus_result.new_iocs
            if not n.promoted and len(n.source_signatures) == 1
        ]
        if single_sig:
            lines.append("## Other Candidate IOCs (Single-Signature)")
            lines.append("")
            lines.append(
                f"_{len(single_sig)} candidates matched exactly one signature — "
                "lower confidence, use as leads._"
            )
            lines.append("")
            lines.append("| Value | Type | Score | Signature |")
            lines.append("|-------|------|-------|-----------|")
            for n in sorted(single_sig, key=lambda x: -x.confidence_score)[:40]:
                sig_id = n.source_signatures[0] if n.source_signatures else "-"
                lines.append(
                    f"| `{n.ioc.value}` | {n.ioc.ioc_type.value} | "
                    f"{n.confidence_score:.2f} | {sig_id} |"
                )
            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append("*Report generated by Paper Werewolf Infrastructure Hunter (corpus mode)*")

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        logger.info(f"Corpus markdown report saved to: {filepath}")
        return filepath

    def generate_corpus_json(
        self,
        corpus_result: CorpusHuntResult,
        filename: str = None,
    ) -> Path:
        """Full JSON dump of the corpus hunt (signatures + promoted + everything else)."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"corpus_report_{timestamp}.json"
        filepath = self.output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(corpus_result.to_dict(), f, indent=2, default=str)
        logger.info(f"Corpus JSON report saved to: {filepath}")
        return filepath

    def generate_corpus_ioc_list(
        self,
        corpus_result: CorpusHuntResult,
        filename: str = None,
    ) -> Path:
        """Plaintext IOC list — promoted IOCs first, then the rest."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"corpus_iocs_{timestamp}.txt"
        filepath = self.output_dir / filename
        lines: List[str] = []
        lines.append("# Corpus hunt IOCs")
        lines.append(f"# Generated: {corpus_result.timestamp}")
        lines.append("")
        lines.append("## Promoted (multi-signature)")
        for n in corpus_result.promoted_iocs:
            lines.append(n.ioc.value)
        lines.append("")
        lines.append("## Single-signature candidates")
        for n in corpus_result.new_iocs:
            if not n.promoted:
                lines.append(n.ioc.value)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        logger.info(f"Corpus IOC list saved to: {filepath}")
        return filepath

    def generate_corpus_reports(
        self,
        corpus_result: CorpusHuntResult,
        base_name: str = None,
    ) -> Dict[str, Path]:
        """Generate all corpus-mode report formats."""
        if base_name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = f"corpus_report_{timestamp}"
        return {
            "json": self.generate_corpus_json(corpus_result, f"{base_name}.json"),
            "markdown": self.generate_corpus_markdown(corpus_result, f"{base_name}.md"),
            "ioc_list": self.generate_corpus_ioc_list(corpus_result, f"{base_name}_iocs.txt"),
        }

    def generate_all_reports(
        self,
        hunt_result: HuntResult,
        base_name: str = None
    ) -> Dict[str, Path]:
        """
        Generate all report formats.

        Args:
            hunt_result: HuntResult object
            base_name: Optional base name for files

        Returns:
            Dict of format -> filepath
        """
        if base_name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = f"hunt_report_{timestamp}"

        results = {}

        results['json'] = self.generate_json_report(
            hunt_result, f"{base_name}.json"
        )
        results['markdown'] = self.generate_markdown_report(
            hunt_result, f"{base_name}.md"
        )
        results['graph'] = self.generate_graph_data(
            hunt_result, f"{base_name}_graph.json"
        )
        results['ioc_list'] = self.generate_ioc_list(
            hunt_result, f"{base_name}_iocs.txt"
        )

        return results


def create_hunt_result(
    seed_iocs: List[IOC],
    enrichment_results: Dict[str, EnrichmentResult],
    connections: List[Connection],
    new_iocs: List[NewIOC],
    pivot_depth: int,
    multi_indicator_matches: Dict[str, List[MultiIndicatorMatch]] = None,
    metadata: Dict[str, Any] = None,
) -> HuntResult:
    """
    Create a HuntResult object from analysis results.

    Args:
        seed_iocs: Original seed IOCs
        enrichment_results: Dict of enrichment results
        connections: List of connections found
        new_iocs: List of newly discovered IOCs
        pivot_depth: Pivot depth used
        multi_indicator_matches: Per-seed multi-indicator pivot results
        metadata: Optional additional metadata

    Returns:
        HuntResult object
    """
    return HuntResult(
        timestamp=datetime.now().isoformat(),
        seed_iocs=seed_iocs,
        enrichment_results=enrichment_results,
        connections=connections,
        new_iocs=new_iocs,
        pivot_depth=pivot_depth,
        multi_indicator_matches=multi_indicator_matches or {},
        metadata=metadata or {},
    )


# =============================================================================
# CLI for Testing
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create sample data for testing
    from models import ConnectionType

    seed_ioc = IOC(
        value="test-domain.com",
        ioc_type=IOCType.DOMAIN,
        is_seed=True,
        source_file="test_report.txt"
    )

    new_ioc = IOC(
        value="discovered-domain.com",
        ioc_type=IOCType.DOMAIN,
        is_seed=False,
        discovered_via="shared_ip_pivot",
        connected_to_seed="test-domain.com"
    )

    connection = Connection(
        source_ioc=seed_ioc,
        target_ioc=new_ioc,
        connection_type=ConnectionType.SHARED_IP,
        confidence_tier=1,
        confidence_score=0.9,
        evidence={"shared_ip": "1.2.3.4", "cotenancy": 5},
        pivot_path=["test-domain.com", "-> IP 1.2.3.4", "discovered-domain.com"],
        timestamp_overlap=True,
        notes="Test connection"
    )

    new_ioc_obj = NewIOC(
        ioc=new_ioc,
        discovered_via="shared_ip_pivot",
        connected_to_seed="test-domain.com",
        confidence_score=0.9,
        confidence_tier=1,
        evidence={"shared_ip": "1.2.3.4"}
    )

    hunt_result = HuntResult(
        timestamp=datetime.now().isoformat(),
        seed_iocs=[seed_ioc],
        enrichment_results={},
        connections=[connection],
        new_iocs=[new_ioc_obj],
        pivot_depth=1
    )

    # Generate reports
    generator = ReportGenerator()
    reports = generator.generate_all_reports(hunt_result, "test_report")

    print("Generated reports:")
    for fmt, path in reports.items():
        print(f"  {fmt}: {path}")
