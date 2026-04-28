# Validin Infrastructure Hunter

Automated infrastructure pivoting CLI for threat intelligence analysts. Given one or more seed IOCs (domains, IPs, or URLs), it queries the [Validin](https://validin.com) passive-DNS and host-response API to discover related infrastructure and score connections by confidence.

## Features

- **Multi-signal pivoting** — shared IPs (with co-tenancy filtering), host-response fingerprint hashes (banner, header, body, cert, favicon, class), redirect location domains, TLS certificates, WHOIS registration patterns, nameservers, subnets
- **Multi-indicator cross-check** — pivots every indicator type independently, then inverts into a per-host view so you can see *which* domains share the most indicators with your seed and *how many* — the strongest single-seed attribution signal
- **3-tier confidence scoring** — Tier 1 (strong, 0.8–1.0), Tier 2 (moderate, 0.4–0.7), Tier 3 (contextual, 0.1–0.3)
- **Noise filtering** — CDN/cloud ASNs, common nameservers, high-connectivity hashes, parking pages, and known-noisy domains are automatically suppressed
- **IOC extraction** — parses domains, IPs, URLs, hashes from local report files or fetched URLs, with defanging support (`hxxps://`, `[.]`, `[at]`, etc.)
- **Report outputs** — JSON, Markdown, graph data (nodes/edges), and a flat IOC blocklist

## Requirements

- Python 3.9+
- A [Validin](https://validin.com) API key

## Installation

```bash
pip install -r requirements.txt
export VALIDIN_API_KEY=your_key_here
```

## Usage

### Hunt from a single IOC

```bash
python main.py hunt --ioc "suspicious-domain.com" --depth 1
```

`--depth 0` enriches seed IOCs only; `--depth 1` (default) also enriches high-confidence discoveries.

### Hunt from report files

Put `.txt`, `.md`, or `.html` files containing IOCs in `reports/`, then:

```bash
python main.py hunt --input reports/ --depth 1
```

IOCs are extracted automatically (domains, IPs, URLs, hashes) with defanging.

You can also list report URLs in `reports/reports.txt` (one URL per line, `#` for comments) — the tool fetches and parses them:

```
# reports/reports.txt
https://example.com/threat-report
```

### Enrich without pivot analysis

```bash
python main.py enrich --ioc "suspicious-domain.com"
```

### Extract IOCs only (no API calls)

```bash
python main.py extract --input reports/ --output iocs.csv
```

### Check Validin threat intelligence

```bash
python main.py threat-check --name "APT28"
```

### Verbosity

```
-v / --verbose    INFO-level logging
--debug           DEBUG-level (full API request log)
```

## Output

Each hunt run creates a timestamped folder under `output/`:

```
output/hunt_suspicious-domain_20250101_120000/
  phase1_enrichment.json       seed IOC enrichment data
  phase2_connections.json      connection analysis
  phase2_new_iocs.json         newly discovered IOCs
  hunt_report_<ts>.json        complete structured result
  hunt_report_<ts>.md          human-readable summary
  hunt_report_<ts>_graph.json  nodes/edges for visualization
  hunt_report_<ts>_iocs.txt    flat IOC list for blocklisting
```

## Configuration

Key settings in `config.py`:

| Setting | Default | Description |
|---|---|---|
| `PIVOT_DEPTH` | `1` | Default pivot depth |
| `MAX_COTENANCY` | `25` | Max co-hosted domains for Tier 1 IP pivot |
| `MAX_HASH_CONNECTIVITY` | `100` | Max hash connections for Tier 1 scoring |
| `REG_WINDOW_DAYS` | `7` | Registration date proximity for Tier 2 |
| `MIN_HASH_WEIGHT` | `0.8` | Minimum hash type weight to query |
| `MAX_HASH_QUERIES_PER_IOC` | `10` | API query limit per IOC for hash pivots |
| `RATE_LIMIT_RPS` | `2` | API requests per second |

Hash type reliability weights (higher = more reliable pivot): `HOST-BANNER_0_HASH` and `HOST-HEADER_HASH` score 1.0; `HOST-CLASS_*` scores 0.9; `HOST-FAVICON_HASH` scores 0.6; `TITLE-HOST` scores 0.3.

## Architecture

```
main.py               CLI — four subcommands: extract, enrich, hunt, threat-check
config.py             All tunable settings and paths
ioc_extractor.py      Parse/defang IOCs from text; fetch report URLs
validin_client.py     Validin REST API client (rate limiting, caching, retries)
enrichment.py         EnrichmentEngine — queries API per IOC, returns EnrichmentResult
connection_analyzer.py ConnectionAnalyzer — scores relationships across enriched IOCs
noise_filter.py       Suppress CDN IPs, common NS, high-connectivity hashes, parking
models.py             Dataclasses: IOC, Connection, EnrichmentResult, HuntResult, etc.
output.py             ReportGenerator — writes JSON, Markdown, graph, IOC list
```

The hunt pipeline runs in phases and saves intermediate JSON after each phase, so a partial run is recoverable.

### Multi-indicator pivot analysis (hunt mode)

**The problem:** discovering a domain via a single Validin pivot (e.g. `HOST-BANNER_0_HASH`) is a lead, not a confirmation. A hash shared by hundreds of hosts tells you less than one shared by five. And a host that appears in *two independent* pivots (same banner hash AND same redirect target) is far more likely to be the same actor's infrastructure than a coincidental match.

**What Phase 1b does:**

For each seed the tool fans out across every indicator type independently:

| Indicator type | How pivoted |
|---|---|
| `HOST-BANNER_0_HASH` | `hash_pivots` API — all hosts returning the same banner hash |
| `HOST-HEADER_HASH` | `hash_pivots` API — all hosts with identical HTTP header fingerprint |
| `HOST-BODY_SHA1` | `hash_pivots` API — all hosts with identical response body |
| `HOST-CERT_SHA1` | `hash_pivots` API — all hosts presenting the same TLS certificate |
| `HOST-FAVICON_HASH` | `hash_pivots` API — all hosts serving the same favicon |
| `HOST-CLASS_0/1_HASH` | `hash_pivots` API — all hosts with the same page-class fingerprint |
| `HOST-LOCATION_DOMAIN` | Hosts that redirect to the same target domain |
| Shared IP | Co-tenancy — other domains on the same IP (filtered by noise threshold) |

The results are then **inverted**: instead of "indicator X → these hosts", you get "this host shares indicators X, Y, Z with your seed". Output is sorted by indicator count (descending), then by quality score (indicator weight × connectivity rarity).

**Reading the output:**

```
HOST                                     INDS  QUALITY  INDICATOR TYPES
----------------------------------------  ----  -------  -------
easytrns.com                               3    2.450  HOST-BANNER_0_HASH[conn=25] | HOST-HEADER_HASH[conn=12] | HOST-LOCATION_DOMAIN[conn=8]
otherdomain.net                            2    1.800  HOST-BANNER_0_HASH[conn=25] | HOST-CERT_SHA1[conn=3]
thirddomain.ru                             1    0.900  HOST-BANNER_0_HASH[conn=25]
```

- **INDS** — how many distinct indicator types this host shares with the seed. 2+ is meaningful; 1 is a lead only.
- **QUALITY** — sum of `(indicator_weight × connectivity_rarity)` across all hits. Lower connectivity = rarer indicator = higher quality.
- **conn=N** — how many hosts globally share that indicator value. Smaller = more distinctive.

The same table appears in the Markdown report under **Multi-Indicator Pivot Analysis**.

### Corpus mode: signature extraction vs. pairwise analysis

Corpus mode runs two distinct analysis passes:

**Corpus signature extraction** asks *what do all my seeds have in common?* It scans every seed's enrichment data, finds parameters shared by 2+ seeds (body hashes, banner hashes, redirect targets, nameservers, etc.), and turns each one into a signature. It then queries Validin with each signature to find every other host that matches it — this is the discovery engine that produces new candidate IOCs.

**Pairwise connection analysis** asks *are these two specific hosts related?* It compares each pair of seeds directly and scores the relationship. It can confirm that seed A and seed B both redirect to the same location domain, but it stops there — it does not then pivot on that location to find additional infrastructure.

The practical difference: a `HOST-LOCATION_DOMAIN` value shared by two seeds appears in the pairwise connection graph but, without corpus signature extraction, it would never be used to discover new IOCs. Both passes run during a corpus hunt and their results are merged.
