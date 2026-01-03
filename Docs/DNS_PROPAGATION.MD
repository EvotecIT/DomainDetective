# DNS Propagation (Multi-Resolver)

The DNS propagation check compares DNS answers across a bounded set of public resolvers to understand global visibility and inconsistency for a given record type (A/AAAA/NS/MX/TXT, etc.).

## What it does

- Queries multiple resolvers for a domain + record type.
- Normalizes and groups responses into distinct “answer sets”.
- Produces rollups (answer sets, countries, resolvers) and findings when:
  - all queries fail,
  - some resolvers fail or return no answers,
  - multiple distinct answer sets are observed.

## How to run

### PowerShell

```powershell
# Run propagation in the overall health workflow (uses DomainHealthCheck settings for server cap/parallelism)
Test-DDDomainOverallHealth -DomainName "example.com" -HealthCheckType DNSPROPAGATION -ExportFormat Html -ExportPath ".\\dns-prop.html"

# Run a single record type and return a view object (good for composition exports)
Test-DDDnsPropagation -DomainName "example.com" -RecordType A -AsView
```

### CLI

```bash
# Include DNS propagation in the report run (can be slow)
ddcli report example.com --dns-propagation
```

## Output surfaces

- HTML (Document profile): world map + rollups per record type.
- Word: per-record-type tables (summary, answer sets, country rollup, resolvers).
- Excel: per-record-type tables suitable for filtering and pivoting.

## Key knobs (DomainHealthCheck)

- `DnsPropagationRecordTypes` (default: `A`, `AAAA`)
- `DnsPropagationMaxServers` (default: `60`)
- `DnsPropagationMaxParallelism` (default: `20`)
- `DnsPropagationIncludeGeo` (default: `true`)
- `DnsPropagationMaxResultsToKeep` (default: `500`)

