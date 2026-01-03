# Certificate Transparency Timeline (Discovery)

## What this check does

The CT Timeline check builds a time-series view of certificate issuance for a target domain using certificate transparency (CT) observations. It summarizes:

- First/last seen CT entry timestamps (UTC)
- Issuer diversity (unique certificates per issuer)
- Validity status (active/expired/not-yet-valid) based on `not_before`/`not_after` when provided
- Issuance velocity signals (last 7 / last 30 days)

Use this to spot unusual issuance patterns, potential mis-issuance, or rapid certificate churn.

## Data captured

- Query status: success/failure + reason (when available)
- CT observation counts:
  - total rows processed
  - unique certificates observed (deduped)
  - first/last seen timestamps (UTC)
- Issuer diversity:
  - issuer counts (unique certificates; best-effort based on CT payload)
- Validity posture:
  - active/expired/not-yet-valid counts (best-effort)
  - wildcard certificate counts
- Issuance velocity:
  - unique certificates issued in last 7 / 30 days (based on CT entry timestamp)
- Timeline buckets:
  - monthly buckets (year-month)
  - unique certificate counts
  - distinct issuer counts
- Recent certificate sample:
  - bounded list of most recent certificates with issuer, CN, validity status, and wildcard flag

## Controls / tuning

The primary implementation lives in `DomainDetective.CertificateTransparencyTimelineAnalysis`.

- `CrtShWildcardUrlTemplate`: CT query URL template for wildcard query (subdomains), default uses crt.sh.
- `CrtShExactUrlTemplate`: CT query URL template for exact-name query (apex-only certificates).
- `QueryOverride`: test/offline hook to supply CT JSON directly.

Performance / hygiene caps:

- `MaxCtRowsToProcess` (default: `10_000`): caps processed CT rows across all queries.
- `MaxUniqueCertificates` (default: `10_000`): caps the number of unique certificates tracked.
- `MaxTimelineBuckets` (default: `240`): caps the number of monthly buckets kept.
- `MaxRecentCertificates` (default: `200`): caps the number of recent-certificate sample rows.

When a cap is hit, `ResultsCapped` is set and an informational assessment is emitted.

## Output surfaces

- HTML report: renders a “CT Timeline” section (summary + findings + timeline buckets + recent sample + references).
- Word report: renders a “CT Timeline” section (summary + findings + evidence tables).
- Excel report (net8.0): renders a “CT Timeline” block (summary + timeline + recent sample tables).

## Notes and limitations

- CT data is an observation set, not a complete certificate inventory.
- Some CT rows may omit validity window fields; validity status is best-effort.
- Very large domains may hit caps; raise limits cautiously if needed.

