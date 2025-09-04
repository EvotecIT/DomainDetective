# WHOIS Query Tuning

This document explains how DomainDetective queries WHOIS servers and how to tune retry/backoff behavior to accommodate strict or rate‑limited registries.

## Caching

- TLD → WHOIS server mappings are cached in‑memory for the lifetime of the process to avoid repeated discovery (via `whois-servers.net` and IANA fallbacks).
- The cache is per‑process and not persisted; there is no TTL eviction within a single run.
- Static built‑in mappings are merged with dynamically discovered mappings. Restart the process to clear dynamic mappings.

## Retries and Backoff

WHOIS queries may intermittently fail due to TCP resets, connection limits, or temporary blacklisting. DomainDetective uses bounded retries with exponential backoff and jitter.

You can tune these parameters via `WhoisAnalysis` properties:

- `MaxQueryRetries` (int, default 3): maximum number of TCP connect/query attempts per WHOIS request.
- `RetryBackoffBase` (TimeSpan, default 200 ms): base delay used in `base * 2^attempt` between retries.
- `RetryJitterMaxMs` (int, default 100): maximum random jitter (milliseconds) added to each backoff delay.

Example:

```csharp
var whois = new WhoisAnalysis {
    MaxQueryRetries = 5,
    RetryBackoffBase = TimeSpan.FromMilliseconds(500),
    RetryJitterMaxMs = 250
};
await whois.QueryWhoisServer("example.com");
```

Tip: Increase `RetryBackoffBase` and `MaxQueryRetries` when working with registries known for strict rate limits. If you continue to encounter throttling, consider adding sleeps between domain batches at the caller level.

## Timeouts

- The overall socket/connect/read timeout is governed by `WhoisAnalysis.Timeout` (default 30 seconds). Retries are performed within this budget via a linked cancellation token; if the timeout expires, the operation aborts.

## Notes

- Some registries enforce aggressive per‑IP limits. For high‑volume use, prefer RDAP endpoints where available.
- The project does not currently implement a TTL‑based eviction for the TLD → server cache. If you need to bypass cached server hints during a run, instantiate a new `WhoisAnalysis`.

