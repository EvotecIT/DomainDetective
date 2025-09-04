# Subject Conventions

This repository standardizes the Subject field across views to make dashboards, filtering, and output contracts consistent.

Guiding rules
- Domain scope: Subject is the domain name (e.g., example.com).
- Host:port scope: Subject is "host:port" when a single target is evaluated.
- Aggregate/multi-target: Subject is null.

Per-view policy
- PortScan: Subject = host (single-host scan by design).
- PortAvailability: Subject = "host:port" if exactly one target; otherwise null.
- MailLatency: Subject = "host:port" if exactly one target; otherwise null.
- DNSBL: Subject = domain when analysis is domain-scoped (e.g., domain + MX IPs); null for IP-only or multi-input runs. Per-host/IP evidence remains under HostSummaries/AllResults.

Notes
- JSON/CLI/PowerShell outputs surface the same Subject value; persona styling never alters it.
- For deep analysis, use the Raw property on each view.

