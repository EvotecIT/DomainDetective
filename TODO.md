# DomainDetective roadmap

Reviewed on 2026-10-04. This file tracks open work and qualification gaps. Completed historical checklist entries have been removed; the linked pull requests and current source are the evidence for implemented behavior. The status below describes source, not an installed module or published package.

## Standards and acceptance

| Area | Current source evidence | Remaining acceptance work |
| --- | --- | --- |
| DNSSEC-backed DANE | [DnsClientX DNSSEC #537](https://github.com/EvotecIT/DnsClientX/pull/537) and [DomainDetective DANE #1314](https://github.com/EvotecIT/DomainDetective/pull/1314) cover proof status and avoid treating a failed TLSA query as absence. | Qualify a real root-to-leaf DNSSEC chain and native Windows resolver policy. Model DANE-TA usage 2 path/name authentication separately from an association hash match. DomainDetective still pins DnsClientX 2.1.0; verify a public three-part DnsClientX release containing the fixes before upgrading that pin. |
| DNS transport and response fidelity | [DnsClientX transport #538](https://github.com/EvotecIT/DnsClientX/pull/538) is merged; [resolver contracts #539](https://github.com/EvotecIT/DnsClientX/pull/539) tracks presentation, bootstrap, policy isolation, and diagnostics. | Settle #539 on its current head. Qualify native NRPT/VPN behavior, live QUIC/HTTP/3, and quiet-host latency separately from loopback tests and controlled benchmarks. |
| SPF, DKIM, ARC, and DMARC policy | [Mail policy #1311](https://github.com/EvotecIT/DomainDetective/pull/1311) and [message authentication #1310](https://github.com/EvotecIT/DomainDetective/pull/1310) cover the reviewed RFC 7208, 6376, 8617, and 9989 contracts. | Exercise internationalized DKIM/ARC selectors with full EAI signed-message fixtures. Keep DNS failures distinct from policy absence in every new summary and report surface. |
| DMARC reports | [Report parsing #1312](https://github.com/EvotecIT/DomainDetective/pull/1312) covers the reviewed parsing defects. | Complete corpus qualification against RFC 9990 and RFC 9991, including real producer samples and size/resource limits. |
| RPKI and web policy | [RPKI #1308](https://github.com/EvotecIT/DomainDetective/pull/1308) and [web policy #1309](https://github.com/EvotecIT/DomainDetective/pull/1309) repair the reviewed state and policy interpretations. | Recheck external provider behavior when its documented contract changes; retain fixture evidence for failure and unknown states. |
| Report composition | [Portable validation #1315](https://github.com/EvotecIT/DomainDetective/pull/1315) and the other report changes have managed artifact checks. | Inspect native Word output for single-domain and multi-domain reports, including one-line introductions and References blocks. Complete cross-format parity checks before removing legacy paths. |

## Release integration

- [ ] Publish a public three-part DnsClientX version containing the merged DNSSEC and transport source fixes, plus any additional resolver contracts selected for that release, when package publication is authorized.
- [ ] Update the DnsClientX pin in `DomainDetective/DomainDetective.csproj` from 2.1.0 to that public version, then validate DomainDetective against the package rather than only a local source reference.
- [ ] Keep source, merged PR, package, and installed-module evidence distinct in release notes and support guidance.

## Protocol qualification

- [ ] Add a separately modeled DANE-TA certificate path/name outcome without requiring public PKIX trust for a private anchor.
- [ ] Qualify RFC 9990/9991 aggregate and failure reports with independent samples and bounded resource use.
- [ ] Qualify internationalized DKIM/ARC selectors through A-label lookup and real EAI message verification.

## Resolver and command surfaces

- [ ] Extend resolver lists and strategies to remaining CLI commands, with clear endpoint errors and bounded per-query/per-endpoint timeouts.
- [ ] Surface TTL and IPv6 preference where they change a supported resolver decision; keep the DNS implementation in DnsClientX.
- [ ] Decide whether CLI/PowerShell batch input and first-class CSV output improve workflows beyond existing piping; if so, define one shared core contract.
- [ ] Decide whether CLI DKIM selector overrides and worst-selector rollups belong in the current command surface.
- [ ] Consider a CLI option for the Word summary column cap; PowerShell already exposes `Set-DDExportOptions -SummaryColumnCap`.

## Report composition parity

The target is one factual section contract shared by Word, Markdown, HTML, and Excel. Profiles may change layout, but must not change a section's status, findings, positives, references, or subject scope.

- [ ] Complete the Word golden-report pass for single-domain and multi-domain documents; check introductions, References, and native visual layout.
- [ ] Define a small shared report schema for header, executive-summary rows, provider chain, per-domain sections, and consistent severity rollups. Keep format-specific evidence tables where they help readers.
- [ ] Align the Document outline across Word, Markdown, and HTML: front matter, contents, executive summary, providers, per-domain sections, and references. Check heading levels and anchor targets.
- [ ] Make HTML Dashboard and Excel Dashboard use the same summary facts as their Document/Workbook profiles; add presentation components only where their current consumers need them.
- [ ] Add an in-memory parity fixture for a curated domain set across Word, Markdown, HTML Document/Dashboard, and Excel Workbook/Dashboard. Compare section facts and counts with a readable test diff, not generated CSV/JSON snapshots.
- [ ] Check PowerShell `Export-DDSecurityReport` profile wiring and the intended presentation differences. Keep meaningful accessibility and navigation assertions when updating UI tests.
- [ ] After parity is proven, remove superseded view-only renderers, then update public examples and help from the actual composition entry points.

## Discovery and operations

- [ ] Evaluate portfolio drift and discovery snapshots through the canonical storage owner before adding another repository-local store.
- [ ] Decide whether scheduled audits need local run history, alert thresholds, and a bounded export format before designing a monitoring service.

## Candidate features requiring product validation

These are ideas from the earlier roadmap, not claims that current code lacks them. Verify the user workflow and existing implementation before scheduling code work.

- RDAP-first registrar/domain information with a bounded WHOIS fallback and structured status semantics.
- Enforcement-readiness summaries for DMARC and MTA-STS/TLS-RPT, based on real evidence rather than a score inferred from configuration alone.
- Per-MX STARTTLS coverage and certificate-path evidence in reports.
- Consistent CLI/PowerShell branding, posture summaries, batch presets, and report-profile options.
- Optional HTTP uptime and latency history, waterfall evidence, drift alerts, and transaction monitoring after the core analysis contracts are stable.
- A development-only provider-documentation verifier: check only an approved vendor-domain list; use HEAD with GET fallback, at most three redirects, and an age gate; report failed links and suggested same-domain replacements in one JSON artifact. It must never run during end-user commands.
