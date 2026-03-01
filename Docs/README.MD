# DomainDetective Documentation

## Documentation Structure

### 1. [ARCHITECTURE.MD](ARCHITECTURE.MD)
Technical architecture and design principles for the HTML reporting system.

### 2. [PROJECT_STRUCTURE.MD](PROJECT_STRUCTURE.MD)
Organization of the reporting system code and components.

### 3. [REPORTING_USAGE.MD](REPORTING_USAGE.MD)
User guide for generating reports via CLI, PowerShell, and C# library.

### 4. [HTTP_POSTURE.MD](HTTP_POSTURE.MD)
HTTP posture and security header checks (request options, output surfaces, dashboards).

### 5. [IP_ENRICHMENT.MD](IP_ENRICHMENT.MD)
IP enrichment (ASN/org, geo, reverse DNS) and reporting surfaces.

### 6. [CT_TIMELINE.MD](CT_TIMELINE.MD)
Certificate transparency timeline (issuance velocity, issuer diversity, validity posture).

### 7. [SUBDOMAINS.MD](SUBDOMAINS.MD)
CT-backed subdomain discovery (bounded + optional DNS verification).

### 8. [DNS_PROPAGATION.MD](DNS_PROPAGATION.MD)
Multi-resolver DNS propagation visibility with map visualization and rollups.

### 9. [DESIRED_STATE.MD](DESIRED_STATE.MD)
Custom baselines (desired state configuration) for drift/non-conformance detection.

### 10. [CERTIFICATE_INVENTORY.MD](CERTIFICATE_INVENTORY.MD)
End-to-end certificate inventory/discovery usage (live capture, snapshots, risk/drift/policy) with PowerShell and C# examples.

## Main TODO
The comprehensive TODO for the reporting system is located at:
**[../TODO.md](../TODO.md)**

This includes:
- Detailed implementation phases
- Unified per-cmdlet export switches (-ExportFormat, -ExportPath, -OpenInBrowser)
- Progress tracking integration
- All protocol coverage including SPF flattening, RDAP, DNSBL, etc.
- HtmlForgeX component utilization
- Library separation strategy

## Quick Reference

### PowerShell Cmdlets (Export Pattern)
- `Test-DDDomainOverallHealth` - Health + report export (-Export*)
- `Test-DDEmailSpfRecord` - SPF (export switches available; report TODO)
- `Test-DDEmailDmarcRecord` - DMARC (export switches available; report TODO)
- `Test-DDEmailDkimRecord` - DKIM (export switches available; report TODO)
- Other `Test-*` cmdlets include the same export switches for future reports

### Report Formats
- HTML (interactive, default)
- PDF (static document)
- Word (editable document)
- Excel (data analysis)
- Markdown (documentation)
- JSON (data export)

### Key Features
- Real-time progress tracking during scans
- Scoring system based on industry standards
- Interactive visualizations using HtmlForgeX
- Offline-capable with CDN fallbacks
- Multi-language support (planned)
- Customizable templates and themes
