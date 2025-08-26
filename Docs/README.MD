# DomainDetective Documentation

## Documentation Structure

### 1. [ARCHITECTURE.MD](ARCHITECTURE.MD)
Technical architecture and design principles for the HTML reporting system.

### 2. [PROJECT_STRUCTURE.MD](PROJECT_STRUCTURE.MD)
Organization of the reporting system code and components.

### 3. [REPORTING_USAGE.MD](REPORTING_USAGE.MD)
User guide for generating reports via CLI, PowerShell, and C# library.

## Main TODO
The comprehensive TODO for the reporting system is located at:
**[TODO.MD](TODO.MD)**

This includes:
- Detailed implementation phases
- PowerShell cmdlet specifications (Show-* pattern)
- Progress tracking integration
- All protocol coverage including SPF flattening, RDAP, DNSBL, etc.
- HtmlForgeX component utilization
- Library separation strategy

## Quick Reference

### PowerShell Cmdlets (New Pattern)
- `Test-DDDomainOverallHealth` - Health + report export (-Export*)
- `Show-DDEmailSpfReport` - SPF-specific reports
- `Show-DDEmailDmarcReport` - DMARC-specific reports
- `Show-DDEmailDkimReport` - DKIM-specific reports
- `Show-DDDnsSecurityReport` - DNS security reports
- `Show-DDTlsReport` - TLS/encryption reports
- `Show-DDReputationReport` - Blacklist/reputation reports

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