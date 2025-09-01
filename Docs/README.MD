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
