# DomainDetective CLI

An interactive command-line tool for comprehensive domain analysis and health checking, similar to MXToolbox but for the terminal.

## Features

### Interactive Wizard Mode
When you run the executable without any arguments, you'll enter an interactive wizard that provides:

- **🔍 Quick Domain Check** - Run essential health checks (MX, SPF, DMARC, DKIM, NS, CAA, DNSSEC)
- **🔬 Advanced Domain Analysis** - Complete analysis with all available checks
- **📊 Custom Test Selection** - Choose specific test categories:
  - Email Security (SPF, DKIM, DMARC, MX)
  - Security (CAA, DNSSEC, DANE)
  - DNS Health (NS, Delegation, Zone Transfer)
  - Reputation (DNSBL, Reverse DNS)
  - Connectivity (Port Scan, SMTP Banner, IMAP/POP3)
  - Advanced (Wildcard DNS, DNS Tunneling, IP Neighbors)
- **📧 Email Header Analysis** - Analyze email headers for authentication
- **🌐 WHOIS Lookup** - Query domain registration information
- **🔒 Certificate Analysis** - Check HTTPS certificates
- **🚀 DNS Propagation Check** - Monitor DNS changes across global resolvers
- **📝 Build DMARC Record** - Interactive DMARC policy builder

### Output Formats

The CLI supports multiple output formats:

1. **Console (Default)** - Rich formatted tables with color-coded results
2. **Table View** - Comprehensive tabular display with status indicators
3. **JSON** - Machine-readable JSON output for integration
4. **HTML Report** - Full HTML report with styling (can be opened in browser)

### Export Options

After analysis, you can:
- Export results to JSON file
- Generate HTML reports
- Open HTML reports directly in your browser

## Usage

This project is currently a standard .NET console application. It is not packaged in this repository as an installed `dotnet tool`, so examples below use either:

- `dotnet run --project DomainDetective.CLI -- ...` from source
- the app produced by `dotnet publish`

### Interactive Mode (Wizard)
From source:
```bash
dotnet run --project DomainDetective.CLI --
```

### Command Line Mode
For direct command execution:

```bash
# Quick domain check
dotnet run --project DomainDetective.CLI -- check example.com

# Output as JSON
dotnet run --project DomainDetective.CLI -- check example.com --json

# Check specific tests
dotnet run --project DomainDetective.CLI -- check example.com --checks SPF,DKIM,DMARC

# Desired State (custom baseline)
dotnet run --project DomainDetective.CLI -- DesiredState example.com --desired-state .\desired-state.json

# Desired State with best-practice gaps + export
dotnet run --project DomainDetective.CLI -- DesiredState example.com --desired-state .\desired-state.json --mode BestPracticesForUnspecified --format html --open

# Include additional checks
dotnet run --project DomainDetective.CLI -- check example.com --check-http --check-takeover

# Analyze email headers
dotnet run --project DomainDetective.CLI -- AnalyzeMessageHeader --file headers.txt

# Check DNS propagation
dotnet run --project DomainDetective.CLI -- DnsPropagation --domain example.com --record-type A

# WHOIS lookup
dotnet run --project DomainDetective.CLI -- Whois example.com
```

## Key Features

### Domain Health Checks
- **Email Configuration**: SPF, DKIM, DMARC, MX records
- **Security**: DNSSEC, CAA, DANE, Certificate validation
- **DNS Health**: NS records, delegation, zone transfers
- **Reputation**: DNSBL listings, reverse DNS
- **Connectivity**: Port scanning, SMTP/IMAP/POP3 TLS
- **Advanced**: DNS tunneling detection, wildcard DNS, IP neighbors

### Visual Indicators
- ✅ **Green** - Check passed successfully
- ⚠️ **Yellow** - Warning or minor issues
- ❌ **Red** - Failed check or critical issues
- 📊 Progress bars for long-running operations
- Color-coded output for easy scanning

### Rich Output Features
- Summary cards showing key metrics
- Detailed issue reporting with recommendations
- DNS propagation status across multiple resolvers
- Certificate chain validation details
- WHOIS data parsing and display

## Building from Source

```bash
# Restore dependencies
dotnet restore

# Build the project
dotnet build DomainDetective.CLI/DomainDetective.CLI.csproj

# Run the CLI
dotnet run --project DomainDetective.CLI --

# Publish an app folder
dotnet publish DomainDetective.CLI/DomainDetective.CLI.csproj -c Release -o ./artifacts/cli
```

Or use the repository build helper:

```powershell
pwsh ./Build/Publish-CLI.ps1
```

That script publishes runtime-specific CLI outputs under `Artifacts/ProjectBuild/CLI` and creates friendly aliases such as `DD.exe` on Windows and `DD` on Unix-like targets.

## Requirements

- .NET 8.0 Runtime
- Internet connection for DNS queries and web checks
- Administrator privileges may be required for some port scanning features

## Examples

### Interactive Wizard Flow
1. Launch without arguments
2. Select "Quick Domain Check" or "Advanced Analysis"
3. Enter domain(s) to analyze
4. Choose output format
5. View results with option to export

### Batch Processing
```bash
# Check multiple domains
dotnet run --project DomainDetective.CLI -- check domain1.com domain2.com domain3.com

# Export results to JSON
dotnet run --project DomainDetective.CLI -- check example.com --json > results.json
```

### Custom Test Selection
In the wizard, you can select specific test categories:
- Email Security tests only
- DNS health checks only
- Security-focused analysis
- Full comprehensive scan

## Output Examples

### Console Output
- Color-coded status indicators
- Hierarchical property display
- Issue highlighting with details
- Progress tracking for long operations

### JSON Output
Structured JSON with all analysis results, suitable for:
- Integration with other tools
- Automated monitoring systems
- Custom reporting solutions

### Word and PDF reports

`GenerateReport` (alias `report`) and `DesiredState` accept `html`, `word`, `pdf`, `excel`, `markdown`,
`markdownhtml` and `json`. Repeat `--format` or separate values with commas. Duplicates are removed while
preserving the requested order. Unknown formats fail before analysis.

```bash
dotnet run --project DomainDetective.CLI -- GenerateReport example.com --format word,pdf --output ./Reports/assessment.docx
dotnet run --project DomainDetective.CLI -- report example.com --format html --format pdf --theme dark --output ./Reports/assessment.html
dotnet run --project DomainDetective.CLI -- DesiredState example.com --desired-state ./desired-state.json --format word --format pdf --output ./Reports/baseline.docx
```

All formats use one assessment model; Word and PDF share one document build. A file supplied to `--output`
provides the base name and each format receives its own extension. GenerateReport writes its scan artifacts
once. The command returns failure if any requested report fails, while successful reports remain available.
In a multi-format batch, MarkdownHtml uses `<base>.markdown.html` with a `<base>.markdown.md` sidecar,
leaving `<base>.html` and `<base>.md` for HTML and Markdown. Single-format filenames are unchanged.

The default output is HTML. `--theme system|light|dark` applies to HTML, including HTML in a combined export;
other combinations require the default `system`. Only `--template default` is supported. Assessment reports
always include technical details and recommendations. There is no separate PDF switch.

### HTML Reports
- Professional styled reports
- Color-coded status sections
- Expandable detail sections
- Print-friendly formatting

## Contributing

The CLI is part of the DomainDetective project. For issues or feature requests, please visit the project repository.
