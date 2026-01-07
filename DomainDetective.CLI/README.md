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

### Interactive Mode (Wizard)
Simply run the executable without arguments:
```bash
DomainDetective.CLI.exe
```

### Command Line Mode
For direct command execution:

```bash
# Quick domain check
DomainDetective.CLI.exe check example.com

# Output as JSON
DomainDetective.CLI.exe check example.com --json

# Check specific tests
DomainDetective.CLI.exe check example.com --checks SPF,DKIM,DMARC

# Desired State (custom baseline)
DomainDetective.CLI.exe DesiredState example.com --desired-state .\desired-state.json

# Desired State with best-practice gaps + export
DomainDetective.CLI.exe DesiredState example.com --desired-state .\desired-state.json --mode BestPracticesForUnspecified --format html --open

# Include additional checks
DomainDetective.CLI.exe check example.com --check-http --check-takeover

# Analyze email headers
DomainDetective.CLI.exe AnalyzeMessageHeader --file headers.txt

# Check DNS propagation
DomainDetective.CLI.exe DnsPropagation --domain example.com --record-type A

# WHOIS lookup
DomainDetective.CLI.exe Whois example.com
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
dotnet build DomainDetective.CLI.csproj

# Run the CLI
dotnet run --project DomainDetective.CLI.csproj
```

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
DomainDetective.CLI.exe check domain1.com domain2.com domain3.com

# Export results to JSON
DomainDetective.CLI.exe check example.com --json > results.json
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

### HTML Reports
- Professional styled reports
- Color-coded status sections
- Expandable detail sections
- Print-friendly formatting

## Contributing

The CLI is part of the DomainDetective project. For issues or feature requests, please visit the project repository.
