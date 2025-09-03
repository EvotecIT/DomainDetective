# DomainDetective Enhanced Reporting System - TODO

## 🔍 Assessment of Current State

### Current Implementation
- Basic HTML reports with simple layouts (BasicDomainReport, SimpleDomainReport, DomainSecurityReport)
- Limited visual appeal - mostly text-based data grids
- Basic scoring system (0-100) with simple risk levels
- No interactive elements or deep-dive capabilities
- No charting or visual representations
- Limited export options (HTML only in current reports)
- No multi-language support
- No integration with PowerShell/CLI for report generation

### HtmlForgeX Capabilities Available
- **DataGrid**: Advanced data display with badges, status indicators, avatars, icons
- **InfoCards**: Beautiful colorful cards with custom backgrounds and progress bars
- **DataTables**: Interactive tables with search, export (Excel, PDF), pagination
- **Charts**: Various chart types for visual data representation
- **Smart Wizard**: Step-by-step guides for remediation
- **VisNetwork**: Network graphs for relationship visualization
- **Tabler Components**: Full UI framework with responsive design
- **Code Highlighting**: For displaying DNS records with syntax highlighting

### Competitor Analysis (from Demo screenshots)
- **SENDMARC**: Category-based scoring (Impersonation, Privacy, Branding), visual score gauges
- **Mailhardener**: Detailed protocol breakdowns, DNS record syntax highlighting, implementation guides

## 📋 Comprehensive Proposal

### Phase 1: Core Report Architecture
- [ ] Create new report base classes in `DomainDetective.Reports.Html.Advanced/`
- [ ] Implement report theme system (Light, Dark, Professional, Compact)
- [ ] Create report template engine for customizable layouts
- [ ] Implement multi-format export infrastructure (HTML, PDF, Word, Excel, Markdown)
- [ ] Add report metadata system for tracking generation details
- [ ] **Scoring Engine Implementation** (from Docs/TODO.MD)
  - [ ] Create DomainSecurityScore class with categories
  - [ ] Implement scoring weights:
    - [ ] SPF: 15 points
    - [ ] DMARC: 20 points
    - [ ] DKIM: 15 points
    - [ ] DNSSEC: 10 points
    - [ ] TLS/SSL: 15 points
    - [ ] MTA-STS: 10 points
    - [ ] DANE: 5 points
    - [ ] BIMI: 5 points
    - [ ] Security Headers: 5 points
  - [ ] Define risk thresholds and category calculations

### Phase 2: Visual Dashboard Design
- [ ] **Progress Log Display**
  - [ ] Use HtmlForgeX Logs component for scan progress
  - [ ] Collapsible log viewer showing all checks performed
  - [ ] Timestamp, duration, and status for each step
  - [ ] Color-coded log entries (info, warning, error)
  - [ ] Search/filter capability within logs
  - [ ] Export logs as separate text file
- [ ] **Executive Summary Dashboard**
  - [ ] Overall security score gauge (0-100) with animated progress
  - [ ] Risk level indicator with color coding (Critical/High/Medium/Low)
  - [ ] Category scores using InfoCards:
    - [ ] 🛡️ **Impersonation Protection** (SPF, DKIM, DMARC) - Purple (#8B5CF6)
    - [ ] 🔒 **Privacy & Encryption** (TLS, MTA-STS, DANE) - Blue (#3B82F6)
    - [ ] 🏆 **Brand Protection** (BIMI, Certificate) - Green (#10B981)
    - [ ] 🖥️ **Infrastructure** (DNS, MX, NS, DNSSEC) - Orange (#F59E0B)
  - [ ] Quick stats row (Total Checks, Passed, Warnings, Failed)
  - [ ] Trend chart showing score history (if available)
- [ ] **Visual Components** (from Docs/TODO.MD)
  - [ ] Score Card Component with circular progress
  - [ ] Security Matrix grid view with color-coded status
  - [ ] Recommendation Engine with prioritized actions
  - [ ] Interactive tooltips and collapsible sections

### Phase 3: Protocol Analysis Components
- [ ] **SPF Analysis Section**
  - [ ] DNS record display with syntax highlighting (using CSharpCode component)
  - [ ] Record breakdown table (mechanism, value, service logo, description)
  - [ ] Flatten SPF visualization showing all included domains
  - [ ] Network graph showing SPF include chain (using VisNetwork)
  - [ ] Common issues warnings with severity badges
  - [ ] Implementation checklist with progress tracking

- [ ] **DMARC Analysis Section**
  - [ ] Policy overview cards (Current Policy, Alignment Mode, Reporting)
  - [ ] DNS record with syntax highlighting
  - [ ] Tag breakdown DataGrid with explanations
  - [ ] Report destination validation status
  - [ ] Policy progression roadmap (none → quarantine → reject)
  - [ ] Sample DMARC report preview

- [ ] **DKIM Analysis Section**
  - [ ] Selector discovery results table
  - [ ] Key strength indicators with badges
  - [ ] DNS record display for each selector
  - [ ] Key rotation recommendations
  - [ ] Implementation guide with selector naming best practices

- [ ] **Email Infrastructure**
  - [ ] MX record priority table with TLS support indicators
  - [ ] MTA-STS policy display with mode badges
  - [ ] TLS certificate chain visualization
  - [ ] DANE/TLSA record analysis
  - [ ] Email flow diagram showing security checkpoints

- [ ] **DNS Security**
  - [ ] DNSSEC chain of trust visualization
  - [ ] DS record details with algorithm info
  - [ ] Name server geographic distribution map
  - [ ] CAA record policy display
  - [ ] DNS response time metrics

### Phase 4: Interactive Features
- [ ] **Remediation Wizard** (using Smart Wizard)
  - [ ] Step 1: Issue selection and prioritization
  - [ ] Step 2: DNS record generation with copy buttons
  - [ ] Step 3: Testing commands and verification
  - [ ] Step 4: Monitoring setup instructions
  - [ ] Step 5: Next steps and timeline

- [ ] **Security Timeline**
  - [ ] Visual timeline showing when to implement each protocol
  - [ ] Dependencies between protocols
  - [ ] Estimated effort indicators
  - [ ] Risk reduction impact for each step

- [ ] **Comparison Mode**
  - [ ] Side-by-side domain comparison
  - [ ] Industry benchmark comparison
  - [ ] Historical comparison (before/after)
  - [ ] Competitor analysis mode

### Phase 5: Deep Dive Analysis
- [ ] **Detailed Test Results** (using DataTables)
  - [ ] Comprehensive test matrix with filters
  - [ ] Column: Test Category, Check Name, Status, Score Impact, Details
  - [ ] Export options (Excel, PDF)
  - [ ] Search and filter by status/category
  - [ ] Inline expandable details for each test

- [ ] **Raw Data Explorer**
  - [ ] Tabbed interface for raw DNS queries
  - [ ] JSON viewer for API responses
  - [ ] Network request timeline
  - [ ] Query performance metrics

- [ ] **Security Headers Analysis**
  - [ ] HTTP security headers check
  - [ ] CSP policy analyzer
  - [ ] Cookie security assessment
  - [ ] HSTS configuration review

### Additional Analysis (from Demo/Pages parity)
- [ ] **HTTPS/TLS (Web) Analysis**
  - [ ] Certificate chain/hostname validation, expiry, key size
  - [ ] Protocol/cipher support (TLS1.0–1.3) and weak/deprecated flags
  - [ ] ALPN detection (h2/h3), OCSP stapling presence, SCT count
  - [ ] Compute web TLS letter grade (A/B/C/D/F) aligned with Mail TLS

- [ ] **Mixed‑Content Audit**
  - [ ] Parse homepage (size/time‑boxed) for http:// resources and insecure form posts
  - [ ] Summarize counts and provide examples + remediation

- [ ] **Website Blacklist Aggregator**
  - [ ] Pluggable providers (OpenPhish, PhishTank, URLHaus; optional Google Safe Browsing)
  - [ ] Caching/backoff and per‑provider evidence in the view

- [ ] **DNS Health Deep Checks**
  - [ ] NS recursion disabled, AXFR exposure test
  - [ ] Glue/in‑bailiwick validation, A/AAAA consistency across NS
  - [ ] SOA serial skew and TTL uniformity across common RRsets

- [ ] **Mail Hardening Extras**
  - [ ] MTA‑STS policy detection and validation
  - [ ] TLSRPT endpoint checks
  - [ ] DANE/TLSA validation for MX

### Phase 6: PowerShell Integration
- [ ] Unified per-cmdlet export switches
  - [x] Add `-ExportFormat` (enum), `-ExportPath`, `-OpenInBrowser` to all Test-* cmdlets
  - [x] Add same switches to key Get-* cmdlets where sensible (e.g., RDAP, headers)
  - [x] Provide `Set-DDExportOptions` for module-wide defaults
  - [ ] Implement dedicated reports per area (DMARC, DKIM, SPF, DNSSEC, MX, etc.)

- [ ] Output conventions
  - [x] DomainOverallHealth returns a View object with `.Raw` (no `-Raw`/`-Summary`)
  - [ ] Convert remaining Test-* cmdlets to return typed View objects with `.Raw`
  - [ ] Ensure cmdlets emit the View to pipeline first, then run export (no pipeline loss)

- [ ] Pipeline Support
  - [ ] `Test-DDEmailSpfRecord -Domain example.com -ExportFormat Html` (report TODO)
  - [ ] `Test-DDEmailDmarcRecord -Domain example.com -ExportFormat Html` (report TODO)
  - [ ] `Test-DDDomainOverallHealth -Domain $domains -ExportFormat Html`

- [ ] Parameters
  - [x] `-ExportFormat` - Html, Pdf, Excel, Word, Json (enum)
  - [x] `-OpenInBrowser` - Open HTML in browser (default via Set-DDExportOptions)
  - [x] `-ExportPath` - Output file path
  - [ ] Templates/Themes configurable centrally (future)
  - [x] Raw data always included in artifacts; IncludeRecommendations (future)

### Phase 7: CLI Integration
- [ ] **CLI Commands**
  - [ ] `domain-detective report generate` - Generate reports
  - [ ] `domain-detective report template list` - List templates
  - [ ] `domain-detective report serve` - Local web server for reports
  - [ ] `domain-detective runs list` - List recent artifact runs from `index.jsonl`
  - [ ] `domain-detective runs open --last` - Open last run report/artifacts

- [ ] **Interactive Mode**
  - [ ] Report configuration wizard
  - [ ] Template selection menu
  - [ ] Export format picker
  - [ ] Batch processing support

### Phase 8: Advanced Features
- [ ] **Multi-Language Support**
  - [ ] Localization infrastructure
  - [ ] Language packs (EN, ES, FR, DE, JP)
  - [ ] RTL layout support
  - [ ] Culturally appropriate examples

- [ ] **Report Scheduling**
  - [ ] Automated report generation
  - [ ] Email delivery integration
  - [ ] Change detection alerts
  - [ ] Weekly/Monthly summaries

- [ ] **API Integration**
  - [ ] RESTful API for report generation
  - [ ] Webhook support for CI/CD
  - [ ] Report storage backend
  - [ ] Access control system

### Phase 9: Specialized Reports
- [ ] **Compliance Reports**
  - [ ] GDPR compliance checklist
  - [ ] SOC 2 requirements mapping
  - [ ] Industry-specific standards (HIPAA, PCI-DSS)
  - [ ] Audit trail documentation

- [ ] **Executive Reports**
  - [ ] High-level summary only
  - [ ] Risk assessment focus
  - [ ] Cost-benefit analysis
  - [ ] Vendor comparison

- [ ] **Technical Deep Dive**
  - [ ] Full protocol specifications
  - [ ] Implementation code samples
  - [ ] Debugging information
  - [ ] Performance metrics

### Phase 10: Visual Enhancements
- [ ] **Color Schemes**
  - [ ] Status colors: Success (#10B981), Warning (#F59E0B), Error (#EF4444)
  - [ ] Category colors as defined in Phase 2
  - [ ] Accessibility-compliant palettes
  - [ ] Dark mode optimized colors

- [ ] **Icons and Graphics**
  - [ ] Protocol-specific icons
  - [ ] Service provider logos
  - [ ] Status indicators
  - [ ] Progress animations

- [ ] **Responsive Design**
  - [ ] Mobile-optimized layouts
  - [ ] Tablet-friendly navigation
  - [ ] Print-optimized styles
  - [ ] Email-safe HTML version

### Phase 11: Data Collection and Progress Tracking
- [ ] **Scan Progress Integration**
  - [ ] Capture all InternalLogger events
  - [ ] Store with timestamps and categories
  - [ ] Calculate step durations
  - [ ] Identify slow operations
  - [ ] Show progress percentage

- [ ] **Performance Metrics**
  - [ ] DNS query response times
  - [ ] Total scan duration
  - [ ] Parallel vs sequential operations
  - [ ] Network latency impact
  - [ ] Resource usage stats

- [ ] **Historical Data**
  - [ ] Store scan results with timestamps
  - [ ] Compare current vs previous scans
  - [ ] Trend analysis over time
  - [ ] Change detection alerts
  - [ ] Improvement tracking

## 🚀 Implementation Priority

### Immediate (Week 1-2)
1. [ ] Implement progress capture in DomainHealthCheck
2. [ ] Create base report classes with progress support
3. [ ] Implement executive dashboard with logs
4. [ ] Add SPF detailed analysis with flattening

### Short Term (Week 3-4)
1. [ ] Complete all protocol analysis sections
2. [ ] Add interactive DataTables
3. [ ] Implement PowerShell cmdlets
4. [ ] Create first export formats (HTML, PDF)

### Medium Term (Month 2)
1. [ ] Add remediation wizard
2. [ ] Implement comparison features
3. [ ] Complete all export formats
4. [ ] Add CLI integration

### Long Term (Month 3+)
1. [ ] Multi-language support
2. [ ] API development
3. [ ] Specialized report types
4. [ ] Advanced visualizations

## 📊 Success Metrics
- [ ] Report generation time < 2 seconds
- [ ] All reports score 100/100 on accessibility
- [ ] Support for domains with 50+ DNS records
- [ ] Export file sizes optimized (HTML < 1MB)
- [ ] Mobile responsive score > 95%

## 🛠️ Technical Requirements
- [ ] Zero external dependencies for offline use
- [ ] Async report generation
- [ ] Streaming support for large datasets
- [ ] Template caching system
- [ ] Report versioning
- [ ] **Performance Goals** (from Docs/TODO.MD)
  - [ ] Sub-second report generation for single domain
  - [ ] Efficient HTML generation with lazy loading
  - [ ] Optimized asset bundling
  - [ ] Minimal external dependencies

## 📝 Documentation Needs
- [ ] Report template creation guide (future)
- [ ] PowerShell examples for per-cmdlet export switches
- [ ] CLI usage documentation
- [ ] API reference
- [ ] Localization guide
- [ ] Progress tracking implementation guide
- [ ] Custom log handler examples

## 🧪 Testing Strategy
- [ ] Unit tests for each report component
- [ ] Visual regression tests
- [ ] Performance benchmarks
- [ ] Accessibility audits
- [ ] Cross-browser testing

## 🔄 Migration Plan
- [ ] Maintain backward compatibility
- [ ] Provide migration cmdlets
- [ ] Document breaking changes
- [ ] Gradual deprecation of old reports

## 🎯 Success Criteria (from Docs/TODO.MD)
- [ ] Clean, modern UI comparable to SendMarc/EasyDMARC
- [ ] Sub-second report generation for single domain
- [ ] 90%+ test coverage
- [ ] Positive user feedback on usability
- [ ] Extensible architecture for future enhancements
- [ ] PowerShell export switches in Test-* cmdlets
- [ ] CLI Integration: ddcli example.com --html-report --template executive

This comprehensive plan transforms DomainDetective's reporting from basic text output to a professional, interactive, and insightful security analysis platform that rivals commercial solutions while maintaining the flexibility of open-source software.
## Cross-Cutting: Progress & Persona

- [ ] Add PowerShell progress sink with persona (Write-Verbose/Warning tone)
- [ ] Add Spectre.Console sink for CLI persona
- [ ] Centralize InternalLogger event fan-out (extends ProgressHub if needed)

## Documentation & Schema

- [ ] Document artifact schema (scan.json, metrics.json, progress.jsonl, index.jsonl)
- [ ] Provide sample artifacts and a data dictionary
- [ ] Quickstart on consuming `index.jsonl`
