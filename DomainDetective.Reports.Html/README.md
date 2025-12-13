# DomainDetective HTML Reports

This library provides HTML report generation for DomainDetective using HtmlForgeX.

## Usage

### Basic Report
```csharp
var healthCheck = new DomainHealthCheck();
await healthCheck.CheckDomainHealthAsync("example.com");

var report = new BasicDomainReport(healthCheck, "example.com");
report.GenerateReport("report.html", openInBrowser: true);
```

### Simple Report with Scoring
```csharp
var report = new SimpleDomainReport(healthCheck, "example.com");
report.GenerateReport("report.html");
```

### Advanced Security Report
```csharp
var report = new DomainSecurityReport(healthCheck, "example.com");
report.GenerateReport("security-report.html");
```

## Report Types

1. **BasicDomainReport** - Simple overview of domain configuration
2. **SimpleDomainReport** - Includes scoring and recommendations
3. **DomainSecurityReport** - Comprehensive report with categories, detailed scoring, and visualizations

## Features

- 🎯 Security scoring system (0-100)
- 📊 Category-based analysis (Impersonation, Privacy, Branding, Infrastructure)
- 🎨 Beautiful UI using Tabler components
- 📱 Responsive design
- 🚀 No JavaScript/CSS knowledge required
- 🔧 Fully customizable through C# API

## Dependencies

- HtmlForgeX 0.4.0
- DomainDetective
- DomainDetective.Reports
