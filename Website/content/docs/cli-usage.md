---
title: CLI Guide
description: Use the DomainDetective CLI for scripted checks, automation, and batch workflows.
slug: cli-usage
collection: docs
layout: docs
---

## Installation

```bash
dotnet tool install -g DomainDetective.CLI
```

## Basic Usage

```bash
# Check a domain
domaindetective check example.com

# Specific checks
domaindetective check example.com --checks SPF,DMARC,DKIM

# Summarize the default check set
domaindetective check example.com --summary
```

## Focused Commands

```bash
# RDAP registration details
domaindetective TestRDAP example.com

# DNS propagation snapshot
domaindetective DnsPropagation --domain example.com --record-type A

# Certificate inventory capture
domaindetective cert-inventory-capture example.com --include-ct-subdomains
```

## Output Formats

```bash
# JSON output
domaindetective check example.com --json

# Multiple domains
domaindetective check example.com contoso.com --summary
```
