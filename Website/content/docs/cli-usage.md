---
title: CLI Usage
description: Using the DomainDetective command-line interface.
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
domaindetective check example.com --spf --dmarc --dkim

# All checks
domaindetective check example.com --all
```

## Output Formats

```bash
# JSON output
domaindetective check example.com --format json

# Table output (default)
domaindetective check example.com --format table
```

## Batch Processing

```bash
# From a file
domaindetective batch domains.txt --spf --dmarc

# From stdin
echo "example.com" | domaindetective batch --spf
```
