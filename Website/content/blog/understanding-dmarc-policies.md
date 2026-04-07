---
title: Understanding DMARC Policies - None, Quarantine, and Reject
description: A practical guide to DMARC policy levels, how they work with SPF and DKIM, and how to safely move from monitoring to enforcement.
slug: understanding-dmarc-policies
date: 2026-03-05
categories: ["Guide"]
tags: ["dmarc", "email-security", "policy"]
collection: blog
layout: page
---

## What is DMARC?

Domain-based Message Authentication, Reporting, and Conformance (DMARC) builds on SPF and DKIM to give domain owners control over how receiving mail servers handle messages that fail authentication checks.

## The Three Policy Levels

### `p=none` - Monitor Mode

The starting point for DMARC deployment. Messages that fail authentication are delivered normally, but reports are sent to the domain owner. Use this to discover all legitimate email sources before enforcing.

### `p=quarantine` - Suspicious Treatment

Failed messages are treated as suspicious - typically sent to spam/junk folders. This is a safe intermediate step before full enforcement.

### `p=reject` - Full Enforcement

Failed messages are rejected outright. This is the recommended end state for maximum protection against email spoofing.

## Analyzing DMARC with DomainDetective

```powershell
$results = Test-DomainHealth -DomainName "example.com" -HealthCheckType DMARC
$dmarc = $results.DmarcAnalysis

# Check current policy
$dmarc.Policy        # none, quarantine, or reject
$dmarc.SubdomainPolicy
$dmarc.Percentage    # What % of mail the policy applies to
$dmarc.ReportingUris # Where aggregate reports are sent
```

## DMARC Deployment Checklist

1. Deploy SPF and DKIM first
2. Set `p=none` with reporting (`rua=mailto:...`)
3. Monitor reports for 2-4 weeks
4. Identify and authorize all legitimate senders
5. Move to `p=quarantine` with `pct=10`, gradually increase
6. Once confident, set `p=reject`

Use our [DMARC Lookup tool](/tools/dmarc/) to validate your configuration at each step.
