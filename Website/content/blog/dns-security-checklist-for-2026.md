---
title: DNS Security Checklist for 2026
description: A comprehensive checklist covering DNSSEC, CAA records, DANE, and other DNS security measures every domain should implement.
slug: dns-security-checklist-for-2026
date: 2026-02-28
categories: ["Checklist"]
tags: ["dns", "dnssec", "security", "caa"]
collection: blog
layout: page
---

## DNS Security in 2026

DNS remains a critical attack surface. From cache poisoning to subdomain takeover, the threats continue to evolve. Here's a comprehensive checklist to ensure your domain's DNS infrastructure is properly secured.

## The Checklist

### Email Authentication
- [ ] SPF record with `-all` enforcement
- [ ] DKIM signing on all outbound mail
- [ ] DMARC at `p=reject` (or `p=quarantine` minimum)
- [ ] MTA-STS policy published
- [ ] TLS-RPT reporting configured
- [ ] BIMI record (optional, for brand visibility)

### DNS Infrastructure
- [ ] DNSSEC enabled and validated
- [ ] NS records point to at least 2 nameservers
- [ ] SOA record with reasonable TTLs
- [ ] No dangling CNAME records (subdomain takeover risk)

### Certificate Security
- [ ] CAA records restricting certificate issuers
- [ ] DANE/TLSA records for mail servers
- [ ] Certificate Transparency monitoring

### Web Security
- [ ] HTTP security headers (CSP, HSTS, X-Frame-Options)
- [ ] security.txt file published
- [ ] HSTS preload list submission

### Threat Intelligence
- [ ] Domain not listed on any DNSBL
- [ ] RDAP/WHOIS contact info up to date
- [ ] Regular subdomain enumeration via CT logs

## Automate with DomainDetective

Run all these checks with a single command:

```bash
domaindetective check example.com --all
```

Or use the [online tools](/tools/) to check each item individually - all analysis runs client-side in your browser.
