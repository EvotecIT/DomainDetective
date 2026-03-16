---
title: Frequently Asked Questions
description: Common questions about DomainDetective.
slug: faq
collection: pages
layout: page
---

## General

### What is DomainDetective?

DomainDetective is a comprehensive domain analysis toolkit that supports 115+ protocol checks. It's available as a C# library, PowerShell module, and CLI tool, with online browser-based tools.

### Is it free?

Yes. DomainDetective is open source and MIT licensed.

### Does the online tool store my data?

No. All analysis runs entirely in your browser using WebAssembly. DNS queries go directly from your browser to Cloudflare's DNS-over-HTTPS endpoint. Nothing is stored on our servers.

## Technical

### How do browser-based DNS queries work?

The online tools use DNS-over-HTTPS (DoH) via Cloudflare's wire format endpoint. Your browser sends HTTPS requests to `cloudflare-dns.com` to resolve DNS records, bypassing the need for raw socket access.

### Which tools don't work in the browser?

Tools requiring direct TCP/UDP socket connections (SMTP, IMAP, POP3, port scanning, ping, traceroute, zone transfer, DNS-over-TLS) are desktop-only. These are marked as "Desktop Only" in the tools list.

### What .NET versions are supported?

- .NET Framework 4.7.2 (Windows PowerShell)
- .NET 8.0 (cross-platform)
- .NET 10.0 (latest)

## Contributing

### How can I contribute?

Visit the [GitHub repository](https://github.com/EvotecIT/DomainDetective) to report issues, suggest features, or submit pull requests.
