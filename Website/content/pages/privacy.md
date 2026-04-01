---
title: Privacy Policy
description: DomainDetective privacy policy - how we handle your data.
slug: privacy
collection: pages
layout: page
---

## Privacy First

DomainDetective is designed with privacy as a core principle.

### Online Tools

When you use the online tools at `/tools/`:

- DNS-heavy analysis runs in your browser using WebAssembly (Blazor WASM)
- DNS queries are sent via DNS-over-HTTPS to public resolvers
- Advanced HTTP and TLS checks may use the hosted DomainDetective analysis API because browsers cannot reliably inspect remote certificates or unrestricted cross-origin responses
- **No analysis results are stored on our servers**
- **No analytics or tracking** is used on the tools pages
- Results are returned to your browser session and are not persisted

### Static Website

The documentation and marketing pages are static HTML served via GitHub Pages. No cookies or tracking scripts are used.

### Third-Party Services

- **Public DNS-over-HTTPS resolvers**: DNS queries from browser tools are resolved via public DoH endpoints such as Cloudflare and Google
- **Google Fonts**: Font files are loaded from Google Fonts CDN
- **GitHub Pages**: The site is hosted on GitHub Pages

### Contact

For privacy questions, open an issue on [GitHub Issues](https://github.com/EvotecIT/DomainDetective/issues).
