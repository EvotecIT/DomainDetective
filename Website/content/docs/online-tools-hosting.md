---
title: Online Tools Hosting
description: Build and host the DomainDetective website and online tools together.
slug: online-tools-hosting
collection: docs
layout: docs
---

DomainDetective ships two web-facing pieces:

- The static website under `Website`
- The Blazor tools app under `DomainDetective.Website`

Some tools run fully in the browser through DNS-over-HTTPS. Others need a hosted companion API because browsers cannot safely or reliably perform remote TLS handshakes or unrestricted cross-origin HTTP inspection.

## What the Host Does

`DomainDetective.OnlineHost` serves the built site and exposes same-origin `/tool-api` endpoints used by the online tools.

Today the hosted API is used for checks such as:

- HTTP headers
- `security.txt`
- certificate inspection
- MTA-STS policy retrieval
- RDAP registration lookups
- BIMI when the indicator/logo fetch needs server-side help

## Build the Site

From the repository root:

```powershell
pwsh ./Website/build.ps1 -Fast
```

That produces:

- `Website/_site` for the static website
- `Website/_site/tools` for the published Blazor tools app

## Run the Online Host

```powershell
dotnet run --project ./DomainDetective.OnlineHost/DomainDetective.OnlineHost.csproj --urls http://localhost:8097
```

Then browse:

- `http://localhost:8097/`
- `http://localhost:8097/tools/`
- `http://localhost:8097/tool-api/health`

## Deployment Notes

- Static hosting alone is not enough for the full online tools experience.
- If you deploy only `Website/_site` to GitHub Pages or another static host, the tools pages will load, but hosted checks will not have `/tool-api`.
- For production, serve the generated site through `DomainDetective.OnlineHost` or another app host/reverse proxy that exposes the same routes.

## Recommended Flow

1. Build the full site with `Website/build.ps1`.
2. Publish `DomainDetective.OnlineHost`.
3. Deploy the generated `Website/_site` output together with the host.
4. Keep the site and `/tool-api` on the same origin so the Blazor app can call the hosted analysis endpoints without extra CORS complexity.
