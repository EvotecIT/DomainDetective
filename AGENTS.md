# DomainDetective

C# domain, DNS, email, web and certificate security analysis toolkit (SPF,
DMARC, DKIM, MTA-STS, DNSSEC, RDAP, RPKI, DNSBL and more), with a CLI, a
PowerShell module, HTML/Markdown/Office reports and a website with online tools.

## Layout

- `DomainDetective/`: the core library. `DomainDetective.Generators/` is its
  source generator; `DomainDetective.Pgp/`, `DomainDetective.CtSql/` and
  `DomainDetective.Visual/` are add-ons.
- `DomainDetective.Reports/` with `.Html/`, `.Markdown/` and `.Office/`: report
  generators.
- `DomainDetective.CLI/`: the CLI. `DomainDetective.PowerShell/` and `Module/`:
  binary cmdlets, manifest, build, Pester tests and generated docs.
- Website: `Website/` (static PowerForge site), `DomainDetective.Website/`
  (Blazor WebAssembly tools app), `DomainDetective.Toolbox/` (shared tool
  components), `DomainDetective.OnlineHost/` (hosted `/tool-api`).
- Tests: `DomainDetective.Tests/`, `DomainDetective.CLI.Tests/`,
  `DomainDetective.CtSql.Tests/`, `DomainDetective.Website.Tests/` (xUnit),
  `Module/Tests/` (Pester).
- `Data/`: rule packs, provider lists and reference data shipped with the library.
- `Docs/`: feature notes and conventions. `Scripts/`: data refresh.

## Build and test

```powershell
dotnet build DomainDetective.sln -c Release
dotnet test DomainDetective.Tests/DomainDetective.Tests.csproj -c Release -f net10.0
dotnet test DomainDetective.CLI.Tests/DomainDetective.CLI.Tests.csproj -c Release -f net10.0
dotnet test DomainDetective.Website.Tests/DomainDetective.Website.Tests.csproj -c Release -f net10.0
./Module/DomainDetective.Tests.ps1                     # Pester, after building
./Module/Build/Build-Module.ps1 -RunMode Build         # module and NuGet packages
./Build/Publish-CLI.ps1 -Plan                          # CLI publish plan (Build/cli.build.json)
pwsh ./Website/build.ps1 -Fast                         # static site; -Serve for a local server
```

- Targets: libraries, cmdlets and core tests `net472;net8.0;net10.0` (`net472`
  only on Windows); CLI and its tests `net8.0;net10.0`; website, toolbox and
  online host `net10.0`; generator `netstandard2.0`. Warnings are errors.
- `DomainDetective.Net8.slnf` builds the subset used by the `net8.0` lane.
- Release only: `-RunMode Publish` and `Build/Build-Project.ps1 -PublishNuget
  -PublishGitHub`.

## Generated files

- `Module/Docs/*.md` and `Module/en-US/` come from the cmdlet XML docs.
  Regenerate with `./Module/Build/Build-Module.ps1 -RunMode Documentation`.
- `Website/data/tools-catalog.json` and the tool stubs in
  `Website/content/pages/tools/` mirror `ToolRegistry`. Regenerate them by
  running `DomainDetective.Website.Tests` with `DD_UPDATE_TOOL_CATALOG=1`.
- `Data/public_suffix_list.dat` and `Data/hsts_preload.json.gz` are refreshed by
  `./Scripts/Update-StandardsData.ps1`, not edited by hand.
- Country and location enums are generated at build time from
  `Data/DNS/PublicDNS.json`.

## Conventions

- C#: K&R braces, braces on every block. Prefer file-scoped namespaces for new
  files.
- Cmdlets use the `DD` noun prefix (`Add-DDDnsblProvider`) and document
  themselves with XML docs: `<summary>`, `<para>` on parameters and `<example>`
  blocks with `<summary>` and `<code>`.
- PowerShell: support Windows PowerShell 5.1 and PowerShell 7, K&R/OTBS braces.
- Result views set `Subject` per `Docs/SUBJECT_CONVENTIONS.MD`.
- Commit and PR titles use Conventional Commits with Gitmoji:
  `feat(mail): ✨ Adopt MimeKit 5 authentication diagnostics`.

## Gotchas

- `[IntegrationFact]` tests are opt-in: set `DOMAINDETECTIVE_INTEGRATION=1`
  (and `DOMAINDETECTIVE_INTEGRATION_DOMAIN` for desired-state checks). They need
  the network.
- Shodan and Censys enrichment read `DOMAINDETECTIVE_SHODAN_API_KEY`,
  `DOMAINDETECTIVE_CENSYS_API_ID` and `DOMAINDETECTIVE_CENSYS_API_SECRET`.
- CI excludes `TestDnssecRecordValidation` on `net472`.
- A static GitHub Pages deployment has no `/tool-api`; validate hosted tool
  checks through `DomainDetective.OnlineHost`.
- Website CI also runs on changes to `DomainDetective.Website/`,
  `DomainDetective.Toolbox/` and `DomainDetective.Website.Tests/`.
