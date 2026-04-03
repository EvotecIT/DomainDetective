# Contributing

## Local Validation

Use the commands below before opening a pull request.

### General .NET changes

```powershell
dotnet test ./DomainDetective.Tests/DomainDetective.Tests.csproj --configuration Release --framework net10.0
dotnet test ./DomainDetective.CLI.Tests/DomainDetective.CLI.Tests.csproj --configuration Release --framework net10.0
```

### Website and online tools changes

Run these when a change affects the public site, Blazor tools app, navigation, wording, or GitHub Pages/static behavior.

```powershell
dotnet test ./DomainDetective.Website.Tests/DomainDetective.Website.Tests.csproj --configuration Release --framework net10.0
dotnet build ./DomainDetective.Website/DomainDetective.Website.csproj
pwsh ./Website/build.ps1 -Fast
```

## Website Projects

- `Website` contains the static marketing/docs/API site
- `DomainDetective.Website` contains the Blazor WebAssembly tools app
- `DomainDetective.Toolbox` contains the shared website/tooling components
- `DomainDetective.Website.Tests` contains helper, component, page, and layout regression tests for the website experience

## CI Workflows

- `.github/workflows/dotnet-tests.yml` runs the .NET test matrix and includes `DomainDetective.Website.Tests` on the `net10.0` lane
- `.github/workflows/website-ci.yml` runs website regression tests before the PowerForge website build on pull requests
- `.github/workflows/deploy-website.yml` deploys the website and also reacts to `DomainDetective.Website/**` and `DomainDetective.Toolbox/**` changes

## Website Trigger Paths

Website-related CI is triggered by changes in:

- `Website/**`
- `DomainDetective.Website/**`
- `DomainDetective.Toolbox/**`
- `DomainDetective.Website.Tests/**`

## Notes

- A static-only deployment such as GitHub Pages does not provide `/tool-api`
- Production-style hosted tool checks should be validated through `DomainDetective.OnlineHost`
