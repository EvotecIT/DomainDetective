# DomainDetective.Visual

`DomainDetective.Visual` adds optional browser capture and image fingerprinting support for visual typosquatting analysis.

The package isolates the heavier Playwright and ImageSharp dependencies from the base `DomainDetective` package.

Register it once during startup:

```csharp
using DomainDetective.Visual;

DomainDetectiveVisualRegistration.Register();
```
