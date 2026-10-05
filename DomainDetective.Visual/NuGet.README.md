# DomainDetective.Visual

`DomainDetective.Visual` adds optional browser capture and image fingerprinting support for visual typosquatting analysis.

The package isolates HtmlTinkerX browser capture and ImageSharp dependencies from the base `DomainDetective` package. HtmlTinkerX owns browser installation and session lifetime.

On .NET Framework targets, the package supports image fingerprinting only. Browser capture requires .NET 8 or later.

Visual fingerprints are intended for comparisons produced under the same target framework/runtime. Persisted hashes may differ across target frameworks because the package uses the ImageSharp line supported by each TFM.

Register it once during startup:

```csharp
using DomainDetective.Visual;

DomainDetectiveVisualRegistration.Register();
```
