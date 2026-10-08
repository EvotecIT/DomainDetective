# DomainDetective.Visual

`DomainDetective.Visual` adds optional browser capture and image fingerprinting support for visual typosquatting analysis.

The package uses OfficeIMO.Core for managed raster decoding and perceptual fingerprints. HtmlTinkerX owns browser installation, capture, and session lifetime. The base `DomainDetective` package does not require either visual provider.

On .NET Framework targets, the package supports image fingerprinting only. Browser capture requires .NET 8 or later.

The fingerprint is a 64-bit horizontal difference hash: bicubic resizing to nine by eight pixels followed by BT.709 luminance comparisons. All supported targets use the same managed implementation. Decoding applies encoded-size, pixel, and working-memory limits; unsupported or malformed assets produce no visual signal.

Rebuild persisted source profiles and precomputed capture fingerprints when migrating from the ImageSharp provider. Decoder and resampler differences can change hashes even though the hexadecimal representation and Hamming-distance thresholds retain their meaning. Compare hashes generated with the same provider implementation.

Register it once during startup:

```csharp
using DomainDetective.Visual;

DomainDetectiveVisualRegistration.Register();
```
