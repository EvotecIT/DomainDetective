# DomainDetective Advanced HTML Reports

This project extends the basic HTML reporting by providing a common base for advanced layouts.

## Usage

```csharp
var healthCheck = new DomainHealthCheck();
var report = new CustomReport(healthCheck, "example.com");
report.Generate("report.html");
```

The `CustomReport` type derives from `AdvancedReportBase` and can use `RenderProgressLog` to include scan progress in the output.
