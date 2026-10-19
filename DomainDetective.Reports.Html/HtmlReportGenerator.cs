using System.Threading.Tasks;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

/// <summary>Generates HTML through the shared composition and captured-evidence pipeline.</summary>
public sealed class HtmlReportGenerator : IReportGenerator {
    /// <summary>Gets the report format produced by this generator.</summary>
    public ReportFormat Format => ReportFormat.Html;

    /// <summary>Determines whether this generator handles the supplied report options.</summary>
    public bool CanGenerate(ReportOptions options) => options.Format == ReportFormat.Html;

    /// <summary>Generates the report from existing results and the requested options.</summary>
    public Task<ReportResult> GenerateAsync(DomainHealthCheck healthCheck, ReportOptions options)
        => HealthCheckCompositionReport.GenerateAsync(healthCheck, options);
}
