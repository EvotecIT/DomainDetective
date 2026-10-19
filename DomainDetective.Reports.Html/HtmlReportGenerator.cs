using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

/// <summary>
/// IReportGenerator adapter for shared HTML composition and current execution evidence.
/// </summary>
public sealed class HtmlReportGenerator : IReportGenerator
{
    /// <summary>Gets the report format produced by this generator.</summary>
    public ReportFormat Format => ReportFormat.Html;

    /// <summary>Determines whether this generator can handle the supplied report options.</summary>
    public bool CanGenerate(ReportOptions options) => options.Format == ReportFormat.Html;

    /// <summary>Generates the report asynchronously.</summary>
    public Task<ReportResult> GenerateAsync(DomainHealthCheck healthCheck, ReportOptions options)
        => HealthCheckCompositionReport.GenerateAsync(healthCheck, options);
}

