using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

/// <summary>
/// IReportGenerator adapter for HTML output using DomainSecurityReport.
/// </summary>
public sealed class HtmlReportGenerator : IReportGenerator
{
    /// <summary>Gets the report format produced by this generator.</summary>
    public ReportFormat Format => ReportFormat.Html;

    /// <summary>Determines whether this generator can handle the supplied report options.</summary>
    public bool CanGenerate(ReportOptions options) => options.Format == ReportFormat.Html;

    /// <summary>Generates the report asynchronously.</summary>
    public Task<ReportResult> GenerateAsync(DomainHealthCheck healthCheck, ReportOptions options)
    {
        var subject = options.CustomProperties != null && options.CustomProperties.TryGetValue("Domain", out var d)
            ? d?.ToString() ?? "domain"
            : "domain";
        var path = string.IsNullOrWhiteSpace(options.OutputPath)
            ? ReportPathHelper.GenerateDefaultPath(subject, ReportFormat.Html, null)
            : options.OutputPath!;

        var open = false;
        if (options.CustomProperties != null && options.CustomProperties.TryGetValue("OpenInBrowser", out var openObj))
        {
            bool.TryParse(openObj?.ToString(), out open);
        }

        var report = new DomainSecurityReport(healthCheck, subject);
        report.GenerateReport(path, open);
        return Task.FromResult(new ReportResult { Success = true, FilePath = path, Format = ReportFormat.Html });
    }
}

