using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

/// <summary>
/// IReportGenerator adapter for HTML output: the assessment report for the checks the health check ran.
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

        var errors = new System.Collections.Generic.List<string>();
        bool verified = healthCheck.LastVerifiedChecks.Count > 0;
        // After individual Verify* calls there is no run record: convert every check and keep those that name a domain.
        var checks = verified ? healthCheck.LastVerifiedChecks : (System.Collections.Generic.IEnumerable<HealthCheckType>)System.Enum.GetValues(typeof(HealthCheckType));
        var items = DomainDetective.Views.Converters.ConvertChecks(healthCheck, checks, verified ? errors : null);
        AssessmentHtmlReport.Generate(path, items, new DomainAssessmentOptions { Title = $"Security Report — {subject}", IgnoreInputsWithoutDomain = !verified }, null, open);
        return Task.FromResult(new ReportResult {
            Success = true,
            FilePath = path,
            Format = ReportFormat.Html,
            ErrorMessage = errors.Count == 0 ? null : "Some checks could not be converted: " + string.Join("; ", errors)
        });
    }
}

