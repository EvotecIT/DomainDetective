using System.Threading.Tasks;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Office;

/// <summary>Generates Excel output through the shared assessment composition engine.</summary>
public class ExcelReportGenerator : IReportGenerator {
    /// <summary>Gets the output format.</summary>
    public ReportFormat Format => ReportFormat.Excel;
    /// <summary>Determines whether this adapter handles the requested format.</summary>
    public bool CanGenerate(ReportOptions options) => options.Format == Format;
    /// <summary>Exports existing results with summaries, narratives, recommendations and supporting evidence.</summary>
    public Task<ReportResult> GenerateAsync(DomainHealthCheck healthCheck, ReportOptions options)
        => HealthCheckCompositionReport.GenerateAsync(healthCheck, options);
}
