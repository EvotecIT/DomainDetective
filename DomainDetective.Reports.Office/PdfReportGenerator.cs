using System.Threading.Tasks;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Office;

/// <summary>Generates PDF by converting the shared assessment Word document through OfficeIMO.</summary>
public sealed class PdfReportGenerator : IReportGenerator {
    /// <summary>Gets the PDF output format.</summary>
    public ReportFormat Format => ReportFormat.Pdf;
    /// <summary>Determines whether the adapter handles the requested format.</summary>
    public bool CanGenerate(ReportOptions options) => options.Format == Format;
    /// <summary>Converts existing assessment results without acquiring evidence again.</summary>
    public Task<ReportResult> GenerateAsync(DomainHealthCheck healthCheck, ReportOptions options)
        => HealthCheckCompositionReport.GenerateAsync(healthCheck, options);
}
