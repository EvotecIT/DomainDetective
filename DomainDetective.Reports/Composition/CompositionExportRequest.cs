using System;
using System.Collections.Generic;

namespace DomainDetective.Reports;

public sealed class CompositionExportRequest
{
    public IReadOnlyList<object> Items { get; set; } = Array.Empty<object>();
    public IReadOnlyList<ReportFormat> Formats { get; set; } = Array.Empty<ReportFormat>();
    public ReportScope Scope { get; set; } = ReportScope.Normal;
    public bool ShowInfoFindings { get; set; } = true;
    public OrderingOptions Ordering { get; set; } = new OrderingOptions();
    public string? Title { get; set; }
    public string? Subject { get; set; }
    public string? Category { get; set; }
    public string? Keywords { get; set; }
    public string? Creator { get; set; }
    public NarrativePlacement NarrativePlacement { get; set; } = NarrativePlacement.Auto;
    public string? CompanyName { get; set; }
    public string? CompanyAddress { get; set; }
    public string? CompanyYear { get; set; }
    public string? LogoPath { get; set; }
    public string? HeaderText { get; set; }
    public string? FooterText { get; set; }
    public string? WatermarkText { get; set; }
    public int? SummaryColumnCap { get; set; }
    public int? HeaderLogoSizePx { get; set; }
    public int? FooterLogoSizePx { get; set; }
    public ProviderHelpRenderOptions? ProviderHelpOptions { get; set; }
    public string HtmlProfile { get; set; } = "Document";
    public string ExcelProfile { get; set; } = "Workbook";
    public string? ExportPath { get; set; }
    public string? DefaultOutputDirectory { get; set; }
    public bool OpenInBrowser { get; set; }
    public bool AutoCollectTtl { get; set; } = true;
    public bool LogSectionOrder { get; set; }
    public CompositionExecutionOptions ExecutionOptions { get; set; } = new CompositionExecutionOptions();
}
