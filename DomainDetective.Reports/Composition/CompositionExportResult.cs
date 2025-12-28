using System;
using System.Collections.Generic;

namespace DomainDetective.Reports;

public sealed class CompositionExportResult
{
    public IReadOnlyList<object> Items { get; set; } = Array.Empty<object>();
    public IReadOnlyList<string> Subjects { get; set; } = Array.Empty<string>();
    public string SubjectLabel { get; set; } = string.Empty;
    public IReadOnlyList<ReportResult> Reports { get; set; } = Array.Empty<ReportResult>();
}
