using System;
using System.Collections.Generic;

namespace DomainDetective.Reports.Excel;

/// <summary>
/// Placeholder for Excel composition (ClosedXML).
/// Mirrors Word/HTML composition ordering options.
/// </summary>
public static class ExcelCompositionReport
{
    public static void Generate(
        string path,
        IReadOnlyList<object> items,
        ReportScope scope,
        OrderingOptions? ordering = null)
    {
        // Scaffold only — real writer will arrive tomorrow.
        throw new NotImplementedException("Excel composition is planned and will be implemented.");
    }
}

