using System;
using System.Collections.Generic;

namespace DomainDetective.Reports.Markdown;

/// <summary>
/// Placeholder for Markdown composition. To be implemented with the same ordering options as other formats.
/// </summary>
public static class MarkdownCompositionReport
{
    public static void Generate(
        string path,
        IReadOnlyList<object> items,
        ReportScope scope,
        OrderingOptions? ordering = null)
    {
        // Scaffold only — real writer will arrive tomorrow.
        throw new NotImplementedException("Markdown composition is planned and will be implemented.");
    }
}

