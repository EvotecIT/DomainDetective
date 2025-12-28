using System;
using System.Collections.Generic;
using System.Reflection;

namespace DomainDetective.Reports;

internal static class CompositionReportDispatcher
{
    private const string HtmlAssembly = "DomainDetective.Reports.Html";
    private const string HtmlReportType = "DomainDetective.Reports.Html.HtmlCompositionReport";
    private const string HtmlProfileType = "DomainDetective.Reports.Html.HtmlProfile";
    private const string OfficeAssembly = "DomainDetective.Reports.Office";
    private const string WordReportType = "DomainDetective.Reports.Office.WordCompositionReport";
    private const string ExcelReportType = "DomainDetective.Reports.Office.ExcelCompositionReport";
    private const string ExcelProfileType = "DomainDetective.Reports.Office.ExcelProfile";
    private const string MarkdownAssembly = "DomainDetective.Reports.Markdown";
    private const string MarkdownReportType = "DomainDetective.Reports.Markdown.MarkdownCompositionReport";

    public static bool TryGenerate(
        ReportFormat format,
        CompositionExportRequest request,
        IReadOnlyList<object> items,
        string outputPath,
        out string? error)
    {
        error = null;
        switch (format)
        {
            case ReportFormat.Word:
                return TryGenerateWord(request, items, outputPath, out error);
            case ReportFormat.Html:
                return TryGenerateHtml(request, items, outputPath, out error);
            case ReportFormat.Excel:
                return TryGenerateExcel(request, items, outputPath, out error);
            case ReportFormat.Markdown:
                return TryGenerateMarkdown(request, items, outputPath, out error);
            case ReportFormat.MarkdownHtml:
                return TryGenerateMarkdownHtml(request, items, outputPath, out error);
            default:
                error = $"{format} composition is not supported.";
                return false;
        }
    }

    private static bool TryGenerateWord(CompositionExportRequest request, IReadOnlyList<object> items, string outputPath, out string? error)
    {
        error = null;
        var reportType = GetType(WordReportType, OfficeAssembly, out error);
        if (reportType == null)
        {
            return false;
        }

        var method = reportType.GetMethod(
            "Generate",
            BindingFlags.Public | BindingFlags.Static,
            null,
            new[] {
                typeof(string),
                typeof(IReadOnlyList<object>),
                typeof(ReportScope),
                typeof(bool),
                typeof(NarrativePlacement),
                typeof(string),
                typeof(string),
                typeof(string),
                typeof(string),
                typeof(string),
                typeof(string),
                typeof(string),
                typeof(string),
                typeof(string),
                typeof(string),
                typeof(string),
                typeof(bool),
                typeof(bool),
                typeof(ProviderHelpRenderOptions),
                typeof(DomainOrder),
                typeof(SectionOrderMode),
                typeof(string[]),
                typeof(int?),
                typeof(int?),
                typeof(int?)
            },
            null);
        if (method == null)
        {
            error = "Word composition generator signature not found.";
            return false;
        }

        return Invoke(method, new object?[] {
            outputPath,
            items,
            request.Scope,
            request.ShowInfoFindings,
            request.NarrativePlacement,
            request.Title,
            request.Subject,
            request.Category,
            request.Keywords,
            request.Creator,
            request.CompanyName,
            request.CompanyAddress,
            request.CompanyYear,
            request.LogoPath,
            request.HeaderText,
            request.WatermarkText,
            true,
            true,
            request.ProviderHelpOptions,
            request.Ordering.DomainOrder,
            request.Ordering.SectionOrderMode,
            request.Ordering.SectionOrder,
            request.SummaryColumnCap,
            request.HeaderLogoSizePx,
            request.FooterLogoSizePx
        }, out error);
    }

    private static bool TryGenerateHtml(CompositionExportRequest request, IReadOnlyList<object> items, string outputPath, out string? error)
    {
        error = null;
        var reportType = GetType(HtmlReportType, HtmlAssembly, out error);
        if (reportType == null)
        {
            return false;
        }

        var profileType = GetType(HtmlProfileType, HtmlAssembly, out error);
        if (profileType == null)
        {
            return false;
        }
        var profileValue = ParseEnum(profileType, request.HtmlProfile, "Document");

        var method = reportType.GetMethod(
            "Generate",
            BindingFlags.Public | BindingFlags.Static,
            null,
            new[] {
                typeof(string),
                typeof(IReadOnlyList<object>),
                typeof(ReportScope),
                typeof(bool),
                typeof(NarrativePlacement),
                typeof(string),
                typeof(string),
                typeof(string),
                typeof(DomainOrder),
                typeof(SectionOrderMode),
                typeof(string[]),
                profileType
            },
            null);
        if (method == null)
        {
            error = "HTML composition generator signature not found.";
            return false;
        }

        return Invoke(method, new object?[] {
            outputPath,
            items,
            request.Scope,
            request.OpenInBrowser,
            request.NarrativePlacement,
            request.Title,
            request.Creator,
            request.Subject,
            request.Ordering.DomainOrder,
            request.Ordering.SectionOrderMode,
            request.Ordering.SectionOrder,
            profileValue
        }, out error);
    }

    private static bool TryGenerateExcel(CompositionExportRequest request, IReadOnlyList<object> items, string outputPath, out string? error)
    {
        error = null;
        var reportType = GetType(ExcelReportType, OfficeAssembly, out error);
        if (reportType == null)
        {
            return false;
        }

        var profileType = GetType(ExcelProfileType, OfficeAssembly, out error);
        if (profileType == null)
        {
            return false;
        }
        var profileValue = ParseEnum(profileType, request.ExcelProfile, "Workbook");

        var method = reportType.GetMethod(
            "Generate",
            BindingFlags.Public | BindingFlags.Static,
            null,
            new[] {
                typeof(string),
                typeof(IReadOnlyList<object>),
                typeof(ReportScope),
                typeof(OrderingOptions),
                profileType
            },
            null);
        if (method == null)
        {
            error = "Excel composition generator signature not found.";
            return false;
        }

        return Invoke(method, new object?[] {
            outputPath,
            items,
            request.Scope,
            request.Ordering,
            profileValue
        }, out error);
    }

    private static bool TryGenerateMarkdown(CompositionExportRequest request, IReadOnlyList<object> items, string outputPath, out string? error)
    {
        return TryGenerateMarkdownInternal("Generate", request, items, outputPath, out error);
    }

    private static bool TryGenerateMarkdownHtml(CompositionExportRequest request, IReadOnlyList<object> items, string outputPath, out string? error)
    {
        return TryGenerateMarkdownInternal("GenerateMarkdownHtml", request, items, outputPath, out error);
    }

    private static bool TryGenerateMarkdownInternal(string methodName, CompositionExportRequest request, IReadOnlyList<object> items, string outputPath, out string? error)
    {
        error = null;
        var reportType = GetType(MarkdownReportType, MarkdownAssembly, out error);
        if (reportType == null)
        {
            return false;
        }

        var method = reportType.GetMethod(
            methodName,
            BindingFlags.Public | BindingFlags.Static,
            null,
            new[] {
                typeof(string),
                typeof(IReadOnlyList<object>),
                typeof(ReportScope),
                typeof(OrderingOptions)
            },
            null);
        if (method == null)
        {
            error = "Markdown composition generator signature not found.";
            return false;
        }

        return Invoke(method, new object?[] {
            outputPath,
            items,
            request.Scope,
            request.Ordering
        }, out error);
    }

    private static bool Invoke(MethodInfo method, object?[] args, out string? error)
    {
        error = null;
        try
        {
            method.Invoke(null, args);
            return true;
        }
        catch (TargetInvocationException ex)
        {
            var msg = ex.InnerException?.Message ?? ex.Message;
            error = msg;
            return false;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static Type? GetType(string typeName, string assemblyName, out string? error)
    {
        error = null;
        var type = Type.GetType($"{typeName}, {assemblyName}", throwOnError: false);
        if (type == null)
        {
            error = $"Composition generator '{typeName}' not found. Ensure '{assemblyName}' is referenced.";
        }
        return type;
    }

    private static object ParseEnum(Type enumType, string? value, string defaultValue)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Enum.Parse(enumType, defaultValue, ignoreCase: true);
        }
        try
        {
            return Enum.Parse(enumType, value, ignoreCase: true);
        }
        catch
        {
            return Enum.Parse(enumType, defaultValue, ignoreCase: true);
        }
    }
}
