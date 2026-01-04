using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace DomainDetective.Reports;

internal static class CompositionReportDispatcher
{
    private const string HtmlAssembly = "DomainDetective.Reports.Html";
    private const string HtmlReportType = "DomainDetective.Reports.Html.HtmlCompositionReport";
    private const string HtmlProfileType = "DomainDetective.Reports.Html.HtmlProfile";
    private const string HtmlForgeXAssembly = "HtmlForgeX";
    private const string HtmlThemeModeType = "HtmlForgeX.ThemeMode";
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

        // vNext: includes ThemeMode; keep fallback for older signatures.
        var themeType = GetType(HtmlThemeModeType, HtmlForgeXAssembly, out _);
        if (themeType != null)
        {
            var methodWithTheme = reportType.GetMethod(
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
                    profileType,
                    themeType
                },
                null);
            if (methodWithTheme != null)
            {
                var themeValue = Enum.Parse(themeType, "Light", ignoreCase: true);
                return Invoke(methodWithTheme, new object?[] {
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
                    profileValue,
                    themeValue
                }, out error);
            }
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
                typeof(DomainOrder),
                typeof(SectionOrderMode),
                typeof(string[]),
                profileType
            },
            null);
	        if (method == null)
	        {
	            // Backward/forward compatibility: older binaries might differ by interface types
	            // (e.g., IEnumerable<object> vs IReadOnlyList<object>) or by nullable metadata.
	            method = FindCompatibleHtmlGenerateMethod(reportType, profileType, themeType);
	            if (method == null)
	            {
	                error = "HTML composition generator signature not found.";
	                return false;
	            }
	        }

	        var parameters = method.GetParameters();
	        var invokeArgs = parameters.Length == 13
	            ? new object?[] {
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
	                profileValue,
	                Enum.Parse(parameters[12].ParameterType, "Light", ignoreCase: true)
	            }
	            : new object?[] {
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
	            };

	        return Invoke(method, invokeArgs, out error);
	    }

	    private static MethodInfo? FindCompatibleHtmlGenerateMethod(Type reportType, Type profileType, Type? themeType)
	    {
	        var candidates = reportType
	            .GetMethods(BindingFlags.Public | BindingFlags.Static)
	            .Where(m => string.Equals(m.Name, "Generate", StringComparison.Ordinal))
	            .ToArray();

	        bool IsCompatible(ParameterInfo[] ps)
	        {
	            if (ps.Length != 12 && ps.Length != 13) return false;
	            if (ps[0].ParameterType != typeof(string)) return false;
	            if (!ps[1].ParameterType.IsAssignableFrom(typeof(IReadOnlyList<object>))) return false;
	            if (ps[2].ParameterType != typeof(ReportScope)) return false;
	            if (ps[3].ParameterType != typeof(bool)) return false;
	            if (ps[4].ParameterType != typeof(NarrativePlacement)) return false;
	            if (ps[8].ParameterType != typeof(DomainOrder)) return false;
	            if (ps[9].ParameterType != typeof(SectionOrderMode)) return false;
	            if (!ps[10].ParameterType.IsAssignableFrom(typeof(string[]))) return false;
	            if (ps[11].ParameterType != profileType) return false;
	            if (ps.Length == 13)
	            {
	                if (themeType == null) return false;
	                if (ps[12].ParameterType != themeType) return false;
	            }
	            return true;
	        }

	        MethodInfo? best = null;
	        foreach (var m in candidates)
	        {
	            var ps = m.GetParameters();
	            if (!IsCompatible(ps)) continue;
	            if (best == null) { best = m; continue; }
	            if (best.GetParameters().Length == 12 && ps.Length == 13) best = m;
	        }

	        return best;
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
