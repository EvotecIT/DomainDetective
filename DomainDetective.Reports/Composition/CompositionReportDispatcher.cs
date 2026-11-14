using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading;

namespace DomainDetective.Reports;

/// <summary>Loads optional renderers without coupling the assessment model to export assemblies.</summary>
internal static class CompositionReportDispatcher {
    public static bool TryGenerate(ReportFormat format, CompositionExportRequest request,
        DomainAssessmentReport report, string outputPath, out string? error) {
        error = null;
        try {
            AssessmentExportSettings.Validate(request);
            switch (format) {
                case ReportFormat.Json:
                    var directory = Path.GetDirectoryName(outputPath);
                    if (!string.IsNullOrEmpty(directory)) { Directory.CreateDirectory(directory); }
                    File.WriteAllText(outputPath, DomainAssessmentJson.Serialize(report));
                    return true;
                case ReportFormat.Excel:
                    return Generate("Office", "AssessmentExcelReport", "AssessmentExcelOptions", request, report, outputPath, out error);
                case ReportFormat.Markdown:
                    return Generate("Markdown", "AssessmentMarkdownReport", "AssessmentMarkdownOptions", request, report, outputPath, out error);
                case ReportFormat.MarkdownHtml:
                    return Generate("Markdown", "MarkdownHtmlReportGenerator", "AssessmentMarkdownOptions", request, report, outputPath, out error);
                case ReportFormat.Html:
                    return GenerateHtml(request, report, outputPath, out error);
                default:
                    error = $"{format} report generation is not supported.";
                    return false;
            }
        } catch (TargetInvocationException ex) {
            error = ex.InnerException?.Message ?? ex.Message;
            return false;
        } catch (Exception ex) {
            error = ex.Message;
            return false;
        }
    }

    internal static IReadOnlyList<ReportResult> GeneratePaperReports(CompositionExportRequest request,
        DomainAssessmentReport report, IReadOnlyDictionary<ReportFormat, string> outputs, CancellationToken cancellationToken) {
        try {
            const string assembly = "DomainDetective.Reports.Office";
            var type = RequireType(assembly + ".AssessmentWordReport", assembly);
            var optionsType = RequireType(assembly + ".AssessmentWordOptions", assembly);
            var options = Activator.CreateInstance(optionsType)!;
            optionsType.GetProperty("ShowInfoFindings")!.SetValue(options, request.ShowInfoFindings);
            var method = type.GetMethod("GenerateReports", new[] {
                typeof(IReadOnlyDictionary<ReportFormat, string>), typeof(DomainAssessmentReport), optionsType, typeof(CancellationToken)
            }) ?? throw new InvalidOperationException("Assessment paper batch generator signature not found.");
            return (IReadOnlyList<ReportResult>)method.Invoke(null, new object[] { outputs, report, options, cancellationToken })!;
        } catch (TargetInvocationException ex) {
            if (ex.InnerException is OperationCanceledException) {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
            }
            return FailedPaperReports(outputs, ex.InnerException?.Message ?? ex.Message);
        } catch (Exception ex) when (ex is not OperationCanceledException) {
            return FailedPaperReports(outputs, ex.Message);
        }
    }

    private static IReadOnlyList<ReportResult> FailedPaperReports(IReadOnlyDictionary<ReportFormat, string> outputs, string error) {
        var results = new List<ReportResult>();
        foreach (var output in outputs) {
            results.Add(new ReportResult { Format = output.Key, FilePath = output.Value, ErrorMessage = error });
        }
        return results;
    }

    private static bool Generate(string assemblySuffix, string renderer, string optionsName,
        CompositionExportRequest request, DomainAssessmentReport report, string path, out string? error) {
        string assembly = "DomainDetective.Reports." + assemblySuffix;
        var type = RequireType(assembly + "." + renderer, assembly);
        var optionsType = RequireType(assembly + "." + optionsName, assembly);
        var options = Activator.CreateInstance(optionsType)!;
        optionsType.GetProperty("ShowInfoFindings")!.SetValue(options, request.ShowInfoFindings);
        var method = type.GetMethod("Generate", new[] { typeof(string), typeof(DomainAssessmentReport), optionsType });
        if (method == null) {
            error = $"Assessment generator '{type.FullName}.Generate' signature not found.";
            return false;
        }
        method.Invoke(null, new[] { (object)path, report, options });
        error = null;
        return true;
    }

    private static bool GenerateHtml(CompositionExportRequest request, DomainAssessmentReport report, string path, out string? error) {
        const string assembly = "DomainDetective.Reports.Html";
        var type = RequireType(assembly + ".AssessmentHtmlReport", assembly);
        var optionsType = RequireType(assembly + ".AssessmentHtmlOptions", assembly);
        var options = Activator.CreateInstance(optionsType)!;
        optionsType.GetProperty("ShowInfoFindings")!.SetValue(options, request.ShowInfoFindings);
        var theme = optionsType.GetProperty("Theme")!;
        theme.SetValue(options, Enum.Parse(theme.PropertyType, (request.HtmlTheme ?? "system").Trim(), ignoreCase: true));
        var method = type.GetMethod("Generate", new[] { typeof(string), typeof(DomainAssessmentReport), optionsType, typeof(bool) });
        if (method == null) {
            error = "HTML assessment generator signature not found.";
            return false;
        }
        method.Invoke(null, new[] { (object)path, report, options, request.OpenInBrowser });
        error = null;
        return true;
    }

    private static Type RequireType(string name, string assembly)
        => Type.GetType(name + ", " + assembly, throwOnError: false)
           ?? throw new InvalidOperationException($"Assessment generator '{name}' not found. Ensure '{assembly}' is referenced.");
}
