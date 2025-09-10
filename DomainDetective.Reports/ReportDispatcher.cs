using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace DomainDetective.Reports;

public sealed class ReportDispatcher
{
    public async Task<ReportResult> GenerateAsync(DomainHealthCheck health, ReportOptions options, string subject, bool openInBrowser = false)
    {
        var path = string.IsNullOrWhiteSpace(options.OutputPath)
            ? ReportPathHelper.GenerateDefaultPath(subject, options.Format, null)
            : options.OutputPath!;

        switch (options.Format)
        {
            case ReportFormat.Json:
            {
                var json = JsonSerializer.Serialize(health, DomainHealthCheck.JsonOptions);
#if NET472
                File.WriteAllText(path, json);
#else
                await File.WriteAllTextAsync(path, json);
#endif
                return new ReportResult { Success = true, FilePath = path, Format = ReportFormat.Json, FileSize = json.Length };
            }
            default:
                var gen = ResolveGenerator(options);
                if (gen != null)
                {
                    options.CustomProperties ??= new System.Collections.Generic.Dictionary<string, object>();
                    if (!options.CustomProperties.ContainsKey("OpenInBrowser"))
                        options.CustomProperties["OpenInBrowser"] = openInBrowser;
                    if (!options.CustomProperties.ContainsKey("Domain"))
                        options.CustomProperties["Domain"] = subject;
                    return await gen.GenerateAsync(health, options);
                }
                return new ReportResult { Success = false, FilePath = path, Format = options.Format, ErrorMessage = $"{options.Format} format not yet implemented" };
        }
    }

    private static IReportGenerator? ResolveGenerator(ReportOptions options)
    {
        // 1) Try known generator types by name (avoids requiring callers to preload assemblies)
        static IReportGenerator? TryCreate(string assemblyQualifiedName)
        {
            try
            {
                var t = Type.GetType(assemblyQualifiedName, throwOnError: false);
                if (t == null) return null;
                if (t.IsAbstract) return null;
                if (!typeof(IReportGenerator).IsAssignableFrom(t)) return null;
                return (IReportGenerator?)Activator.CreateInstance(t);
            }
            catch { return null; }
        }

        switch (options.Format)
        {
            case ReportFormat.Html:
            {
                var gen = TryCreate("DomainDetective.Reports.Html.HtmlReportGenerator, DomainDetective.Reports.Html");
                if (gen != null) return gen;
                break;
            }
            case ReportFormat.Markdown:
            {
                var gen = TryCreate("DomainDetective.Reports.Markdown.MarkdownReportGenerator, DomainDetective.Reports.Markdown");
                if (gen != null) return gen;
                break;
            }
            case ReportFormat.HtmlAsMarkdown:
            {
                var gen = TryCreate("DomainDetective.Reports.Markdown.HtmlAsMarkdownReportGenerator, DomainDetective.Reports.Markdown");
                if (gen != null) return gen;
                break;
            }
            case ReportFormat.Pdf:
            {
                var gen = TryCreate("DomainDetective.Reports.Pdf.PdfReportGenerator, DomainDetective.Reports.Pdf");
                if (gen != null) return gen;
                break;
            }
            case ReportFormat.Word:
            {
                var gen = TryCreate("DomainDetective.Reports.Office.WordReportGenerator, DomainDetective.Reports.Office");
                if (gen != null) return gen;
                break;
            }
            case ReportFormat.Excel:
            {
                var gen = TryCreate("DomainDetective.Reports.Office.ExcelReportGenerator, DomainDetective.Reports.Office");
                if (gen != null) return gen;
                break;
            }
        }

        // 2) Fallback: scan already loaded assemblies for any IReportGenerator
        try
        {
            foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                Type[] types;
                try { types = asm.GetTypes(); } catch { continue; }
                    foreach (var t in types)
                    {
                        if (t.IsAbstract) continue;
                        if (!typeof(IReportGenerator).IsAssignableFrom(t)) continue;
                        IReportGenerator? gen;
                        try
                        {
                            gen = Activator.CreateInstance(t) as IReportGenerator;
                        }
                        catch
                        {
                            continue;
                        }
                        if (gen == null) continue;
                        try
                        {
                            if (gen.CanGenerate(options)) return gen;
                        }
                        catch
                        {
                        }
                    }
            }
        }
        catch { }
        return null;
    }
}
