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
                    IReportGenerator gen;
                    try { gen = (IReportGenerator)Activator.CreateInstance(t); } catch { continue; }
                    try { if (gen.CanGenerate(options)) return gen; } catch { }
                }
            }
        }
        catch { }
        return null;
    }
}
