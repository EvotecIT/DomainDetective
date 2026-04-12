using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Reports;
using OfficeIMO.Markdown;

namespace DomainDetective.Reports.Markdown;

/// <summary>
/// Generates a Markdown report using OfficeIMO.Markdown that mirrors the Word layout.
/// </summary>
public sealed class MarkdownReportGenerator : IReportGenerator {
    /// <summary>Gets the report format produced by this generator.</summary>
    public ReportFormat Format => ReportFormat.Markdown;

    /// <summary>Determines whether the supplied options request Markdown output.</summary>
    public bool CanGenerate(ReportOptions options) => options.Format == ReportFormat.Markdown;

    /// <summary>Generates the Markdown report for the supplied domain health check.</summary>
    public Task<ReportResult> GenerateAsync(DomainHealthCheck healthCheck, ReportOptions options) {
        var domain = options.CustomProperties?.ContainsKey("Domain") == true
            ? options.CustomProperties["Domain"]?.ToString() ?? "unknown"
            : "unknown";

        var outputPath = options.OutputPath;
        if (string.IsNullOrWhiteSpace(outputPath)) {
            outputPath = ReportPathHelper.GenerateDefaultPath(domain, ReportFormat.Markdown, null);
        }
        // Ensure .md extension
        if (!string.Equals(Path.GetExtension(outputPath), ".md", StringComparison.OrdinalIgnoreCase)) {
            outputPath = Path.ChangeExtension(outputPath, ".md");
        }

        try {
            var md = BuildMarkdown(healthCheck, domain);
            var text = md.ToMarkdown();
#if NET472
            File.WriteAllText(outputPath!, text, Encoding.UTF8);
#else
            File.WriteAllText(outputPath!, text, Encoding.UTF8);
#endif
            return Task.FromResult(new ReportResult {
                Success = true,
                FilePath = outputPath!,
                Format = ReportFormat.Markdown,
                Metadata = new ReportMetadata {
                    Domain = domain,
                    TemplateName = "Markdown-Default"
                }
            });
        }
        catch (Exception ex) {
            return Task.FromResult(new ReportResult {
                Success = false,
                FilePath = outputPath!,
                Format = ReportFormat.Markdown,
                ErrorMessage = ex.Message
            });
        }
    }

    internal static MarkdownDoc BuildMarkdown(DomainHealthCheck healthCheck, string domain) {
        // Assessments summary
        var assessments = healthCheck.GetAllAssessments().ToList();
        int warn = assessments.Count(a => a.Severity == AssessmentSeverity.Warning);
        int err = assessments.Count(a => a.Severity == AssessmentSeverity.Error);

        // Mail classification view (optional)
        DomainDetective.Views.MailClassificationInfo? mci = null;
        try {
            var classifier = new MailDomainClassifier(healthCheck, new InternalLogger(false));
            var res = classifier.ClassifyAsync(domain).GetAwaiter().GetResult();
            mci = Views.Converters.Convert(res);
        } catch { }

        var md = MarkdownDoc.Create()
          .FrontMatter(new { title = $"Domain Detective — {domain}", date = DateTimeOffset.Now.ToString("u") })
          .H1("Executive Summary")
          .Toc(opts => { opts.MinLevel = 1; opts.MaxLevel = 3; opts.Ordered = false; opts.IncludeTitle = false; opts.Collapsible = true; opts.Collapsed = false; }, placeAtTop: true)
          .H2("Overview")
          .P($"Report generated on {DateTime.Now:yyyy-MM-dd HH:mm:ss}")
          .Table(t => t
                .Headers("Key", "Value")
                .Row("Domain", domain)
                .Row("Status", err > 0 ? "🔴 Error" : (warn > 0 ? "🟠 Warning" : "🟢 OK"))
                .Row("Warnings", warn.ToString())
                .Row("Errors", err.ToString())
                .AlignLeft(0).AlignLeft(1));

        if (mci != null) {
            md.H2("Mail Classification")
              .Table(t => t
                    .Headers("Classification", "Confidence", "Receiving", "Sending")
                    .Row(mci.Classification, mci.Confidence,
                         string.Join(", ", mci.ReceivingSignals ?? Array.Empty<string>()),
                         string.Join(", ", mci.SendingSignals ?? Array.Empty<string>()))
                    .AlignLeft(0,1,2,3));

            if (mci.ScoreBreakdown != null && mci.ScoreBreakdown.Count > 0) {
                md.H3("Score Breakdown")
                  .Table(t => t
                        .Headers("Metric", "Value")
                        .Rows(mci.ScoreBreakdown.Select(kv => (IReadOnlyList<string>)new[]{ kv.Key, kv.Value.ToString("0.##") }))
                        .AlignLeft(0).AlignRight(1));
            }

            if (mci.Recommendations != null && mci.Recommendations.Count > 0) {
                md.H3("Recommendations").Ul(mci.Recommendations.Select(r => r.Title ?? r.Code).ToArray());
            }
            if (mci.Positives != null && mci.Positives.Count > 0) {
                md.H3("Positives").Ul(mci.Positives.Select(r => r.Title ?? r.Code).ToArray());
            }
            if (mci.References != null && mci.References.Count > 0) {
                md.H3("References");
                md.Ul(ul => {
                    foreach (var u in mci.References) ul.ItemLink(u, u);
                });
            }
        }

        return md;
    }
}
