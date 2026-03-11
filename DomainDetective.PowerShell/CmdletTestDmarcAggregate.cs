using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Globalization;
using DomainDetective.Helpers;
using System.Management.Automation;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace DomainDetective.PowerShell {
    /// <summary>Parses DMARC aggregate XML reports.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Summarize aggregate reports.</summary>
    ///   <code>Get-ChildItem ./reports/*.xml | Test-DDDmarcAggregate</code>
    /// </example>
    /// <summary>Controls how DMARC aggregate records are summarized.</summary>
    public enum DmarcAggregateSummarizeBy {
        /// <summary>Summarize by RFC5322.From domain.</summary>
        Domain,
        /// <summary>Summarize by source IP address.</summary>
        Ip,
        /// <summary>Summarize by header_from field.</summary>
        HeaderFrom,
        /// <summary>Summarize by reporting organization/email (from report_metadata).</summary>
        Reporter,
        /// <summary>Summarize by origin ASN (enrichment).</summary>
        Asn,
        /// <summary>Summarize by country (enrichment).</summary>
        Country
    }

    /// <summary>
    /// Cmdlet to parse DMARC aggregate reports and summarize failures.
    /// </summary>
    [Cmdlet(VerbsDiagnostic.Test, "DDDmarcAggregate")]
    [Alias("Test-EmailDmarcAggregate", "Test-DmarcAggregate")]
    public sealed class CmdletTestDmarcAggregate : ExportableAsyncPSCmdlet {
        /// <para>Path to a report file, a directory, or a wildcard pattern (supports .xml|.gz|.zip).</para>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string Path { get; set; } = string.Empty;

        /// <summary>Summarization mode: Domain (default), Ip, or HeaderFrom.</summary>
        [Parameter(Mandatory = false)]
        public DmarcAggregateSummarizeBy SummarizeBy { get; set; } = DmarcAggregateSummarizeBy.Domain;

        /// <summary>When set, attempts to de-duplicate reports using report-id + date range.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter Deduplicate { get; set; }

        /// <summary>Emit JSON for the summary to the pipeline.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter Json { get; set; }

        /// <summary>
        /// Parses the specified DMARC aggregate report and writes each summary.
        /// </summary>
        /// <returns>A completed task.</returns>
        protected override async Task ProcessRecordAsync() {
            var files = ExpandPaths(Path);
            var reports = new List<DmarcAggregateReport>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            IReadOnlyList<object> exportItems;
            foreach (var f in files) {
                try {
                    var report = DmarcReportParser.Parse(f);
                    if (Deduplicate.IsPresent) {
                        var key = $"{report.ReportId}|{report.RangeBeginUtc?.UtcDateTime:o}|{report.RangeEndUtc?.UtcDateTime:o}";
                        if (!string.IsNullOrWhiteSpace(report.ReportId) && !seen.Add(key)) {
                            continue;
                        }
                    }
                    reports.Add(report);
                } catch (Exception ex) {
                    WriteWarning($"Failed to parse '{f}': {ex.Message}");
                }
            }

            var allRecords = reports.SelectMany(r => r.Records).ToList();
            switch (SummarizeBy) {
                case DmarcAggregateSummarizeBy.Ip:
                    var ip = allRecords.SummarizeFailuresByIp().OrderByDescending(x => x.Count).ToList();
                    WriteObject(ip, true);
                    ExportIfRequested(ip);
                    exportItems = ip.Cast<object>().ToList();
                    break;
                case DmarcAggregateSummarizeBy.HeaderFrom:
                    var hf = allRecords.SummarizeFailuresByHeaderFrom().OrderByDescending(x => x.Count).ToList();
                    WriteObject(hf, true);
                    ExportIfRequested(hf);
                    exportItems = hf.Cast<object>().ToList();
                    break;
                case DmarcAggregateSummarizeBy.Reporter:
                    var pairs = reports.SelectMany(r => r.Records.Select(rec => (Report: r, Record: rec))).ToList();
                    var rep = pairs.SummarizeFailuresByReporter().OrderByDescending(x => x.Count).ToList();
                    WriteObject(rep, true);
                    ExportIfRequested(rep);
                    exportItems = rep.Cast<object>().ToList();
                    break;
                case DmarcAggregateSummarizeBy.Asn:
                    // Enrich with ASN & Country prior to summarizing
                    DmarcAggregateEnrichment.EnrichAsync(allRecords).GetAwaiter().GetResult();
                    var asn = allRecords.SummarizeFailuresByAsn().OrderByDescending(x => x.Count).ToList();
                    WriteObject(asn, true);
                    ExportIfRequested(asn);
                    exportItems = asn.Cast<object>().ToList();
                    break;
                case DmarcAggregateSummarizeBy.Country:
                    DmarcAggregateEnrichment.EnrichAsync(allRecords).GetAwaiter().GetResult();
                    var ctry = allRecords.SummarizeFailuresByCountry().OrderByDescending(x => x.Count).ToList();
                    WriteObject(ctry, true);
                    ExportIfRequested(ctry);
                    exportItems = ctry.Cast<object>().ToList();
                    break;
                default:
                    var byDomain = SummarizeByDomain(allRecords).OrderByDescending(x => x.TotalCount).ToList();
                    WriteObject(byDomain, true);
                    ExportIfRequested(byDomain);
                    exportItems = byDomain.Cast<object>().ToList();
                    break;
            }
            if (IsExportRequested()) {
                await ExportReportsAsync(exportItems);
            }
        }

        private static IEnumerable<string> ExpandPaths(string input) {
            var exts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".xml", ".gz", ".gzip", ".zip" };
            if (Directory.Exists(input)) {
                return Directory.EnumerateFiles(input).Where(f => exts.Contains(System.IO.Path.GetExtension(f)));
            }
            if (input.IndexOf('*') >= 0 || input.IndexOf('?') >= 0) {
                var dir = System.IO.Path.GetDirectoryName(input);
                var pat = System.IO.Path.GetFileName(input);
                if (string.IsNullOrEmpty(dir)) dir = ".";
                var matches = Directory.EnumerateFiles(dir, pat);
                return matches.Where(f => exts.Contains(System.IO.Path.GetExtension(f)));
            }
            return File.Exists(input) ? new [] { input } : Array.Empty<string>();
        }

        private static IEnumerable<DmarcAggregateSummary> SummarizeByDomain(IEnumerable<DmarcAggregateRecord> records) {
            var table = new Dictionary<string, DmarcAggregateSummary>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in records) {
                var domain = r.HeaderFrom;
                if (string.IsNullOrWhiteSpace(domain)) continue;
                if (!table.TryGetValue(domain, out var s)) {
                    s = new DmarcAggregateSummary { Domain = domain };
                    table.Add(domain, s);
                }
                s.TotalCount += r.Count;
                if (r.IsPass) s.PassCount += r.Count; else s.FailCount += r.Count;
            }
            return table.Values;
        }

        private void ExportIfRequested<T>(IEnumerable<T> data) {
            if (Json.IsPresent) {
                var json = System.Text.Json.JsonSerializer.Serialize(data, DomainDetective.Helpers.JsonOptions.Default);
                WriteObject(json);
            }
        }

        private async Task ExportReportsAsync(IReadOnlyList<object> items) {
            var formats = GetRequestedFormatsOrDefault(ExportDefaults.Format);
            var label = $"dmarc-aggregate-{SummarizeBy.ToString().ToLowerInvariant()}";
            var supportedCompositionFormats = formats
                .Where(f => f == DomainDetective.Reports.ReportFormat.Word || f == DomainDetective.Reports.ReportFormat.Html)
                .ToArray();
            var generated = false;
            var hadUnsupportedFormats = formats.Any(f =>
                f != DomainDetective.Reports.ReportFormat.Word
                && f != DomainDetective.Reports.ReportFormat.Html
                && f != DomainDetective.Reports.ReportFormat.Json);

            if (supportedCompositionFormats.Length > 0) {
                try {
                    var compositionUnsupportedFormats = false;
                    CompositionExportHelper.WriteReports(
                        items,
                        supportedCompositionFormats,
                        ExportPath,
                        label,
                        DomainDetective.Reports.ReportScope.Normal,
                        $"DMARC Aggregate Report - {SummarizeBy}",
                        OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                        TryOpenReport,
                        out compositionUnsupportedFormats);
                    generated = true;
                    hadUnsupportedFormats |= compositionUnsupportedFormats;
                } catch (Exception ex) {
                    WriteWarning($"DMARC aggregate export failed: {ex.Message}");
                }
            }

            if (formats.Contains(DomainDetective.Reports.ReportFormat.Json)) {
                try {
                    var outPath = ResolveOutPathForFormat(
                        ExportPath,
                        ExportDefaults.OutputDirectory,
                        label,
                        DomainDetective.Reports.ReportFormat.Json,
                        formats);
                    var json = System.Text.Json.JsonSerializer.Serialize(items, DomainDetective.Helpers.JsonOptions.Default);
                    File.WriteAllText(outPath, json);
                    generated = true;
                    WriteVerbose($"DMARC aggregate JSON saved: {outPath}");
                    if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) {
                        TryOpenReport(outPath);
                    }
                } catch (Exception ex) {
                    WriteWarning($"DMARC aggregate JSON export failed: {ex.Message}");
                }
            }

            if (!generated || hadUnsupportedFormats) {
                await ExportNotImplementedAsync("Test-DDDmarcAggregate");
            }
        }
    }

    /// <summary>Summarized DMARC aggregate statistics for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    public sealed class DmarcAggregateSummary {
        /// <summary>Domain name the statistics apply to.</summary>
        public string Domain { get; set; } = string.Empty;

        /// <summary>Total messages seen for the domain.</summary>
        public int TotalCount { get; set; }

        /// <summary>Messages passing DMARC evaluation.</summary>
        public int PassCount { get; set; }

        /// <summary>Messages failing DMARC evaluation.</summary>
        public int FailCount { get; set; }
    }
}
