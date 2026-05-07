using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Validates sitemap XML and sitemap-listed URLs.</summary>
/// <para>Checks sitemap discovery, XML shape, urlset and sitemapindex entries, duplicate locations, redirects, redirect loops, HTTP errors, noindex, and canonical mismatches.</para>
/// <example>
///   <summary>Scan the default sitemap for a domain.</summary>
///   <prefix>PS&gt; </prefix>
///   <code>Test-DDSitemap -Subject evotec.pl</code>
/// </example>
/// <example>
///   <summary>Scan a specific sitemap URL with a larger URL probe limit.</summary>
///   <prefix>PS&gt; </prefix>
///   <code>Test-DDSitemap -Subject https://example.com/sitemap.xml -MaxUrlProbes 1000</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDSitemap")]
[Alias("Test-Sitemap", "Test-DDXmlSitemap")]
[OutputType(typeof(DomainDetective.Views.SitemapInfo))]
public sealed class CmdletTestSitemap : ExportableAsyncPSCmdlet {
    /// <para>Domain, host, sitemap URL, or absolute HTTP/HTTPS URL to scan.</para>
    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    public string[] Subject = Array.Empty<string>();

    /// <para>HTTP timeout in seconds for each probe.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 300)]
    public int TimeoutSeconds { get; set; } = 20;

    /// <para>Maximum sitemap XML documents to fetch, including nested sitemapindex entries.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 1000)]
    public int MaxSitemapDocuments { get; set; } = 20;

    /// <para>Maximum URL entries to parse from urlset documents.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 1000000)]
    public int MaxEntries { get; set; } = 10000;

    /// <para>Maximum parsed URLs to probe for reachability and indexing signals.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 1000000)]
    public int MaxUrlProbes { get; set; } = 250;

    /// <para>Maximum redirect hops before treating a URL as a redirect loop.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 50)]
    public int MaxRedirects { get; set; } = 10;

    /// <para>Do not probe sitemap URL entries; only fetch and parse sitemap XML.</para>
    [Parameter(Mandatory = false)]
    public SwitchParameter NoUrlProbe { get; set; }

    /// <para>Do not inspect HTML noindex or canonical tags on successful URL probes.</para>
    [Parameter(Mandatory = false)]
    public SwitchParameter NoCanonicalCheck { get; set; }

    /// <para>Do not fall back to HTTP when HTTPS probing fails.</para>
    [Parameter(Mandatory = false)]
    public SwitchParameter NoHttpFallback { get; set; }

    /// <para>Optional user agent sent with probes.</para>
    [Parameter(Mandatory = false)]
    public string UserAgent { get; set; } = "Mozilla/5.0 (compatible; DomainDetective-Sitemap)";

    /// <summary>Runs sitemap analysis.</summary>
    /// <returns>A task that represents the asynchronous operation.</returns>
    protected override async Task ProcessRecordAsync() {
        async Task ProcessSubjectAsync(string subject) {
            var logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(
                logger,
                WriteVerbose,
                WriteWarning,
                WriteDebug,
                WriteError,
                WriteProgress,
                WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();

            logger.WriteVerbose("Checking sitemap for {0}", subject);
            var analysis = new SitemapAnalysis();
            var options = new SitemapAnalysisOptions {
                Timeout = TimeSpan.FromSeconds(TimeoutSeconds),
                AllowHttpFallback = !NoHttpFallback.IsPresent,
                ProbeUrls = !NoUrlProbe.IsPresent,
                CheckCanonical = !NoCanonicalCheck.IsPresent,
                MaxSitemapDocuments = MaxSitemapDocuments,
                MaxEntries = MaxEntries,
                MaxUrlProbes = MaxUrlProbes,
                MaxRedirects = MaxRedirects,
                UserAgent = UserAgent
            };

            await analysis.AnalyzeAsync(subject, logger, options, CancelToken).ConfigureAwait(false);
            var view = DomainDetective.Views.Converters.Convert(analysis);
            WriteObject(view);

            if (IsExportRequested()) {
                try {
                    var hadUnsupportedFormats = false;
                    CompositionExportHelper.WriteReports(
                        new List<object> { view },
                        GetRequestedFormatsOrDefault(ExportDefaults.Format),
                        ExportPath,
                        subject,
                        DomainDetective.Reports.ReportScope.Normal,
                        $"Sitemap Report - {subject}",
                        OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                        TryOpenReport,
                        out hadUnsupportedFormats);

                    if (hadUnsupportedFormats) {
                        await ExportNotImplementedAsync("Test-DDSitemap").ConfigureAwait(false);
                    }
                } catch (Exception ex) {
                    WriteWarning($"Sitemap export failed: {ex.Message}");
                }
            }
        }

        await ForEachAsync(Subject, ProcessSubjectAsync).ConfigureAwait(false);
    }
}
