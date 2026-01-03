using System;
using DnsClientX;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates SPF record for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check SPF configuration.</summary>
    ///   <code>Test-DDEmailSpfRecord -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailSpfRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailSpf")]
    public sealed class CmdletTestSpfRecord : ExportableAsyncPSCmdlet {
        /// <summary>Domain to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        //[Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        //public SwitchParameter FullResponse;

        private readonly System.Collections.Generic.List<object> _items = new();
        private readonly System.Collections.Generic.List<string> _subjects = new();
        private readonly object _exportLock = new();

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            async Task ProcessDomainAsync(string domain) {
                var logger = new InternalLogger(false);
                var internalLoggerPowerShell = new InternalLoggerPowerShell(
                    logger,
                    this.WriteVerbose,
                    this.WriteWarning,
                    this.WriteDebug,
                    this.WriteError,
                    this.WriteProgress,
                    this.WriteInformation);
                internalLoggerPowerShell.ResetActivityIdCounter();
                var healthCheck = new DomainHealthCheck(DnsEndpoint, logger);
                ApplyExecutionOptions(healthCheck);

                logger.WriteVerbose("Querying SPF record for domain: {0}", domain);
                await healthCheck.VerifySPF(domain, cancellationToken: CancelToken);
                var output = DomainDetective.Views.Converters.Convert(healthCheck.SpfAnalysis);
                WriteObject(output);

                if (!IsExportRequested()) {
                    return;
                }
                var fmts = GetRequestedFormatsOrDefault(ExportDefaults.Format);
                foreach (var fmt in fmts) {
                    if (fmt == DomainDetective.Reports.ReportFormat.Word || fmt == DomainDetective.Reports.ReportFormat.Html) {
                        lock (_exportLock) {
                            _items.Add(output);
                            if (!_subjects.Contains(domain, StringComparer.OrdinalIgnoreCase)) {
                                _subjects.Add(domain);
                            }
                        }
                    } else if (fmt == DomainDetective.Reports.ReportFormat.Json) {
                        var outPath = ResolveOutPathForFormat(ExportPath, ExportDefaults.OutputDirectory, domain, fmt, fmts);
                        try {
                            var json = System.Text.Json.JsonSerializer.Serialize(healthCheck.SpfAnalysis, DomainDetective.Helpers.JsonOptions.Default);
                            System.IO.File.WriteAllText(outPath, json);
                            WriteVerbose($"SPF JSON saved: {outPath}");
                            if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) {
                                TryOpenReport(outPath);
                            }
                        } catch (System.Exception ex) {
                            WriteWarning($"SPF export failed: {ex.Message}");
                        }
                    } else {
                        await ExportNotImplementedAsync("Test-DDEmailSpfRecord");
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }

        /// <summary>
        /// Finalizes multi-domain exports for Word/HTML by composing a single file.
        /// </summary>
        protected override Task EndProcessingAsync() {
            if (_items.Count == 0) return Task.CompletedTask;
            var fmts = GetRequestedFormatsOrDefault(ExportDefaults.Format);
            var needsWord = Array.Exists(fmts.ToArray(), f => f == DomainDetective.Reports.ReportFormat.Word);
            var needsHtml = Array.Exists(fmts.ToArray(), f => f == DomainDetective.Reports.ReportFormat.Html);
            if (!needsWord && !needsHtml) return Task.CompletedTask;

            var label = DomainName.Length switch {
                0 => "spf",
                1 => DomainName[0],
                2 => $"{DomainName[0]}+{DomainName[1]}",
                _ => $"{DomainName[0]}+{DomainName[1]}(+{DomainName.Length - 2})"
            };
            try {
                if (needsWord) {
                    var outPath = ResolveOutPathForFormat(ExportPath, ExportDefaults.OutputDirectory, label, DomainDetective.Reports.ReportFormat.Word, fmts);
                    DomainDetective.Reports.Office.WordCompositionReport.Generate(
                        outPath,
                        _items,
                        DomainDetective.Reports.ReportScope.Detailed,
                        showInfoFindings: true,
                        narrativePlacement: ExportDefaults.NarrativePlacement,
                        titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"SPF Report — {label}" : ExportDefaults.NarrativeTitle,
                        subjectOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject,
                        categoryOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCategory) ? null : ExportDefaults.NarrativeCategory,
                        keywordsOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeKeywords) ? null : ExportDefaults.NarrativeKeywords,
                        creatorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                        companyName: string.IsNullOrWhiteSpace(ExportDefaults.CompanyName) ? null : ExportDefaults.CompanyName,
                        companyAddress: string.IsNullOrWhiteSpace(ExportDefaults.CompanyAddress) ? null : ExportDefaults.CompanyAddress,
                        companyYear: string.IsNullOrWhiteSpace(ExportDefaults.CompanyYear) ? null : ExportDefaults.CompanyYear,
                        logoPath: string.IsNullOrWhiteSpace(ExportDefaults.LogoPath) ? null : ExportDefaults.LogoPath,
                        headerText: string.IsNullOrWhiteSpace(ExportDefaults.HeaderText) ? null : ExportDefaults.HeaderText,
                        watermarkText: string.IsNullOrWhiteSpace(ExportDefaults.WatermarkText) ? null : ExportDefaults.WatermarkText,
                        summaryColumnCap: ExportDefaults.SummaryColumnCap,
                        headerLogoSizePx: ExportDefaults.HeaderLogoSizePx,
                        footerLogoSizePx: ExportDefaults.FooterLogoSizePx);
                    if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                }
                if (needsHtml) {
                    var outPath = ResolveOutPathForFormat(ExportPath, ExportDefaults.OutputDirectory, label, DomainDetective.Reports.ReportFormat.Html, fmts);
                    DomainDetective.Reports.Html.HtmlCompositionReport.Generate(
                        outPath,
                        _items,
                        DomainDetective.Reports.ReportScope.Detailed,
                        OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                        ExportDefaults.NarrativePlacement,
                        titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? null : ExportDefaults.NarrativeTitle,
                        authorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                        descriptionOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject);
                }
            } catch (System.Exception ex) {
                WriteWarning($"SPF export failed: {ex.Message}");
            }
            return Task.CompletedTask;
        }
    }
}

