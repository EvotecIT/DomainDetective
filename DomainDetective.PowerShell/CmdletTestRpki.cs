using System;
using System.Linq;
using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates RPKI origins for domain IPs.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>Outputs a view object with full raw analysis attached at Raw.</remarks>
    /// <example>
    ///   <summary>Check RPKI status.</summary>
    ///   <code>Test-DDRpki -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDRpki", DefaultParameterSetName = "ServerName")]
    [Alias("Test-Rpki")]
    public sealed class CmdletTestRpki : ExportableAsyncPSCmdlet {
        /// <summary>Domain name(s) to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string[] DomainName = Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        private readonly System.Collections.Generic.List<object> _items = new();
        private readonly System.Collections.Generic.List<string> _subjects = new();
        private readonly object _exportLock = new();

        // BeginProcessing handled per-domain to allow safe parallelism.

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            async Task ProcessDomainAsync(string domain) {
                var logger = new InternalLogger(false);
                var psLogger = new InternalLoggerPowerShell(
                    logger,
                    WriteVerbose,
                    WriteWarning,
                    WriteDebug,
                    WriteError,
                    WriteProgress,
                    WriteInformation);
                psLogger.ResetActivityIdCounter();
                var healthCheck = new DomainHealthCheck(DnsEndpoint, logger);
                ApplyExecutionOptions(healthCheck);

                logger.WriteVerbose("Querying RPKI for domain: {0}", domain);
                await healthCheck.VerifyRPKI(domain, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.RpkiAnalysis);
                WriteObject(view);
                if (!IsExportRequested()) {
                    return;
                }
                var fmts = GetRequestedFormatsOrDefault(ExportDefaults.Format);
                foreach (var fmt in fmts) {
                    if (fmt == DomainDetective.Reports.ReportFormat.Word || fmt == DomainDetective.Reports.ReportFormat.Html) {
                        lock (_exportLock) {
                            _items.Add(view);
                            if (!_subjects.Contains(domain, StringComparer.OrdinalIgnoreCase)) {
                                _subjects.Add(domain);
                            }
                        }
                    } else {
                        await ExportNotImplementedAsync("Test-DDRpki");
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }

        /// <summary>Finalizes multi-domain exports for Word/HTML by composing a single file.</summary>
        protected override Task EndProcessingAsync() {
            if (_items.Count == 0) {
                return Task.CompletedTask;
            }
            var fmts = GetRequestedFormatsOrDefault(ExportDefaults.Format);
            var needsWord = Array.Exists(fmts.ToArray(), f => f == DomainDetective.Reports.ReportFormat.Word);
            var needsHtml = Array.Exists(fmts.ToArray(), f => f == DomainDetective.Reports.ReportFormat.Html);
            if (!needsWord && !needsHtml) {
                return Task.CompletedTask;
            }

            var label = _subjects.Count switch {
                0 => "rpki",
                1 => _subjects[0],
                2 => $"{_subjects[0]}+{_subjects[1]}",
                _ => $"{_subjects[0]}+{_subjects[1]}(+{_subjects.Count - 2})"
            };
            try {
                if (needsWord) {
                    var outPath = ResolveOutPathForFormat(ExportPath, ExportDefaults.OutputDirectory, label, DomainDetective.Reports.ReportFormat.Word, fmts);
                    DomainDetective.Reports.Office.WordCompositionReport.Generate(
                        outPath,
                        _items,
                        DomainDetective.Reports.ReportScope.Normal,
                        showInfoFindings: true,
                        narrativePlacement: ExportDefaults.NarrativePlacement,
                        titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"RPKI Report — {label}" : ExportDefaults.NarrativeTitle,
                        subjectOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject,
                        categoryOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCategory) ? null : ExportDefaults.NarrativeCategory,
                        keywordsOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeKeywords) ? null : ExportDefaults.NarrativeKeywords,
                        creatorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
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
                        DomainDetective.Reports.ReportScope.Normal,
                        OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                        ExportDefaults.NarrativePlacement,
                        titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? null : ExportDefaults.NarrativeTitle,
                        authorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                        descriptionOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject);
                }
            } catch (System.Exception ex) {
                WriteWarning($"RPKI export failed: {ex.Message}");
            }
            return Task.CompletedTask;
        }
    }
}

