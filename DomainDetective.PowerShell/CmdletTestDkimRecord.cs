using System;
using DnsClientX;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates DKIM records for the specified selectors.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Verify DKIM selectors.</summary>
    ///   <code>Test-DDEmailDkimRecord -DomainName example.com -Selectors selector1</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailDkimRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailDkim")]
    public sealed class CmdletTestDkimRecord : ExportableAsyncPSCmdlet {
        /// <para>Domain(s) to query.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = System.Array.Empty<string>();

        /// <para>Selectors to validate. When omitted, common selectors are auto-detected.</para>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public string[] Selectors = System.Array.Empty<string>();

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 2, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <para>Return full analysis result.</para>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter FullResponse;

        // View-by-default: Raw analysis is attached to view.Raw

        private readonly System.Collections.Generic.List<object> _items = new();
        private readonly System.Collections.Generic.List<string> _subjects = new();
        private readonly object _exportLock = new();

        // BeginProcessing handled per-domain to allow safe parallelism.
        /// <summary>
        /// Validates DKIM records for the provided selectors.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        /// <summary>Processes each domain, emits DKIM view(s), and accumulates for optional composition export.</summary>
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

                logger.WriteVerbose("Querying DKIM records for domain: {0}", domain);
                var selectors = Selectors ?? Array.Empty<string>();
                var includeMissingSelectors = selectors.Length > 0;
                await healthCheck.VerifyDKIM(domain, selectors, includeMissingSelectors, cancellationToken: CancelToken);
                var output = DomainDetective.Views.Converters.Convert(healthCheck.DKIMAnalysis).ToList();
                if (!includeMissingSelectors && output.Count == 0) {
                    WriteWarning($"No DKIM selectors found for {domain}. Provide -Selectors to test specific selectors.");
                } else if (includeMissingSelectors && output.Count > 0 && output.All(x => !x.DkimRecordExists)) {
                    var checkedSelectors = string.Join(", ", selectors.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()));
                    if (!string.IsNullOrWhiteSpace(checkedSelectors)) {
                        WriteWarning($"No matching DKIM selectors found for {domain} (checked: {checkedSelectors}).");
                    } else {
                        WriteWarning($"No matching DKIM selectors found for {domain}.");
                    }
                }
                WriteObject(output, true);

                if (IsExportRequested()) {
                    var fmt = (ExportFormat != null && ExportFormat.Length > 0) ? ExportFormat[0] : ExportDefaults.Format;
                    if (fmt == DomainDetective.Reports.ReportFormat.Word || fmt == DomainDetective.Reports.ReportFormat.Html) {
                        lock (_exportLock) {
                            _items.AddRange(output);
                            if (!_subjects.Contains(domain, StringComparer.OrdinalIgnoreCase)) {
                                _subjects.Add(domain);
                            }
                        }
                    } else {
                        await ExportNotImplementedAsync("Test-DDEmailDkimRecord");
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }

        /// <summary>Composes DKIM sections into one document for Word/HTML export.</summary>
        protected override Task EndProcessingAsync() {
            if (_items.Count == 0) return Task.CompletedTask;
            var fmt = (ExportFormat != null && ExportFormat.Length > 0) ? ExportFormat[0] : ExportDefaults.Format;
            if (fmt != DomainDetective.Reports.ReportFormat.Word && fmt != DomainDetective.Reports.ReportFormat.Html) return Task.CompletedTask;

            var label = _subjects.Count switch {
                0 => "dkim",
                1 => _subjects[0],
                2 => $"{_subjects[0]}+{_subjects[1]}",
                _ => $"{_subjects[0]}+{_subjects[1]}(+{_subjects.Count - 2})"
            };
            var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, label, fmt);
            try {
                if (fmt == DomainDetective.Reports.ReportFormat.Word) {
                    DomainDetective.Reports.Office.WordCompositionReport.Generate(
                        outPath,
                        _items,
                        DomainDetective.Reports.ReportScope.Detailed,
                        showInfoFindings: true,
                        narrativePlacement: ExportDefaults.NarrativePlacement,
                        titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"DKIM Report — {label}" : ExportDefaults.NarrativeTitle,
                        subjectOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject,
                        categoryOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCategory) ? null : ExportDefaults.NarrativeCategory,
                        keywordsOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeKeywords) ? null : ExportDefaults.NarrativeKeywords,
                        creatorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                        summaryColumnCap: ExportDefaults.SummaryColumnCap,
                        headerLogoSizePx: ExportDefaults.HeaderLogoSizePx,
                        footerLogoSizePx: ExportDefaults.FooterLogoSizePx);
                    if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                } else {
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
                WriteWarning($"DKIM export failed: {ex.Message}");
            }
            return Task.CompletedTask;
        }
    }
}

