using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates DMARC record for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check DMARC settings.</summary>
    ///   <code>Test-DDEmailDmarcRecord -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailDmarcRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailDmarc")]
    public sealed class CmdletTestDmarcRecord : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string[] DomainName;

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        // View-by-default: Raw analysis is attached to view.Raw

        private InternalLogger _logger;
        private DomainHealthCheck healthCheck;
        private readonly System.Collections.Generic.List<object> _items = new();
        private readonly System.Collections.Generic.List<string> _subjects = new();

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        /// <summary>Processes each domain, emits DMARC view, and accumulates for optional composition export.</summary>
        protected override async Task ProcessRecordAsync() {
            foreach (var domain in DomainName) {
                _logger.WriteVerbose("Querying DMARC record for domain: {0}", domain);
                await healthCheck.VerifyDMARC(domain);
                var output = DomainDetective.Views.Converters.Convert(healthCheck.DmarcAnalysis);
                WriteObject(output);
                if (IsExportRequested()) {
                    var fmt = ExportFormat ?? ExportDefaults.Format;
                    if (fmt == DomainDetective.Reports.ReportFormat.Word || fmt == DomainDetective.Reports.ReportFormat.Html) {
                        _items.Add(output);
                        _subjects.Add(domain);
                    } else {
                        await ExportNotImplementedAsync("Test-DDEmailDmarcRecord");
                    }
                }
            }
        }

        /// <summary>Composes DMARC sections into one document for Word/HTML export.</summary>
        protected override Task EndProcessingAsync() {
            if (_items.Count == 0) return Task.CompletedTask;
            var fmt = ExportFormat ?? ExportDefaults.Format;
            if (fmt != DomainDetective.Reports.ReportFormat.Word && fmt != DomainDetective.Reports.ReportFormat.Html) return Task.CompletedTask;

            var label = _subjects.Count switch {
                0 => "dmarc",
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
                        titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"DMARC Report — {label}" : ExportDefaults.NarrativeTitle,
                        subjectOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject,
                        categoryOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCategory) ? null : ExportDefaults.NarrativeCategory,
                        keywordsOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeKeywords) ? null : ExportDefaults.NarrativeKeywords,
                        creatorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator);
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
                WriteWarning($"DMARC export failed: {ex.Message}");
            }
            return Task.CompletedTask;
        }
    }
}
