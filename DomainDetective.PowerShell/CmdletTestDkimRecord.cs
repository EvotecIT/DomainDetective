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
        public string[] DomainName;

        /// <para>Selectors to validate. When omitted, common selectors are auto-detected.</para>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public string[] Selectors;

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 2, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <para>Return full analysis result.</para>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter FullResponse;

        // View-by-default: Raw analysis is attached to view.Raw

        private InternalLogger _logger;
        private DomainHealthCheck healthCheck;
        private readonly System.Collections.Generic.List<object> _items = new();
        private readonly System.Collections.Generic.List<string> _subjects = new();

        /// <summary>
        /// Initializes DKIM checking with the current settings.
        /// </summary>
        /// <returns>A completed task.</returns>
        protected override Task BeginProcessingAsync() {
            // Initialize the logger to be able to see verbose, warning, debug, error, progress, and information messages.
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            // initialize the health check object
            healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }
        /// <summary>
        /// Validates DKIM records for the provided selectors.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        /// <summary>Processes each domain, emits DKIM view(s), and accumulates for optional composition export.</summary>
        protected override async Task ProcessRecordAsync() {
            foreach (var domain in DomainName) {
                _logger.WriteVerbose("Querying DKIM records for domain: {0}", domain);
                await healthCheck.VerifyDKIM(domain, Selectors);
                var output = DomainDetective.Views.Converters.Convert(healthCheck.DKIMAnalysis).ToList();
                WriteObject(output, true);

                if (IsExportRequested()) {
                    var fmt = ExportFormat ?? ExportDefaults.Format;
                    if (fmt == DomainDetective.Reports.ReportFormat.Word || fmt == DomainDetective.Reports.ReportFormat.Html) {
                        _items.AddRange(output);
                        _subjects.Add(domain);
                    } else {
                        await ExportNotImplementedAsync("Test-DDEmailDkimRecord");
                    }
                }
            }
        }

        /// <summary>Composes DKIM sections into one document for Word/HTML export.</summary>
        protected override Task EndProcessingAsync() {
            if (_items.Count == 0) return Task.CompletedTask;
            var fmt = ExportFormat ?? ExportDefaults.Format;
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
                        titleOverride: $"DKIM Report — {label}");
                    if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                } else {
                    DomainDetective.Reports.Html.HtmlCompositionReport.Generate(outPath, _items, DomainDetective.Reports.ReportScope.Detailed, OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser, ExportDefaults.NarrativePlacement);
                }
            } catch (System.Exception ex) {
                WriteWarning($"DKIM export failed: {ex.Message}");
            }
            return Task.CompletedTask;
        }
    }
}
