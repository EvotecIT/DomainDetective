using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates TLS-RPT record for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>Outputs a view object with full raw analysis attached at Raw.</remarks>
    /// <example>
    ///   <summary>Check TLS report policy.</summary>
    ///   <code>Test-DDEmailTlsRptRecord -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailTlsRptRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailTlsRpt")]
    public sealed class CmdletTestTlsRptRecord : ExportableAsyncPSCmdlet {
        /// <summary>Domain name(s) to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        private InternalLogger _logger = null!;
        private DomainHealthCheck healthCheck = null!;

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
        protected override async Task ProcessRecordAsync() {
            var items = new System.Collections.Generic.List<object>();
            foreach (var domain in DomainName) {
                _logger.WriteVerbose("Querying TLSRPT record for domain: {0}", domain);
                await healthCheck.VerifyTLSRPT(domain);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.TLSRPTAnalysis);
                WriteObject(view);
                if (IsExportRequested()) items.Add(view);
            }
            if (IsExportRequested()) {
                var fmt = (ExportFormat != null && ExportFormat.Length > 0) ? ExportFormat[0] : ExportDefaults.Format;
                if (fmt == DomainDetective.Reports.ReportFormat.Word) {
                    var key = DomainName.Length switch { 0 => "tlsrpt", 1 => DomainName[0], 2 => $"{DomainName[0]}+{DomainName[1]}", _ => $"{DomainName[0]}+{DomainName[1]}(+{DomainName.Length-2})" };
                    var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, key, fmt);
                    try {
                        DomainDetective.Reports.Office.WordCompositionReport.Generate(
                            outPath,
                            items,
                            DomainDetective.Reports.ReportScope.Normal,
                            showInfoFindings: true,
                            narrativePlacement: ExportDefaults.NarrativePlacement,
                            titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"TLS-RPT Report — {key}" : ExportDefaults.NarrativeTitle,
                            subjectOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject,
                            categoryOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCategory) ? null : ExportDefaults.NarrativeCategory,
                            keywordsOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeKeywords) ? null : ExportDefaults.NarrativeKeywords,
                            creatorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator);
                        if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                    } catch (System.Exception ex) {
                        WriteWarning($"TLS-RPT export failed: {ex.Message}");
                    }
                } else {
                    await ExportNotImplementedAsync("Test-DDEmailTlsRptRecord");
                }
                return;
            }
        }
    }
}
