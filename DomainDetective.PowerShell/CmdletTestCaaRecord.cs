using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates CAA records for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check CAA entries.</summary>
    ///   <code>Test-DDDnsCaaRecord -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsCaaRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-DnsCaa")]
    public sealed class CmdletTestCaaRecord : ExportableAsyncPSCmdlet {
        /// <para>Domain to query.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName = string.Empty;

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        private InternalLogger _logger = null!;
        private DomainHealthCheck healthCheck = null!;

        /// <summary>
        /// Initializes the CAA record health check.
        /// </summary>
        /// <returns>A completed task.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            ApplyExecutionOptions(healthCheck);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Validates CAA records for the domain.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying CAA record for domain: {0}", DomainName);
            await healthCheck.VerifyCAA(DomainName);
            var view = DomainDetective.Views.Converters.Convert(healthCheck.CAAAnalysis);
            WriteObject(view);
            if (IsExportRequested()) {
                var fmt = (ExportFormat != null && ExportFormat.Length > 0) ? ExportFormat[0] : ExportDefaults.Format;
                if (fmt == DomainDetective.Reports.ReportFormat.Word) {
                    var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, DomainName, fmt);
                    try {
                        DomainDetective.Reports.Office.WordCompositionReport.Generate(
                            outPath,
                            new System.Collections.Generic.List<object> { view },
                            DomainDetective.Reports.ReportScope.Normal,
                            showInfoFindings: true,
                            narrativePlacement: ExportDefaults.NarrativePlacement,
                            titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"CAA Report — {DomainName}" : ExportDefaults.NarrativeTitle,
                            summaryColumnCap: ExportDefaults.SummaryColumnCap,
                            headerLogoSizePx: ExportDefaults.HeaderLogoSizePx,
                            footerLogoSizePx: ExportDefaults.FooterLogoSizePx);
                        if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                    } catch (System.Exception ex) {
                        WriteWarning($"CAA export failed: {ex.Message}");
                    }
                } else {
                    await ExportNotImplementedAsync("Test-DDDnsCaaRecord");
                }
                return;
            }
        }
    }
}


