using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Retrieves NS records for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Query name servers.</summary>
    ///   <code>Test-DDDnsNsRecord -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsNsRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-DnsNs")]
    public sealed class CmdletTestNsRecord : ExportableAsyncPSCmdlet {
        /// <summary>Domain to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        private InternalLogger _logger;
        private DomainHealthCheck healthCheck;

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
            _logger.WriteVerbose("Querying NS record for domain: {0}", DomainName);
            await healthCheck.VerifyNS(DomainName);
            var view = DomainDetective.Views.Converters.Convert(healthCheck.NSAnalysis);
            WriteObject(view);
            if (IsExportRequested()) {
                var fmt = ExportFormat ?? ExportDefaults.Format;
                if (fmt == DomainDetective.Reports.ReportFormat.Word) {
                    var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, DomainName, fmt);
                    try {
                        DomainDetective.Reports.Office.WordCompositionReport.Generate(
                            outPath,
                            new System.Collections.Generic.List<object> { view },
                            DomainDetective.Reports.ReportScope.Normal,
                            showInfoFindings: true,
                            narrativePlacement: ExportDefaults.NarrativePlacement,
                            titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"NS Report — {DomainName}" : ExportDefaults.NarrativeTitle);
                        if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                    } catch (System.Exception ex) {
                        WriteWarning($"NS export failed: {ex.Message}");
                    }
                } else {
                    await ExportNotImplementedAsync("Test-DDDnsNsRecord");
                }
                return;
            }
        }
    }
}
