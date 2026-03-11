using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;
using DomainDetective.Views;

namespace DomainDetective.PowerShell {
    /// <summary>Lists domains hosted on the same IP.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Returns a unified IpNeighborInfo view including total addresses and neighbor domain counts.
    /// Raw exposes the full IPNeighborAnalysis.
    /// </remarks>
    /// <example>
    ///   <summary>Check IP neighbors.</summary>
    ///   <code>Test-DDNetworkIpNeighbor -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDNetworkIpNeighbor", DefaultParameterSetName = "ServerName")]
    [Alias("Test-NetworkIpNeighbor")]
    [OutputType(typeof(IpNeighborInfo))]
    public sealed class CmdletTestIPNeighbor : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>Include MX host neighbor analysis.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter IncludeMX;

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

                logger.WriteVerbose("Querying IP neighbors for domain: {0}", domain);
                await healthCheck.Verify(domain, new[] { HealthCheckType.IPNEIGHBOR }, cancellationToken: CancelToken);
                if (IncludeMX.IsPresent) {
                    await healthCheck.CheckMailIPNeighbors(domain, cancellationToken: CancelToken);
                }
                var view = DomainDetective.Views.Converters.Convert(healthCheck.IPNeighborAnalysis);
                WriteObject(view);
                if (IsExportRequested()) {
                    try {
                        var hadUnsupportedFormats = false;
                        CompositionExportHelper.WriteReports(
                            new System.Collections.Generic.List<object> { view },
                            GetRequestedFormatsOrDefault(ExportDefaults.Format),
                            ExportPath,
                            domain,
                            DomainDetective.Reports.ReportScope.Normal,
                            $"IP Neighbor Report - {domain}",
                            OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                            TryOpenReport,
                            out hadUnsupportedFormats);

                        if (hadUnsupportedFormats) {
                            await ExportNotImplementedAsync("Test-DDNetworkIpNeighbor");
                        }
                    } catch (System.Exception ex) {
                        WriteWarning($"IP neighbor export failed: {ex.Message}");
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
