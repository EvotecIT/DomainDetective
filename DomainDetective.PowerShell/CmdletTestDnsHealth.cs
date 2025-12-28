using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Runs authoritative DNS health checks (SOA serial skew, apex A/AAAA consistency).</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check authoritative DNS health.</summary>
    ///   <code>Test-DDDnsHealth -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDDnsHealth", DefaultParameterSetName = "Domain")]
    [Alias("Test-DnsHealth")]
    public sealed class CmdletTestDnsHealth : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Domain", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>Runs DNS health verification.</summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            async Task ProcessDomainAsync(string domain) {
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
                var healthCheck = new DomainHealthCheck(DnsClientX.DnsEndpoint.System, logger);
                ApplyExecutionOptions(healthCheck);

                logger.WriteVerbose("Running DNS health checks for {0}", domain);
                await healthCheck.Verify(domain, new[] { HealthCheckType.DNSHEALTH }, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.DnsHealthAnalysis);
                WriteObject(view);
                if (IsExportRequested()) {
                    await ExportNotImplementedAsync("Test-DDDnsHealth");
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
