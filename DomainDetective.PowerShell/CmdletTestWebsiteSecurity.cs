using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks HTTPS security headers and mixed content for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check HTTPS security.</summary>
    ///   <code>Test-DDWebsiteSecurity -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDWebsiteSecurity", DefaultParameterSetName = "Domain")]
    [Alias("Test-WebsiteSecurity")]
    public sealed class CmdletTestWebsiteSecurity : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to query (host or host:port).</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Domain", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>Runs HTTPS security checks.</summary>
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

                logger.WriteVerbose("Checking HTTPS security for {0}", domain);
                await healthCheck.VerifyWebsiteHttps(domain, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.HttpAnalysis);
                WriteObject(view);
                if (IsExportRequested()) {
                    await ExportNotImplementedAsync("Test-DDWebsiteSecurity");
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
