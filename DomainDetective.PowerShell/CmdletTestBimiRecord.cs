using DnsClientX;
using System;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates BIMI record for the specified domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check BIMI configuration.</summary>
    ///   <code>Test-DDEmailBimiRecord -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailBimiRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailBimi")]
    public sealed class CmdletTestBimiRecord : ExportableAsyncPSCmdlet {
        /// <para>Domain(s) to query.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = Array.Empty<string>();

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>
        /// Retrieves BIMI information for the domain.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
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

                logger.WriteVerbose("Querying BIMI record for domain: {0}", domain);
                await healthCheck.VerifyBIMI(domain, cancellationToken: CancelToken);
                var output = DomainDetective.Views.Converters.Convert(healthCheck.BimiAnalysis);
                WriteObject(output);
                if (IsExportRequested()) {
                    await ExportNotImplementedAsync();
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}



