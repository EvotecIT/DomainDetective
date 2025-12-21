using DnsClientX;
using System;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates DANE TLSA records for the given domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check DANE records.</summary>
    ///   <code>Test-DDTlsDaneRecord -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDTlsDaneRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-TlsDane")]
    public sealed class CmdletTestDaneRecord : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string[] DomainName = Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>Custom ports to query.</summary>
        [Parameter(Mandatory = false, Position = 2, ParameterSetName = "ServerName")]
        public int[]? Ports;

        /// <summary>Return full analysis object.</summary>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter FullResponse;

        /// <summary>
        /// Validates DANE TLSA records for the specified ports.
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

                logger.WriteVerbose("Querying DANE record for domain: {0}", domain);
                var ports = Ports != null && Ports.Length > 0 ? Ports : new[] { (int)ServiceType.SMTP };
                await healthCheck.VerifyDANE(domain, ports, cancellationToken: CancelToken);
                var output = DomainDetective.Views.Converters.Convert(healthCheck.DaneAnalysis);
                WriteObject(output);
                if (IsExportRequested()) {
                    await ExportNotImplementedAsync();
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}



