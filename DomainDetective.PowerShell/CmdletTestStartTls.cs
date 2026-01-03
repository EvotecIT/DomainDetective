using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks SMTP STARTTLS support for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Verify STARTTLS.</summary>
    ///   <code>Test-DDEmailStartTls -DomainName example.com -Port 587</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDEmailStartTls", DefaultParameterSetName = "ServerName")]
    [Alias("Test-EmailStartTls")]
    public sealed class CmdletTestStartTls : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to test.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>SMTP port number.</summary>
        [Parameter(Mandatory = false)]
        public int Port = 25;

        /// <summary>Return the full analysis object instead of per-server details.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter FullResponse;

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

                logger.WriteVerbose("Querying STARTTLS for domain: {0} on port {1}", domain, Port);
                await healthCheck.VerifySTARTTLS(domain, Port, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.StartTlsAnalysis);
                WriteObject(view);
                if (IsExportRequested()) {
                    await ExportNotImplementedAsync("Test-DDEmailStartTls");
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
