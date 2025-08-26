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
        /// <summary>Domain to test.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>SMTP port number.</summary>
        [Parameter(Mandatory = false)]
        public int Port = 25;

        /// <summary>Return the full analysis object instead of per-server details.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter FullResponse;

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
            _logger.WriteVerbose("Querying STARTTLS for domain: {0} on port {1}", DomainName, Port);
            await healthCheck.VerifySTARTTLS(DomainName, Port);
            if (FullResponse) {
                WriteObject(healthCheck.StartTlsAnalysis);
            } else {
                var details = healthCheck.StartTlsAnalysis?.ServerDetails;
                if (details != null) WriteObject(details.Values, true);
                else WriteObject(healthCheck.StartTlsAnalysis);
            }
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
