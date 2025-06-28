using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks SMTP STARTTLS support for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Verify STARTTLS.</summary>
    ///   <code>Test-StartTls -DomainName example.com -Port 587</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "StartTls", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestStartTls : AsyncPSCmdlet {
        /// <param name="DomainName">Domain to test.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <param name="DnsEndpoint">DNS server used for queries.</param>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <param name="Port">SMTP port number.</param>
        [Parameter(Mandatory = false)]
        public int Port = 25;

        private InternalLogger _logger;
        private DomainHealthCheck healthCheck;

        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }

        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying STARTTLS for domain: {0} on port {1}", DomainName, Port);
            await healthCheck.VerifySTARTTLS(DomainName, Port);
            WriteObject(healthCheck.StartTlsAnalysis);
        }
    }
}