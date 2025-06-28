using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Retrieves contact TXT information for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Get contact details.</summary>
    ///   <code>Test-ContactRecord -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "ContactRecord", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestContactRecord : AsyncPSCmdlet {
        /// <param name="DomainName">Domain to query.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <param name="DnsEndpoint">DNS server used for queries.</param>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

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
            _logger.WriteVerbose("Querying contact record for domain: {0}", DomainName);
            await healthCheck.Verify(DomainName, new[] { HealthCheckType.CONTACT });
            WriteObject(healthCheck.ContactInfoAnalysis);
        }
    }
}
