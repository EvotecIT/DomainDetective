using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Retrieves security.txt information for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Get security contacts.</summary>
    ///   <code>Test-SecurityTXT -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDomainSecurityTxt", DefaultParameterSetName = "ServerName")]
[Alias("Test-DomainSecurityTxt")]
    public sealed class CmdletTestSecurityTXT : AsyncPSCmdlet {
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
            _logger.WriteVerbose("Querying security.txt for domain: {0}", DomainName);
            await healthCheck.Verify(DomainName, new[] { HealthCheckType.SECURITYTXT });
            WriteObject(healthCheck.SecurityTXTAnalysis);
        }
    }
}