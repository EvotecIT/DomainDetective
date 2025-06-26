using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks for dangling CNAME records on a domain.</summary>
    /// <example>
    ///   <summary>Detect unclaimed CNAMEs.</summary>
    ///   <code>Test-DanglingCname -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DanglingCname", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestDanglingCname : AsyncPSCmdlet {
        /// <param name="DomainName">Domain to query.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <param name="DnsEndpoint">DNS server used for queries.</param>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }

        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Checking dangling CNAME for domain: {0}", DomainName);
            await _healthCheck.Verify(DomainName, new[] { HealthCheckType.DANGLINGCNAME });
            WriteObject(_healthCheck.DanglingCnameAnalysis);
        }
    }
}
