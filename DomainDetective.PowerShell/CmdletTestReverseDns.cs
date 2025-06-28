using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates PTR records for MX hosts.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check reverse DNS configuration.</summary>
    ///   <code>Test-ReverseDns -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "ReverseDns", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestReverseDns : AsyncPSCmdlet {
        /// <param name="DomainName">Domain to analyze.</param>
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
            var internalLoggerPowerShell = new InternalLoggerPowerShell(
                _logger,
                this.WriteVerbose,
                this.WriteWarning,
                this.WriteDebug,
                this.WriteError,
                this.WriteProgress,
                this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }

        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying reverse DNS for domain: {0}", DomainName);
            await _healthCheck.Verify(DomainName, new[] { HealthCheckType.REVERSEDNS });
            WriteObject(_healthCheck.ReverseDnsAnalysis);
        }
    }
}
