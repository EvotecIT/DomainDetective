using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates PTR records for MX hosts.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check reverse DNS configuration.</summary>
    ///   <code>Test-DDReverseDns -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDReverseDns", DefaultParameterSetName = "ServerName")]
    [Alias("Test-ReverseDns")]
    public sealed class CmdletTestReverseDns : AsyncPSCmdlet {
        /// <summary>Domain to analyze.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
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

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying reverse DNS for domain: {0}", DomainName);
            await _healthCheck.Verify(DomainName, new[] { HealthCheckType.REVERSEDNS });
            WriteObject(_healthCheck.ReverseDnsAnalysis);
        }
    }
}
