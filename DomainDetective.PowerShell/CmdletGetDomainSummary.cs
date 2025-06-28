using DnsClientX;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Returns a summary of domain health checks.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Get basic domain overview.</summary>
    ///   <code>Get-DomainSummary -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "DomainSummary", DefaultParameterSetName = "ServerName")]
    [OutputType(typeof(DomainSummary))]
    public sealed class CmdletGetDomainSummary : AsyncPSCmdlet {
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
            _logger.WriteVerbose("Querying domain summary for domain: {0}", DomainName);
            await _healthCheck.Verify(DomainName);
            var summary = _healthCheck.BuildSummary();
            WriteObject(summary);
        }
    }
}
