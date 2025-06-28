using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks Autodiscover related DNS records.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Verify Autodiscover setup.</summary>
    ///   <code>Test-Autodiscover -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "Autodiscover", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestAutodiscover : AsyncPSCmdlet {
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
            _logger.WriteVerbose("Querying Autodiscover for domain: {0}", DomainName);
            await _healthCheck.VerifyAutodiscover(DomainName);
            WriteObject(_healthCheck.AutodiscoverAnalysis);
        }
    }
}
