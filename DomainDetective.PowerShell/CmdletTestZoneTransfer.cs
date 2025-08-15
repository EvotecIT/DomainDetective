using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Attempts zone transfers against authoritative name servers.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check for open zone transfers.</summary>
    ///   <code>Test-DDZoneTransfer -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDZoneTransfer", DefaultParameterSetName = "ServerName")]
    [Alias("Test-ZoneTransfer")]
    public sealed class CmdletTestZoneTransfer : AsyncPSCmdlet {
        /// <summary>Domain to query.</summary>
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
            var psLogger = new InternalLoggerPowerShell(
                _logger,
                this.WriteVerbose,
                this.WriteWarning,
                this.WriteDebug,
                this.WriteError,
                this.WriteProgress,
                this.WriteInformation);
            psLogger.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Checking zone transfer for domain: {0}", DomainName);
            await _healthCheck.VerifyZoneTransfer(DomainName);
            WriteObject(_healthCheck.ZoneTransferAnalysis);
        }
    }
}
