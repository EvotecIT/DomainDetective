using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates SMIMEA records for the given email address.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check SMIMEA record.</summary>
    ///   <code>Test-SmimeaRecord -EmailAddress user@example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "SmimeaRecord", DefaultParameterSetName = "Email")]
    public sealed class CmdletTestSmimeaRecord : AsyncPSCmdlet {
        /// <param name="EmailAddress">Email address to query.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Email")]
        [ValidateNotNullOrEmpty]
        public string EmailAddress;

        /// <param name="DnsEndpoint">DNS server used for queries.</param>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "Email")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var psLogger = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
            psLogger.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }

        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying SMIMEA record for {0}", EmailAddress);
            await _healthCheck.VerifySMIMEA(EmailAddress);
            WriteObject(_healthCheck.SmimeaAnalysis);
        }
    }
}
