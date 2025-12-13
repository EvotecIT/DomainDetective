using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates delegation records for a domain.</summary>
    /// <example>
    ///   <summary>Check delegation.</summary>
    ///   <code>Test-DDDnsDelegation -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDDnsDelegation", DefaultParameterSetName = "ServerName")]
    [Alias("Test-DnsDelegation", "Test-Delegation")]
    public sealed class CmdletTestDelegation : ExportableAsyncPSCmdlet {
        /// <para>Domain to query.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName = string.Empty;

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        private InternalLogger _logger = null!;
        private DomainHealthCheck _healthCheck = null!;

        /// <summary>
        /// Prepares the delegation check and logging.
        /// </summary>
        /// <returns>A completed task.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var psLogger = new InternalLoggerPowerShell(
                _logger,
                WriteVerbose,
                WriteWarning,
                WriteDebug,
                WriteError,
                WriteProgress,
                WriteInformation);
            psLogger.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Validates parent zone delegation for the target domain.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Checking delegation for domain: {0}", DomainName);
            await _healthCheck.VerifyDelegation(DomainName);
            var view = DomainDetective.Views.Converters.Convert(_healthCheck.NSAnalysis);
            WriteObject(view);
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
