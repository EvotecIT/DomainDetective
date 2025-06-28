using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates ARC headers from raw input.</summary>
    /// <example>
    ///   <summary>Analyze ARC headers from a file.</summary>
    ///   <code>Get-Content './headers.txt' -Raw | Test-Arc</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "Arc")]
    public sealed class CmdletTestArc : AsyncPSCmdlet {
        /// <param name="HeaderText">Raw header text.</param>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string HeaderText;

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
            _healthCheck = new DomainHealthCheck(DnsEndpoint.System, _logger);
            return Task.CompletedTask;
        }

        protected override Task ProcessRecordAsync() {
            var result = _healthCheck.VerifyARC(HeaderText, CancelToken);
            WriteObject(result);
            return Task.CompletedTask;
        }
    }
}
