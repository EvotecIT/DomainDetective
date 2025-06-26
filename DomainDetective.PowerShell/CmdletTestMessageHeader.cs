using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Parses raw email message headers.</summary>
    /// <example>
    ///   <summary>Analyze headers from a file.</summary>
    ///   <code>Get-Content './headers.txt' -Raw | Test-MessageHeader</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "MessageHeader")]
    public sealed class CmdletTestMessageHeader : AsyncPSCmdlet {
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
            var result = _healthCheck.CheckMessageHeaders(HeaderText, CancelToken);
            WriteObject(result);
            return Task.CompletedTask;
        }
    }
}
