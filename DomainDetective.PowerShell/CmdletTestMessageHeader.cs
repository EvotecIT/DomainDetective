using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Parses raw email message headers.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Analyze headers from a file.</summary>
    ///   <code>Get-Content './headers.txt' -Raw | Get-DDEmailMessageHeaderInfo</code>
    /// </example>
[Cmdlet(VerbsCommon.Get, "DDEmailMessageHeaderInfo")]
[Alias("Get-EmailHeaderInfo")]
    public sealed class CmdletTestMessageHeader : ExportableAsyncPSCmdlet {
        /// <summary>Raw header text.</summary>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string HeaderText;

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
            _healthCheck = new DomainHealthCheck(DnsEndpoint.System, _logger);
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override Task ProcessRecordAsync() {
            var result = _healthCheck.CheckMessageHeaders(HeaderText, CancelToken);
            WriteObject(result);
            if (IsExportRequested()) { return ExportNotImplementedAsync(); }
            return Task.CompletedTask;
        }
    }
}
