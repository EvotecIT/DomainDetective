using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Parses raw email message headers.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Analyze headers from a file.</summary>
    ///   <code>Get-Content './headers.txt' -Raw | Get-DDEmailMessageHeaderInfo -ExpectedMx 'mx1.gateway.example.net'</code>
    /// </example>
[Cmdlet(VerbsCommon.Get, "DDEmailMessageHeaderInfo")]
[Alias("Get-EmailHeaderInfo")]
    public sealed class CmdletTestMessageHeader : ExportableAsyncPSCmdlet {
        /// <summary>Raw header text.</summary>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true)]
        [ValidateNotNullOrEmpty]
        public string HeaderText = string.Empty;

        /// <summary>Expected public MX hosts that should appear in the received path.</summary>
        [Parameter]
        public string[]? ExpectedMx { get; set; }

        private InternalLogger _logger = null!;
        private DomainHealthCheck _healthCheck = null!;

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
            ApplyExecutionOptions(_healthCheck);
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override Task ProcessRecordAsync() {
            _logger.ClearLoggedMessages();
            var result = _healthCheck.CheckMessageHeaders(HeaderText, ExpectedMx, CancelToken);
            WriteObject(result);
            if (IsExportRequested()) {
                try {
                    var hadUnsupportedFormats = false;
                    CompositionExportHelper.WriteReports(
                        new System.Collections.Generic.List<object> { result },
                        GetRequestedFormatsOrDefault(ExportDefaults.Format),
                        ExportPath,
                        "message-header",
                        DomainDetective.Reports.ReportScope.Normal,
                        "Email Message Header Report",
                        OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                        TryOpenReport,
                        out hadUnsupportedFormats);

                    if (hadUnsupportedFormats) {
                        return ExportNotImplementedAsync("Get-DDEmailMessageHeaderInfo");
                    }
                } catch (System.Exception ex) {
                    WriteWarning($"Message header export failed: {ex.Message}");
                }
            }
            return Task.CompletedTask;
        }
    }
}

