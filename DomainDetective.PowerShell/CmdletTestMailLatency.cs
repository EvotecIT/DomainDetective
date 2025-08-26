using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Measures SMTP connection and banner latency.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check mail latency for a server.</summary>
    ///   <code>Test-DDEmailLatency -HostName mail.example.com -Port 25</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailLatency", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailLatency")]
    public sealed class CmdletTestMailLatency : ExportableAsyncPSCmdlet {
        /// <summary>SMTP host to check.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string HostName;

        /// <summary>SMTP port number.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public int Port = 25;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var helper = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            helper.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(internalLogger: _logger);
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Measuring mail latency for {0}:{1}", HostName, Port);
            await _healthCheck.CheckMailLatency(HostName, Port);
            WriteObject(_healthCheck.MailLatencyAnalysis.ServerResults[$"{HostName}:{Port}"]);
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
