using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks if a DNS server allows recursive queries.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Test a DNS server.</summary>
    ///   <code>Test-DDDnsOpenResolver -Server 8.8.8.8 -Port 53</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDDnsOpenResolver")]
    [Alias("Test-DnsOpenResolver", "Test-OpenResolver")]
    public sealed class CmdletTestOpenResolver : ExportableAsyncPSCmdlet {
        /// <summary>DNS server to check.</summary>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string Server;

        /// <summary>DNS port.</summary>
        [Parameter(Mandatory = false, Position = 1)]
        public int Port = 53;

        private InternalLogger _logger;
        private DomainHealthCheck _hc;

        /// <summary>Initializes helper classes.</summary>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _hc = new DomainHealthCheck(internalLogger: _logger);
            return Task.CompletedTask;
        }

        /// <summary>Performs the open resolver test.</summary>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Checking open resolver for {0}:{1}", Server, Port);
            await _hc.CheckOpenResolverHost(Server, Port, CancelToken);
            WriteObject(_hc.OpenResolverAnalysis.ServerResults[$"{Server}:{Port}"]);
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
