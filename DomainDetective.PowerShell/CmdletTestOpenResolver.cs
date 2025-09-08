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
        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false)]
        public DnsClientX.DnsEndpoint DnsEndpoint = DnsClientX.DnsEndpoint.System;
        /// <summary>DNS server to check.</summary>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string Server = string.Empty;

        /// <summary>DNS port.</summary>
        [Parameter(Mandatory = false, Position = 1)]
        public int Port = 53;

        private InternalLogger _logger = null!;
        private DomainHealthCheck _hc = null!;

        /// <summary>Initializes helper classes.</summary>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _hc = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }

        /// <summary>Performs the open resolver test.</summary>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Checking open resolver for {0}:{1}", Server, Port);
            await _hc.CheckOpenResolverHost(Server, Port, CancelToken);
            var view = DomainDetective.Views.Converters.Convert(_hc.OpenResolverAnalysis);
            WriteObject(view);
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
