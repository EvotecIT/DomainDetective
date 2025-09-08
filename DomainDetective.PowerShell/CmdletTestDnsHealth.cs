using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Runs authoritative DNS health checks (SOA serial skew, apex A/AAAA consistency).</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check authoritative DNS health.</summary>
    ///   <code>Test-DDDnsHealth -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDDnsHealth", DefaultParameterSetName = "Domain")]
    [Alias("Test-DnsHealth")]
    public sealed class CmdletTestDnsHealth : ExportableAsyncPSCmdlet {
        /// <summary>Domain to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Domain")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A completed task.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsClientX.DnsEndpoint.System, _logger);
            return Task.CompletedTask;
        }

        /// <summary>Runs DNS health verification.</summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Running DNS health checks for {0}", DomainName);
            await _healthCheck.Verify(DomainName, new[] { HealthCheckType.DNSHEALTH });
            var view = DomainDetective.Views.Converters.Convert(_healthCheck.DnsHealthAnalysis);
            WriteObject(view);
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
