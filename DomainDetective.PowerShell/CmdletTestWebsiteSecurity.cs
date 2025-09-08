using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks HTTPS security headers and mixed content for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check HTTPS security.</summary>
    ///   <code>Test-DDWebsiteSecurity -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDWebsiteSecurity", DefaultParameterSetName = "Domain")]
    [Alias("Test-WebsiteSecurity")]
    public sealed class CmdletTestWebsiteSecurity : ExportableAsyncPSCmdlet {
        /// <summary>Domain to query (host or host:port).</summary>
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

        /// <summary>Runs HTTPS security checks.</summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Checking HTTPS security for {0}", DomainName);
            await _healthCheck.VerifyWebsiteHttps(DomainName);
            var view = DomainDetective.Views.Converters.Convert(_healthCheck.HttpAnalysis);
            WriteObject(view);
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
