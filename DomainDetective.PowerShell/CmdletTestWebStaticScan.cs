using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Runs a static (non-browser) web scan for a URL.</summary>
    [Cmdlet(VerbsDiagnostic.Test, "DDWebStaticScan", DefaultParameterSetName = "Url")]
    [Alias("Test-WebStaticScan")]
    public sealed class CmdletTestWebStaticScan : ExportableAsyncPSCmdlet {
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Url")]
        [ValidateNotNullOrEmpty]
        public string Url;

        [Parameter(Mandatory = false)]
        public int MaxSeconds = 30;

        [Parameter(Mandatory = false)]
        public int MaxResources = 300;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsClientX.DnsEndpoint.System, _logger);
            return Task.CompletedTask;
        }

        protected override async Task ProcessRecordAsync() {
            _healthCheck.WebStaticScanAnalysis.Timeout = System.TimeSpan.FromSeconds(MaxSeconds);
            _healthCheck.WebStaticScanAnalysis.MaxResources = MaxResources;
            await _healthCheck.VerifyWebStaticScan(Url);

            var view = DomainDetective.Views.Converters.Convert(_healthCheck.WebStaticScanAnalysis);
            WriteObject(view);
        }
    }
}
