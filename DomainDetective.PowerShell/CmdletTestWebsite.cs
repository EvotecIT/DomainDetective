using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Runs both web certificate and HTTPS security checks.</summary>
    /// <para>Outputs CertificateInfo and HttpInfo views.</para>
    [Cmdlet(VerbsDiagnostic.Test, "DDWebsite", DefaultParameterSetName = "Domain")]
    [Alias("Test-Website")]
    public sealed class CmdletTestWebsite : ExportableAsyncPSCmdlet {
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Domain")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        [Parameter(Mandatory = false)]
        public int Port = 443;

        [Parameter(Mandatory = false)]
        public SwitchParameter SkipRevocation;

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
            _healthCheck.CertificateAnalysis.SkipRevocation = SkipRevocation;
            await _healthCheck.VerifyWebsiteCertificate(DomainName, Port);
            await _healthCheck.VerifyWebsiteHttps(DomainName);

            var certView = DomainDetective.Views.Converters.Convert(_healthCheck.CertificateAnalysis);
            var httpView = DomainDetective.Views.Converters.Convert(_healthCheck.HttpAnalysis);
            var combined = DomainDetective.Views.Converters.CombineWebsite(certView, httpView);
            WriteObject(combined);
        }
    }
}
