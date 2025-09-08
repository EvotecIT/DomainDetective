using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Runs both web certificate and HTTPS security checks.</summary>
    /// <para>Outputs CertificateInfo and HttpInfo views.</para>
    [Cmdlet(VerbsDiagnostic.Test, "DDWebsite", DefaultParameterSetName = "Domain")]
    [Alias("Test-Website")]
    public sealed class CmdletTestWebsite : ExportableAsyncPSCmdlet {
        /// <summary>Domain to analyze.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Domain")]
        [ValidateNotNullOrEmpty]
    public string DomainName = string.Empty;

        /// <summary>HTTPS port number.</summary>
        [Parameter(Mandatory = false)]
        public int Port = 443;

        /// <summary>Skip certificate revocation checks.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter SkipRevocation;

    private InternalLogger _logger = null!;
    private DomainHealthCheck _healthCheck = null!;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A completed task.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsClientX.DnsEndpoint.System, _logger);
            return Task.CompletedTask;
        }

        /// <summary>Runs certificate and HTTPS security checks.</summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
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
