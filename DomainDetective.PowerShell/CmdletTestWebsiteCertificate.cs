using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates TLS certificate for a website.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check HTTPS certificate.</summary>
    ///   <code>Test-WebsiteCertificate -Url https://example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "WebsiteCertificate", DefaultParameterSetName = "Url")]
    public sealed class CmdletTestWebsiteCertificate : AsyncPSCmdlet {
        /// <param name="Url">Website URL.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Url")]
        [ValidateNotNullOrEmpty]
        public string Url;

        /// <param name="Port">TCP port used for connection.</param>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "Url")]
        public int Port = 443;

        /// <param name="ShowChain">Output certificate chain information.</param>
        [Parameter(Mandatory = false)]
        public SwitchParameter ShowChain;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(internalLogger: _logger);
            return Task.CompletedTask;
        }

        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Verifying website certificate for {0}", Url);
            await _healthCheck.VerifyWebsiteCertificate(Url, Port);
            WriteObject(_healthCheck.CertificateAnalysis);
            if (ShowChain && _healthCheck.CertificateAnalysis.Chain.Count > 0) {
                WriteObject(_healthCheck.CertificateAnalysis.Chain, true);
            }
        }
    }
}