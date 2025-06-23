using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    [Cmdlet(VerbsDiagnostic.Test, "WebsiteCertificate", DefaultParameterSetName = "Url")]
    public sealed class CmdletTestWebsiteCertificate : AsyncPSCmdlet {
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Url")]
        [ValidateNotNullOrEmpty]
        public string Url;

        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "Url")]
        public int Port = 443;

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
        }
    }
}
