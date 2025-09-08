using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates TLS certificate for a website.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check HTTPS certificate.</summary>
    ///   <code>Test-DDDomainCertificate -Url https://example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDomainCertificate", DefaultParameterSetName = "Url")]
[Alias("Test-DomainCertificate")]
    public sealed class CmdletTestWebsiteCertificate : ExportableAsyncPSCmdlet {
        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false)]
        public DnsClientX.DnsEndpoint DnsEndpoint = DnsClientX.DnsEndpoint.System;
        /// <summary>Website URL.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Url")]
        [ValidateNotNullOrEmpty]
        public string Url;

        /// <summary>TCP port used for connection.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "Url")]
        public int Port = 443;

        /// <summary>Output certificate chain information.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter ShowChain;

        /// <summary>Do not check certificate revocation status.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter SkipRevocation;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Verifying website certificate for {0}", Url);
            _healthCheck.CertificateAnalysis.SkipRevocation = SkipRevocation;
            await _healthCheck.VerifyWebsiteCertificate(Url, Port);
            var view = DomainDetective.Views.Converters.Convert(_healthCheck.CertificateAnalysis);
            WriteObject(view);
            if (ShowChain && _healthCheck.CertificateAnalysis.Chain.Count > 0) {
                WriteObject(_healthCheck.CertificateAnalysis.Chain, true);
            }
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
