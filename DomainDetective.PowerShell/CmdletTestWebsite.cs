using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Runs both web certificate and HTTPS security checks.</summary>
    /// <para>Outputs CertificateInfo and HttpInfo views.</para>
    [Cmdlet(VerbsDiagnostic.Test, "DDWebsite", DefaultParameterSetName = "Domain")]
    [Alias("Test-Website")]
    public sealed class CmdletTestWebsite : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to analyze.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Domain", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>HTTPS port number.</summary>
        [Parameter(Mandatory = false)]
        public int Port = 443;

        /// <summary>Skip certificate revocation checks.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter SkipRevocation;

        /// <summary>Runs certificate and HTTPS security checks.</summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            async Task ProcessDomainAsync(string domain) {
                var logger = new InternalLogger(false);
                var internalLoggerPowerShell = new InternalLoggerPowerShell(
                    logger,
                    WriteVerbose,
                    WriteWarning,
                    WriteDebug,
                    WriteError,
                    WriteProgress,
                    WriteInformation);
                internalLoggerPowerShell.ResetActivityIdCounter();
            var healthCheck = new DomainHealthCheck(DnsClientX.DnsEndpoint.System, logger);
            ApplyExecutionOptions(healthCheck);

            logger.WriteVerbose("Checking website certificate and HTTPS for {0}:{1}", domain, Port);
            healthCheck.CertificateAnalysis.SkipRevocation = SkipRevocation;
                await healthCheck.VerifyWebsiteCertificate(domain, Port, cancellationToken: CancelToken);
                await healthCheck.VerifyWebsiteHttps(domain, cancellationToken: CancelToken);

                var certView = DomainDetective.Views.Converters.Convert(healthCheck.CertificateAnalysis);
                var httpView = DomainDetective.Views.Converters.Convert(healthCheck.HttpAnalysis);
                var combined = DomainDetective.Views.Converters.CombineWebsite(certView, httpView);
                WriteObject(combined);
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
