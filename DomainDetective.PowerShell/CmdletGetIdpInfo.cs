using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Retrieves identity provider (IdP) information for the specified domain.</summary>
    /// <para>Performs OIDC discovery and GetUserRealm calls to expose tenant hints.</para>
    /// <example>
    ///   <summary>Get IdP information.</summary>
    ///   <code>Get-DDIdpInfo -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "DDIdpInfo", DefaultParameterSetName = "ByName")]
    [Alias("Get-IdpInfo")]
    public sealed class CmdletGetIdpInfo : ParallelAsyncPSCmdlet {
        /// <para>Domain(s) to probe for identity tenant information.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ByName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>Retrieves IdP details and writes a view object.</summary>
        protected override async Task ProcessRecordAsync() {
            async Task ProcessDomainAsync(string domain) {
                var logger = new InternalLogger(false);
                var internalLoggerPowerShell = new InternalLoggerPowerShell(
                    logger,
                    this.WriteVerbose,
                    this.WriteWarning,
                    this.WriteDebug,
                    this.WriteError,
                    this.WriteProgress,
                    this.WriteInformation);
                internalLoggerPowerShell.ResetActivityIdCounter();
                var healthCheck = new DomainHealthCheck(DnsClientX.DnsEndpoint.System, logger);
                ApplyExecutionOptions(healthCheck);

                logger.WriteVerbose("Querying IdP information for domain: {0}", domain);
                await healthCheck.VerifyIdpInfo(domain, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.IdpInfoAnalysis);
                WriteObject(view);
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
