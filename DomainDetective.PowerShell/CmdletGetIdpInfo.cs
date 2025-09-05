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
    public sealed class CmdletGetIdpInfo : AsyncPSCmdlet {
        /// <para>Domain to probe for identity tenant information.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ByName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        /// <summary>Initializes logging and context.</summary>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(
                _logger,
                this.WriteVerbose,
                this.WriteWarning,
                this.WriteDebug,
                this.WriteError,
                this.WriteProgress,
                this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsClientX.DnsEndpoint.System, _logger);
            return Task.CompletedTask;
        }

        /// <summary>Retrieves IdP details and writes a view object.</summary>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying IdP information for domain: {0}", DomainName);
            await _healthCheck.VerifyIdpInfo(DomainName);
            var view = DomainDetective.Views.Converters.Convert(_healthCheck.IdpInfoAnalysis);
            WriteObject(view);
        }
    }
}

