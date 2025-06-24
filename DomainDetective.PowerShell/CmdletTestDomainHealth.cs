using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    [Cmdlet(VerbsDiagnostic.Test, "DomainHealth", DefaultParameterSetName = "ServerName")]
    [OutputType(typeof(DomainHealthCheck))]
    public sealed class CmdletTestDomainHealth : AsyncPSCmdlet {
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string DomainName;

        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        [Parameter(Mandatory = false)]
        public HealthCheckType[]? HealthCheckType;

        [Parameter(Mandatory = false)]
        public string[]? DkimSelectors;

        [Parameter(Mandatory = false)]
        public ServiceType[]? DaneServiceType;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

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
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }

        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying domain health for domain: {0}", DomainName);
            await _healthCheck.Verify(DomainName, HealthCheckType, DkimSelectors, DaneServiceType);
            WriteObject(_healthCheck);
        }
    }
}