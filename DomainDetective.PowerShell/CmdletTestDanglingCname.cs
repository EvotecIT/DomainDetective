using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks for dangling CNAME records on a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>Outputs a view object with full raw analysis attached at Raw.</remarks>
    /// <example>
    ///   <summary>Detect unclaimed CNAMEs.</summary>
    ///   <code>Test-DDDnsDanglingCname -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsDanglingCname", DefaultParameterSetName = "ServerName")]
[Alias("Test-DnsDanglingCname")]
    public sealed class CmdletTestDanglingCname : ExportableAsyncPSCmdlet {
        /// <para>Domain to query.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        /// <summary>
        /// Initializes the dangling CNAME checker.
        /// </summary>
        /// <returns>A completed task.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Checks for dangling CNAME entries on the domain.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Checking dangling CNAME for domain: {0}", DomainName);
            await _healthCheck.Verify(DomainName, new[] { HealthCheckType.DANGLINGCNAME });
            var view = DomainDetective.Views.Converters.Convert(_healthCheck.DanglingCnameAnalysis);
            WriteObject(view);
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
