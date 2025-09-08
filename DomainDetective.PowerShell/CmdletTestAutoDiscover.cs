using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks Autodiscover related DNS records.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>Outputs a view object with full raw analysis attached at Raw.</remarks>
    /// <example>
    ///   <summary>Verify Autodiscover setup.</summary>
    ///   <code>Test-DDEmailAutoDiscover -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDEmailAutoDiscover", DefaultParameterSetName = "ServerName")]
    [Alias("Test-EmailAutoDiscover")]
    public sealed class CmdletTestAutoDiscover : ExportableAsyncPSCmdlet {
        /// <para>Domain to query.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName = string.Empty;

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <para>Include HTTP endpoint results.</para>
        /// <para>Outputs Autodiscover endpoint analysis.</para>
        [Parameter]
        public SwitchParameter IncludeEndpoints;

        private InternalLogger _logger = null!;
        private DomainHealthCheck _healthCheck = null!;

        /// <summary>
        /// Initializes the Autodiscover health checker.
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
        /// Checks Autodiscover settings for the specified domain.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying Autodiscover for domain: {0}", DomainName);
            await _healthCheck.VerifyAutodiscover(DomainName);
            var view = DomainDetective.Views.Converters.Convert(_healthCheck.AutodiscoverAnalysis);
            WriteObject(view);
            if (IncludeEndpoints) {
                WriteObject(_healthCheck.AutodiscoverHttpAnalysis.Endpoints, true);
            }
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
