using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;
using DomainDetective.Views;

namespace DomainDetective.PowerShell {
    /// <summary>Lists domains hosted on the same IP.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Returns a unified IpNeighborInfo view including total addresses and neighbor domain counts.
    /// Raw exposes the full IPNeighborAnalysis.
    /// </remarks>
    /// <example>
    ///   <summary>Check IP neighbors.</summary>
    ///   <code>Test-DDNetworkIpNeighbor -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDNetworkIpNeighbor", DefaultParameterSetName = "ServerName")]
[Alias("Test-NetworkIpNeighbor")]
    [OutputType(typeof(IpNeighborInfo))]
    public sealed class CmdletTestIPNeighbor : ExportableAsyncPSCmdlet {
        /// <summary>Domain to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
    public string DomainName = string.Empty;

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>Include MX host neighbor analysis.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter IncludeMX;

    private InternalLogger _logger = null!;
    private DomainHealthCheck _healthCheck = null!;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
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
            ApplyExecutionOptions(_healthCheck);
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying IP neighbors for domain: {0}", DomainName);
            await _healthCheck.Verify(DomainName, new[] { HealthCheckType.IPNEIGHBOR });
            if (IncludeMX.IsPresent)
            {
                await _healthCheck.CheckMailIPNeighbors(DomainName);
            }
            var view = DomainDetective.Views.Converters.Convert(_healthCheck.IPNeighborAnalysis);
            WriteObject(view);
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}

