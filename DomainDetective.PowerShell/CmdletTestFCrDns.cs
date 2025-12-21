using DnsClientX;
using System;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Validates forward-confirmed reverse DNS for MX hosts.</summary>
/// <remarks>Outputs a view object with full raw analysis attached at Raw.</remarks>
/// <example>
///   <summary>Check FCrDNS configuration.</summary>
///   <code>Test-DDDnsForwardReverse -DomainName example.com</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsForwardReverse", DefaultParameterSetName = "ServerName")]
[Alias("Test-DnsFcrDns")]
public sealed class CmdletTestFCrDns : ExportableAsyncPSCmdlet {
    /// <summary>Domain(s) to analyze.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    public string[] DomainName = Array.Empty<string>();

    /// <summary>DNS server used for queries.</summary>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    /// <summary>Executes the cmdlet operation.</summary>
    /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
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
            var healthCheck = new DomainHealthCheck(DnsEndpoint, logger);
            ApplyExecutionOptions(healthCheck);

            logger.WriteVerbose("Querying FCrDNS for domain: {0}", domain);
            await healthCheck.Verify(domain, new[] { HealthCheckType.FCRDNS }, cancellationToken: CancelToken);
            var view = DomainDetective.Views.Converters.Convert(healthCheck.FcrDnsAnalysis);
            WriteObject(view);
            if (IsExportRequested()) {
                await ExportNotImplementedAsync("Test-DDDnsForwardReverse");
            }
        }

        await ForEachAsync(DomainName, ProcessDomainAsync);
    }
}
