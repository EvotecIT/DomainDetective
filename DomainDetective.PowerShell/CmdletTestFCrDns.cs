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
    [ValidateDomainName]
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
                try {
                    var hadUnsupportedFormats = false;
                    CompositionExportHelper.WriteReports(
                        new System.Collections.Generic.List<object> { view },
                        GetRequestedFormatsOrDefault(ExportDefaults.Format),
                        ExportPath,
                        domain,
                        DomainDetective.Reports.ReportScope.Normal,
                        $"FCrDNS Report — {domain}",
                        OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                        TryOpenReport,
                        out hadUnsupportedFormats);

                    if (hadUnsupportedFormats) {
                        await ExportNotImplementedAsync("Test-DDDnsForwardReverse");
                    }
                } catch (System.Exception ex) {
                    WriteWarning($"FCrDNS export failed: {ex.Message}");
                }
            }
        }

        await ForEachAsync(DomainName, ProcessDomainAsync);
    }
}
