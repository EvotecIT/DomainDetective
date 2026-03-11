using DnsClientX;
using System;
using System.Management.Automation;
using System.Threading.Tasks;
using System.Linq;

namespace DomainDetective.PowerShell;

/// <summary>Tests EDNS support on authoritative name servers.</summary>
/// <para>Part of the DomainDetective project.</para>
/// <example>
///   <summary>Check EDNS support.</summary>
///   <code>Test-DDDnsEdnsSupport -DomainName example.com</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsEdnsSupport", DefaultParameterSetName = "ServerName")]
[Alias("Test-DnsEdnsSupport")]
public sealed class CmdletTestEdnsSupport : ExportableAsyncPSCmdlet {
    /// <summary>Domain(s) to query.</summary>
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

            logger.WriteVerbose("Querying EDNS support for domain: {0}", domain);
            await healthCheck.Verify(domain, new[] { HealthCheckType.EDNSSUPPORT }, cancellationToken: CancelToken);
            var view = DomainDetective.Views.Converters.Convert(healthCheck.EdnsSupportAnalysis);
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
                        $"EDNS Support Report - {domain}",
                        OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                        TryOpenReport,
                        out hadUnsupportedFormats);

                    if (hadUnsupportedFormats) {
                        await ExportNotImplementedAsync("Test-DDDnsEdnsSupport");
                    }
                } catch (Exception ex) {
                    WriteWarning($"EDNS support export failed: {ex.Message}");
                }
            }
        }

        await ForEachAsync(DomainName, ProcessDomainAsync);
    }
}
