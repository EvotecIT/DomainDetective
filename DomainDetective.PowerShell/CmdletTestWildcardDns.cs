using DnsClientX;
using System;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Detects wildcard DNS responses by querying random subdomains.</summary>
/// <para>Part of the DomainDetective project.</para>
/// <example>
///   <summary>Check for wildcard DNS.</summary>
///   <code>Test-DDDnsWildcard -DomainName example.com</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsWildcard", DefaultParameterSetName = "ServerName")]
[Alias("Test-DnsWildcard")]
public sealed class CmdletTestWildcardDns : ExportableAsyncPSCmdlet
{
    /// <summary>Domain(s) to query.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
    [ValidateNotNullOrEmpty]
    public string[] DomainName = Array.Empty<string>();

    /// <summary>DNS server used for queries.</summary>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>Executes the cmdlet operation.</summary>
    /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
    protected override async Task ProcessRecordAsync()
    {
        async Task ProcessDomainAsync(string domain)
        {
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
            var healthCheck = new DomainHealthCheck(DnsEndpoint, logger);
            ApplyExecutionOptions(healthCheck);

            logger.WriteVerbose("Querying wildcard DNS for domain: {0}", domain);
            await healthCheck.Verify(domain, new[] { HealthCheckType.WILDCARDDNS }, cancellationToken: CancelToken);
            var view = DomainDetective.Views.Converters.Convert(healthCheck.WildcardDnsAnalysis);
            WriteObject(view);
            if (IsExportRequested()) {
                var fmt = (ExportFormat != null && ExportFormat.Length > 0) ? ExportFormat[0] : ExportDefaults.Format;
                if (fmt == DomainDetective.Reports.ReportFormat.Word) {
                    var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, domain, fmt);
                    try {
                        DomainDetective.Reports.Office.WordCompositionReport.Generate(
                            outPath,
                            new System.Collections.Generic.List<object> { view },
                            DomainDetective.Reports.ReportScope.Normal,
                            showInfoFindings: true,
                            narrativePlacement: ExportDefaults.NarrativePlacement,
                            titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"Wildcard DNS — {domain}" : ExportDefaults.NarrativeTitle,
                            summaryColumnCap: ExportDefaults.SummaryColumnCap,
                            headerLogoSizePx: ExportDefaults.HeaderLogoSizePx,
                            footerLogoSizePx: ExportDefaults.FooterLogoSizePx);
                        if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) {
                            TryOpenReport(outPath);
                        }
                    } catch (System.Exception ex) {
                        WriteWarning($"Wildcard DNS export failed: {ex.Message}");
                    }
                } else {
                    await ExportNotImplementedAsync("Test-DDDnsWildcard");
                }
            }
        }

        await ForEachAsync(DomainName, ProcessDomainAsync);
    }
}




