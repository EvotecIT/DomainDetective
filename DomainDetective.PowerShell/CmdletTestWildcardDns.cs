using DnsClientX;
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
    /// <summary>Domain to query.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
    [ValidateNotNullOrEmpty]
    public string DomainName = string.Empty;

    /// <summary>DNS server used for queries.</summary>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    private InternalLogger _logger = null!;
    private DomainHealthCheck healthCheck = null!;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
    protected override Task BeginProcessingAsync()
    {
        _logger = new InternalLogger(false);
        var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
        internalLoggerPowerShell.ResetActivityIdCounter();
        healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
        return Task.CompletedTask;
    }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
    protected override async Task ProcessRecordAsync()
    {
        _logger.WriteVerbose("Querying wildcard DNS for domain: {0}", DomainName);
        await healthCheck.Verify(DomainName, new[] { HealthCheckType.WILDCARDDNS });
        var view = DomainDetective.Views.Converters.Convert(healthCheck.WildcardDnsAnalysis);
        WriteObject(view);
        if (IsExportRequested()) {
            var fmt = ExportFormat ?? ExportDefaults.Format;
            if (fmt == DomainDetective.Reports.ReportFormat.Word) {
                var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, DomainName, fmt);
                try {
                    DomainDetective.Reports.Office.WordCompositionReport.Generate(
                        outPath,
                        new System.Collections.Generic.List<object> { view },
                        DomainDetective.Reports.ReportScope.Normal,
                        showInfoFindings: true,
                        narrativePlacement: ExportDefaults.NarrativePlacement,
                        titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"Wildcard DNS — {DomainName}" : ExportDefaults.NarrativeTitle);
                    if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                } catch (System.Exception ex) {
                    WriteWarning($"Wildcard DNS export failed: {ex.Message}");
                }
            } else {
                await ExportNotImplementedAsync("Test-DDDnsWildcard");
            }
            return;
        }
    }
}
