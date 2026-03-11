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
    [ValidateDomainName]
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
                try {
                    var hadUnsupportedFormats = false;
                    CompositionExportHelper.WriteReports(
                        new System.Collections.Generic.List<object> { view },
                        GetRequestedFormatsOrDefault(ExportDefaults.Format),
                        ExportPath,
                        domain,
                        DomainDetective.Reports.ReportScope.Normal,
                        $"Wildcard DNS — {domain}",
                        OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                        TryOpenReport,
                        out hadUnsupportedFormats);

                    if (hadUnsupportedFormats) {
                        await ExportNotImplementedAsync("Test-DDDnsWildcard");
                    }
                } catch (System.Exception ex) {
                    WriteWarning($"Wildcard DNS export failed: {ex.Message}");
                }
            }
        }

        await ForEachAsync(DomainName, ProcessDomainAsync);
    }
}


