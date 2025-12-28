using System.Management.Automation;
using DomainDetective.Views;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Scans common web directories for exposure.</summary>
/// <para>Part of the DomainDetective project.</para>
/// <remarks>
/// Returns a unified DirectoryExposureInfo view with Assessments, Status, Counts, Recommendations, and Raw (full analysis object) for lossless access.
/// </remarks>
/// <example>
///   <summary>Check for exposed directories over HTTP.</summary>
///   <code>Test-DDDirectoryExposure -DomainName example.com</code>
/// </example>
/// <example>
///   <summary>Check for exposed directories over HTTPS.</summary>
///   <code>Test-DDDirectoryExposure -DomainName example.com -UseHttps</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDirectoryExposure", DefaultParameterSetName = "ServerName")]
[Alias("Test-DirectoryExposure")]
[OutputType(typeof(DirectoryExposureInfo))]
public sealed class CmdletTestDirectoryExposure : ExportableAsyncPSCmdlet {
    /// <summary>Domain(s) to query.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    public string[] DomainName = System.Array.Empty<string>();

    /// <summary>Use HTTPS instead of HTTP.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter UseHttps;

    /// <summary>DNS server used for queries.</summary>
    [Parameter(Mandatory = false)]
    public DnsClientX.DnsEndpoint DnsEndpoint = DnsClientX.DnsEndpoint.System;

    /// <summary>Executes the cmdlet operation.</summary>
    protected override async Task ProcessRecordAsync() {
        async Task ProcessDomainAsync(string domain) {
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

            var url = (UseHttps.IsPresent ? "https://" : "http://") + domain.Trim().TrimEnd('/');
            await healthCheck.DirectoryExposureAnalysis.Analyze(url, logger, cancellationToken: CancelToken);
            var view = DomainDetective.Views.Converters.Convert(healthCheck.DirectoryExposureAnalysis);
            WriteObject(view);
            if (IsExportRequested()) {
                await ExportNotImplementedAsync("Test-DDDirectoryExposure");
            }
        }

        await ForEachAsync(DomainName, ProcessDomainAsync);
    }
}
