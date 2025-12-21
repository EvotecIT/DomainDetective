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
public sealed class CmdletTestDirectoryExposure : ExportableAsyncPSCmdlet
{
    /// <summary>Domain to query.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
    [ValidateNotNullOrEmpty]
    public string DomainName = string.Empty;

    /// <summary>Use HTTPS instead of HTTP.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter UseHttps;

    private InternalLogger _logger = null!;
    private DomainHealthCheck _healthCheck = null!;
    /// <summary>DNS server used for queries.</summary>
    [Parameter(Mandatory = false)]
    public DnsClientX.DnsEndpoint DnsEndpoint = DnsClientX.DnsEndpoint.System;

    /// <summary>Initializes logging and helper classes.</summary>
    protected override Task BeginProcessingAsync()
    {
        _logger = new InternalLogger(false);
        var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
        internalLoggerPowerShell.ResetActivityIdCounter();
        _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
        ApplyExecutionOptions(_healthCheck);
        return Task.CompletedTask;
    }

    /// <summary>Executes the cmdlet operation.</summary>
    protected override async Task ProcessRecordAsync()
    {
        var url = (UseHttps.IsPresent ? "https://" : "http://") + DomainName.Trim().TrimEnd('/');
        await _healthCheck.DirectoryExposureAnalysis.Analyze(url, _logger);
        var view = DomainDetective.Views.Converters.Convert(_healthCheck.DirectoryExposureAnalysis);
        WriteObject(view);
        if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
    }
}

