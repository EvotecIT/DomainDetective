using System.Management.Automation;
using DomainDetective.Views;
using System.Threading.Tasks;
using PortScanProfile = DomainDetective.PortScanProfileDefinition.PortScanProfile;

namespace DomainDetective.PowerShell;

/// <summary>Scans a host for open TCP/UDP ports.</summary>
/// <para>Part of the DomainDetective project.</para>
/// <remarks>
/// Returns a unified PortScanInfo view with total/open counts and Raw (full analysis) for details.
/// Profiles provide curated port lists; Ports overrides scan a custom set.
/// </remarks>
/// <example>
///   <summary>Scan with default profile.</summary>
///   <code>Test-DDNetworkPortScan -HostName example.com</code>
/// </example>
/// <example>
///   <summary>Scan specific ports.</summary>
///   <code>Test-DDNetworkPortScan -HostName example.com -Ports 22,80,443</code>
/// </example>
/// <example>
///   <summary>Scan using profiles.</summary>
///   <code>Test-DDNetworkPortScan -HostName example.com -Profile Default,SMB</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDNetworkPortScan")]
[Alias("Test-NetworkPortScan")]
[OutputType(typeof(PortScanInfo))]
public sealed class CmdletTestPortScan : ExportableAsyncPSCmdlet
{
    /// <summary>Host to scan.</summary>
    [Parameter(Mandatory = true, Position = 0)]
    [ValidateNotNullOrEmpty]
    public string HostName = string.Empty;

    /// <summary>Port list to scan.</summary>
    [Parameter(Mandatory = false)]
    public int[] Ports = System.Array.Empty<int>();

    /// <summary>Predefined profiles.</summary>
    [Parameter(Mandatory = false)]
    public PortScanProfile[] Profile = System.Array.Empty<PortScanProfile>();

    /// <summary>Show progress updates.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter ShowProgress;

    private InternalLogger _logger = null!;
    private DomainHealthCheck _healthCheck = null!;
    /// <summary>DNS server used for queries.</summary>
    [Parameter(Mandatory = false)]
    public DnsClientX.DnsEndpoint DnsEndpoint = DnsClientX.DnsEndpoint.System;

    /// <summary>Initializes logging and helper classes.</summary>
    /// <returns>A completed task.</returns>
    protected override Task BeginProcessingAsync()
    {
        _logger = new InternalLogger(false);
        var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
        internalLoggerPowerShell.ResetActivityIdCounter();
        _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
        ApplyExecutionOptions(_healthCheck);
        return Task.CompletedTask;
    }

    /// <summary>Runs the port scan and writes results.</summary>
    /// <returns>A task that represents the asynchronous operation.</returns>
    protected override async Task ProcessRecordAsync()
    {
        await _healthCheck.ScanPorts(HostName, Ports, Profile, default, ShowProgress.IsPresent);
        var view = DomainDetective.Views.Converters.Convert(_healthCheck.PortScanAnalysis);
        WriteObject(view);
        if (IsExportRequested()) {
            try {
                var hadUnsupportedFormats = false;
                CompositionExportHelper.WriteReports(
                    new System.Collections.Generic.List<object> { view },
                    GetRequestedFormatsOrDefault(ExportDefaults.Format),
                    ExportPath,
                    HostName,
                    DomainDetective.Reports.ReportScope.Normal,
                    $"Port Scan Report - {HostName}",
                    OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                    TryOpenReport,
                    out hadUnsupportedFormats);

                if (hadUnsupportedFormats) {
                    await ExportNotImplementedAsync("Test-DDNetworkPortScan");
                }
            } catch (System.Exception ex) {
                WriteWarning($"Port scan export failed: {ex.Message}");
            }
        }
    }
}

