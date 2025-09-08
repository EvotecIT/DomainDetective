using System.Management.Automation;
using DomainDetective.Views;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Enumerates SMTP AUTH mechanisms across MX hosts.</summary>
/// <para>Part of the DomainDetective project.</para>
/// <remarks>
/// Returns a unified SmtpAuthInfo view with per-server Mechanisms/Capabilities and Assessments. Raw contains the full SmtpAuthAnalysis.
/// </remarks>
/// <example>
///   <summary>List AUTH mechanisms for a domain.</summary>
///   <code>Test-DDEmailSmtpAuth -DomainName example.com</code>
/// </example>
/// <example>
///   <summary>Include EHLO capabilities.</summary>
///   <code>Test-DDEmailSmtpAuth -DomainName example.com -InspectCapabilities</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailSmtpAuth", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailSmtpAuth")]
[OutputType(typeof(SmtpAuthInfo))]
public sealed class CmdletTestSmtpAuth : ExportableAsyncPSCmdlet
{
    /// <summary>Domain to query.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
    [ValidateNotNullOrEmpty]
    public string DomainName;

    /// <summary>SMTP port number.</summary>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
    public int Port = 25;

    /// <summary>Capture EHLO capabilities in addition to AUTH.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter InspectCapabilities;

    private InternalLogger _logger;
    private DomainHealthCheck _healthCheck;

    /// <summary>Initializes logging and helper classes.</summary>
    /// <returns>A completed task.</returns>
    protected override Task BeginProcessingAsync()
    {
        _logger = new InternalLogger(false);
        var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
        internalLoggerPowerShell.ResetActivityIdCounter();
        _healthCheck = new DomainHealthCheck(internalLogger: _logger);
        return Task.CompletedTask;
    }

    /// <summary>Runs SMTP AUTH checks and writes results.</summary>
    /// <returns>A task that represents the asynchronous operation.</returns>
    protected override async Task ProcessRecordAsync()
    {
        _logger.WriteVerbose("Checking SMTP AUTH for {0}:{1}", DomainName, Port);
        _healthCheck.SmtpAuthAnalysis.InspectCapabilities = InspectCapabilities.IsPresent;
        await _healthCheck.VerifySmtpAuth(DomainName, Port);
        var view = DomainDetective.Views.Converters.Convert(_healthCheck.SmtpAuthAnalysis);
        WriteObject(view);
        if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
    }
}
