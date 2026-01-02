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
public sealed class CmdletTestSmtpAuth : ExportableAsyncPSCmdlet {
    /// <summary>Domain(s) to query.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    [ValidateDomainName]
    public string[] DomainName = System.Array.Empty<string>();

    /// <summary>SMTP port number.</summary>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
    public int Port = 25;

    /// <summary>Capture EHLO capabilities in addition to AUTH.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter InspectCapabilities;

    /// <summary>Runs SMTP AUTH checks and writes results.</summary>
    /// <returns>A task that represents the asynchronous operation.</returns>
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
            var healthCheck = new DomainHealthCheck(internalLogger: logger);
            ApplyExecutionOptions(healthCheck);

            logger.WriteVerbose("Checking SMTP AUTH for {0}:{1}", domain, Port);
            healthCheck.SmtpAuthAnalysis.InspectCapabilities = InspectCapabilities.IsPresent;
            await healthCheck.VerifySmtpAuth(domain, Port, cancellationToken: CancelToken);
            var view = DomainDetective.Views.Converters.Convert(healthCheck.SmtpAuthAnalysis);
            WriteObject(view);
            if (IsExportRequested()) {
                await ExportNotImplementedAsync("Test-DDEmailSmtpAuth");
            }
        }

        await ForEachAsync(DomainName, ProcessDomainAsync);
    }
}
