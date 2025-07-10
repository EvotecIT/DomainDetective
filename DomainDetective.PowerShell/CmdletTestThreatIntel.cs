using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Queries reputation services for a domain or IP address.</summary>
/// <para>Part of the DomainDetective project.</para>
/// <example>
///   <summary>Check reputation listings.</summary>
///   <code>Test-ThreatIntel -NameOrIpAddress example.com</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDThreatIntel")]
[Alias("Test-DomainThreatIntel")]
public sealed class CmdletTestThreatIntel : AsyncPSCmdlet {
    /// <param name="NameOrIpAddress">Domain or IP address to query.</param>
    [Parameter(Mandatory = true, Position = 0)]
    [ValidateNotNullOrEmpty]
    public string NameOrIpAddress;

    /// <param name="GoogleApiKey">Google Safe Browsing API key.</param>
    [Parameter(Mandatory = false)]
    public string? GoogleApiKey;

    /// <param name="PhishTankApiKey">PhishTank API key.</param>
    [Parameter(Mandatory = false)]
    public string? PhishTankApiKey;

    /// <param name="VirusTotalApiKey">VirusTotal API key.</param>
    [Parameter(Mandatory = false)]
    public string? VirusTotalApiKey;

    private InternalLogger _logger;
    private DomainHealthCheck _healthCheck;

    protected override Task BeginProcessingAsync() {
        _logger = new InternalLogger(false);
        var loggerPs = new InternalLoggerPowerShell(
            _logger,
            this.WriteVerbose,
            this.WriteWarning,
            this.WriteDebug,
            this.WriteError,
            this.WriteProgress,
            this.WriteInformation);
        loggerPs.ResetActivityIdCounter();
        _healthCheck = new DomainHealthCheck(internalLogger: _logger);
        return Task.CompletedTask;
    }

    protected override async Task ProcessRecordAsync() {
        _healthCheck.GoogleSafeBrowsingApiKey = GoogleApiKey;
        _healthCheck.PhishTankApiKey = PhishTankApiKey;
        _healthCheck.VirusTotalApiKey = VirusTotalApiKey;

        _logger.WriteVerbose("Querying threat intel for {0}", NameOrIpAddress);
        await _healthCheck.VerifyThreatIntel(NameOrIpAddress);
        WriteObject(_healthCheck.ThreatIntelAnalysis);
    }
}
