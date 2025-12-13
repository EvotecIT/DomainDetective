using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Queries reputation services for a domain or IP address.</summary>
/// <para>Part of the DomainDetective project.</para>
/// <example>
///   <summary>Check reputation listings.</summary>
///   <code>Test-DDDomainThreatIntel -NameOrIpAddress example.com</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDomainThreatIntel")]
[Alias("Test-DomainThreatIntel")]
    public sealed class CmdletTestThreatIntel : ExportableAsyncPSCmdlet {
        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false)]
        public DnsClientX.DnsEndpoint DnsEndpoint = DnsClientX.DnsEndpoint.System;
    /// <summary>Domain or IP address to query.</summary>
    [Parameter(Mandatory = true, Position = 0)]
    [ValidateNotNullOrEmpty]
        public string NameOrIpAddress = string.Empty;

    /// <summary>Google Safe Browsing API key.</summary>
    [Parameter(Mandatory = false)]
    public string? GoogleApiKey;

    /// <summary>PhishTank API key.</summary>
    [Parameter(Mandatory = false)]
    public string? PhishTankApiKey;

    /// <summary>VirusTotal API key.</summary>
    [Parameter(Mandatory = false)]
    public string? VirusTotalApiKey;

        private InternalLogger _logger = null!;
        private DomainHealthCheck _healthCheck = null!;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
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
        _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
        return Task.CompletedTask;
    }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
    protected override async Task ProcessRecordAsync() {
        _healthCheck.GoogleSafeBrowsingApiKey = GoogleApiKey;
        _healthCheck.PhishTankApiKey = PhishTankApiKey;
        _healthCheck.VirusTotalApiKey = VirusTotalApiKey;

        _logger.WriteVerbose("Querying threat intel for {0}", NameOrIpAddress);
        await _healthCheck.VerifyThreatIntel(NameOrIpAddress);
        var view = DomainDetective.Views.Converters.Convert(_healthCheck.ThreatIntelAnalysis);
        WriteObject(view);
        if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
    }
}
