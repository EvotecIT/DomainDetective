using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Validates forward-confirmed reverse DNS for MX hosts.</summary>
/// <example>
///   <summary>Check FCrDNS configuration.</summary>
///   <code>Test-FCrDns -DomainName example.com</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsForwardReverse", DefaultParameterSetName = "ServerName")]
[Alias("Test-DnsFcrDns")]
public sealed class CmdletTestFCrDns : AsyncPSCmdlet
{
    /// <param name="DomainName">Domain to analyze.</param>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
    [ValidateNotNullOrEmpty]
    public string DomainName;

    /// <param name="DnsEndpoint">DNS server used for queries.</param>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    private InternalLogger _logger;
    private DomainHealthCheck _healthCheck;

    protected override Task BeginProcessingAsync()
    {
        _logger = new InternalLogger(false);
        var psLogger = new InternalLoggerPowerShell(
            _logger,
            this.WriteVerbose,
            this.WriteWarning,
            this.WriteDebug,
            this.WriteError,
            this.WriteProgress,
            this.WriteInformation);
        psLogger.ResetActivityIdCounter();
        _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
        return Task.CompletedTask;
    }

    protected override async Task ProcessRecordAsync()
    {
        _logger.WriteVerbose("Querying FCrDNS for domain: {0}", DomainName);
        await _healthCheck.Verify(DomainName, new[] { HealthCheckType.FCRDNS });
        WriteObject(_healthCheck.FcrDnsAnalysis);
    }
}
