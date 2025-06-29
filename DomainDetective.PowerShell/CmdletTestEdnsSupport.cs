using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Tests EDNS support on authoritative name servers.</summary>
/// <para>Part of the DomainDetective project.</para>
/// <example>
///   <summary>Check EDNS support.</summary>
///   <code>Test-EdnsSupport -DomainName example.com</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "EdnsSupport", DefaultParameterSetName = "ServerName")]
public sealed class CmdletTestEdnsSupport : AsyncPSCmdlet
{
    /// <param name="DomainName">Domain to query.</param>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
    [ValidateNotNullOrEmpty]
    public string DomainName;

    /// <param name="DnsEndpoint">DNS server used for queries.</param>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    private InternalLogger _logger;
    private DomainHealthCheck healthCheck;

    protected override Task BeginProcessingAsync()
    {
        _logger = new InternalLogger(false);
        var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
        internalLoggerPowerShell.ResetActivityIdCounter();
        healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
        return Task.CompletedTask;
    }

    protected override async Task ProcessRecordAsync()
    {
        _logger.WriteVerbose("Querying EDNS support for domain: {0}", DomainName);
        await healthCheck.Verify(DomainName, new[] { HealthCheckType.EDNSSUPPORT });
        WriteObject(healthCheck.EdnsSupportAnalysis);
    }
}
