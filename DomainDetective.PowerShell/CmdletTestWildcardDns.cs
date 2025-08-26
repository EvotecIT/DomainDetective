using DnsClientX;
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
    /// <summary>Domain to query.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
    [ValidateNotNullOrEmpty]
    public string DomainName;

    /// <summary>DNS server used for queries.</summary>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    private InternalLogger _logger;
    private DomainHealthCheck healthCheck;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
    protected override Task BeginProcessingAsync()
    {
        _logger = new InternalLogger(false);
        var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
        internalLoggerPowerShell.ResetActivityIdCounter();
        healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
        return Task.CompletedTask;
    }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
    protected override async Task ProcessRecordAsync()
    {
        _logger.WriteVerbose("Querying wildcard DNS for domain: {0}", DomainName);
        await healthCheck.Verify(DomainName, new[] { HealthCheckType.WILDCARDDNS });
        WriteObject(healthCheck.WildcardDnsAnalysis);
        if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
    }
}
