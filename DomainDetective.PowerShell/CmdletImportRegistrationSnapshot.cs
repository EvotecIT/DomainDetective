using System;
using System.Management.Automation;
using DnsClientX;
using DomainDetective.TimeSeries.Registration;

namespace DomainDetective.PowerShell;

/// <summary>Captures a unified WHOIS/RDAP registration snapshot and stores it in a time-series store.</summary>
/// <para>Queries RDAP (structured) and WHOIS (fallback/extra fields) and stores a normalized JSON snapshot on disk.</para>
/// <example>
///   <summary>Capture and store a registration snapshot</summary>
///   <code>Import-DDRegistrationSnapshot -DomainName example.com -StorePath .\Store</code>
/// </example>
[Cmdlet(VerbsData.Import, "DDRegistrationSnapshot")]
[Alias("Import-RegistrationSnapshot")]
[OutputType(typeof(RegistrationSnapshot))]
public sealed class CmdletImportRegistrationSnapshot : PSCmdlet
{
    /// <summary>Domain to query.</summary>
    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    public string DomainName { get; set; } = string.Empty;

    /// <summary>Root directory for snapshot storage.</summary>
    [Parameter(Mandatory = true)]
    [ValidateNotNullOrEmpty]
    public string StorePath { get; set; } = string.Empty;

    /// <summary>DNS endpoint used for auxiliary lookups (default System).</summary>
    [Parameter(Mandatory = false)]
    public DnsEndpoint DnsEndpoint { get; set; } = DnsEndpoint.System;

    /// <summary>Skip RDAP query (use WHOIS only).</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter SkipRdap { get; set; }

    /// <summary>Skip WHOIS query (use RDAP only).</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter SkipWhois { get; set; }

    /// <summary>WHOIS timeout in seconds (default 30).</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 600)]
    public int WhoisTimeoutSeconds { get; set; } = 30;

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord()
    {
        var domain = (DomainName ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(domain))
        {
            ThrowTerminatingError(new ErrorRecord(new ArgumentException("DomainName is required.", nameof(DomainName)), "DomainNameRequired", ErrorCategory.InvalidArgument, DomainName));
            return;
        }

        var logger = new InternalLogger(false);
        var healthCheck = new DomainHealthCheck(DnsEndpoint, logger);
        healthCheck.WhoisAnalysis.Timeout = TimeSpan.FromSeconds(WhoisTimeoutSeconds);

        RdapAnalysis? rdap = null;
        WhoisAnalysis? whois = null;

        if (!SkipRdap.IsPresent)
        {
            try
            {
                healthCheck.QueryRDAP(domain).GetAwaiter().GetResult();
                rdap = healthCheck.RdapAnalysis;
            }
            catch (Exception ex)
            {
                WriteWarning($"RDAP query failed: {ex.Message}");
            }
        }

        if (!SkipWhois.IsPresent)
        {
            try
            {
                healthCheck.CheckWHOIS(domain).GetAwaiter().GetResult();
                whois = healthCheck.WhoisAnalysis;
            }
            catch (Exception ex)
            {
                WriteWarning($"WHOIS query failed: {ex.Message}");
            }
        }

        var snapshot = RegistrationSnapshotBuilder.Build(domain, rdap, whois);
        var store = new RegistrationTimeSeriesStore(StorePath);
        _ = store.SaveSnapshot(snapshot);

        WriteObject(snapshot);
    }
}
