using System;
using System.Management.Automation;
using DomainDetective.TimeSeries.Registration;

namespace DomainDetective.PowerShell;

/// <summary>Builds a structured WHOIS/RDAP drift view from stored registration snapshots.</summary>
/// <para>Loads stored snapshots for a domain and produces a drift view suitable for Word/HTML composition reports.</para>
/// <example>
///   <summary>Get drift for the last 90 days</summary>
///   <code>Get-DDRegistrationDrift -DomainName example.com -StorePath .\Store -SinceUtc (Get-Date).ToUniversalTime().AddDays(-90)</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDRegistrationDrift")]
[Alias("Get-RegistrationDrift")]
[OutputType(typeof(DomainDetective.Views.RegistrationDriftInfo))]
public sealed class CmdletGetRegistrationDrift : PSCmdlet
{
    /// <summary>Domain to load snapshots for.</summary>
    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    [ValidateDomainName]
    public string DomainName { get; set; } = string.Empty;

    /// <summary>Root directory for snapshot storage.</summary>
    [Parameter(Mandatory = true)]
    [ValidateNotNullOrEmpty]
    public string StorePath { get; set; } = string.Empty;

    /// <summary>Only load snapshots captured since this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord()
    {
        var domain = (DomainName ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(domain))
        {
            ThrowTerminatingError(new ErrorRecord(new ArgumentException("DomainName is required.", nameof(DomainName)), "DomainNameRequired", ErrorCategory.InvalidArgument, DomainName));
            return;
        }

        var store = new RegistrationTimeSeriesStore(StorePath);
        DateTimeOffset? since = null;
        if (SinceUtc.HasValue)
        {
            since = new DateTimeOffset(DateTime.SpecifyKind(SinceUtc.Value, DateTimeKind.Utc));
        }

        var snapshots = store.LoadSnapshots(domain, since);
        var view = DomainDetective.Views.Converters.Convert(snapshots, subjectOverride: domain);
        WriteObject(view);
    }
}
