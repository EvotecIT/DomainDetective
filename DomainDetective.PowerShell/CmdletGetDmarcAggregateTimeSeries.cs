using System;
using System.Management.Automation;
using DomainDetective.TimeSeries.DmarcAggregate;
using DomainDetective.Views;

namespace DomainDetective.PowerShell;

/// <summary>Builds a DMARC Aggregate (RUA) time-series view from stored snapshots.</summary>
/// <para>Loads normalized snapshots from disk and outputs a view object suitable for Export-DDSecurityReport.</para>
/// <example>
///   <summary>Build a per-domain DMARC aggregate section from a store</summary>
///   <code>Get-DDDmarcAggregateTimeSeries -DomainName example.com -StorePath .\Store</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDDmarcAggregateTimeSeries")]
[Alias("Get-DmarcAggregateTimeSeries")]
[OutputType(typeof(DmarcAggregateTimeSeriesInfo))]
public sealed class CmdletGetDmarcAggregateTimeSeries : PSCmdlet
{
    /// <summary>Domain(s) to load.</summary>
    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    [ValidateDomainName]
    public string[] DomainName { get; set; } = Array.Empty<string>();

    /// <summary>Root directory for snapshot storage.</summary>
    [Parameter(Mandatory = true)]
    [ValidateNotNullOrEmpty]
    public string StorePath { get; set; } = string.Empty;

    /// <summary>Only include snapshots with end time on/after this UTC date/time.</summary>
    [Parameter(Mandatory = false)]
    public DateTime? SinceUtc { get; set; }

    /// <summary>Convenience override for -SinceUtc (UTC): include snapshots from the last N days.</summary>
    [Parameter(Mandatory = false)]
    public int Days { get; set; }

    /// <summary>Executes the cmdlet.</summary>
    protected override void ProcessRecord()
    {
        var store = new DmarcAggregateTimeSeriesStore(StorePath);
        DateTimeOffset? since = null;
        if (Days > 0)
        {
            since = DateTimeOffset.UtcNow.AddDays(-Days);
        }
        else if (SinceUtc.HasValue)
        {
            since = new DateTimeOffset(DateTime.SpecifyKind(SinceUtc.Value, DateTimeKind.Utc));
        }

        foreach (var domain in DomainName ?? Array.Empty<string>())
        {
            if (string.IsNullOrWhiteSpace(domain)) continue;
            var snaps = store.LoadSnapshots(domain, since);
            var view = Converters.Convert(snaps, subjectOverride: domain);
            WriteObject(view);
        }
    }
}
