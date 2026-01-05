using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates an SOA desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateSoa")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateSoa : PSCmdlet {
    /// <para>Enable/disable the SOA desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>When true, require an SOA record to exist.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireRecord { get; set; }

    /// <para>When true, require SOA serial format to match expected patterns.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireSerialFormat { get; set; }

    /// <para>Minimum allowed SOA refresh value (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinRefresh { get; set; }

    /// <para>Maximum allowed SOA refresh value (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxRefresh { get; set; }

    /// <para>Minimum allowed SOA retry value (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinRetry { get; set; }

    /// <para>Maximum allowed SOA retry value (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxRetry { get; set; }

    /// <para>Minimum allowed SOA expire value (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinExpire { get; set; }

    /// <para>Maximum allowed SOA expire value (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxExpire { get; set; }

    /// <para>Minimum allowed SOA minimum value (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinMinimum { get; set; }

    /// <para>Maximum allowed SOA minimum value (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxMinimum { get; set; }

    /// <summary>Creates an SOA policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Soa = new DesiredStateSoaPolicy {
                Enabled = Enabled,
                RequireRecord = RequireRecord,
                RequireSerialFormat = RequireSerialFormat,
                MinRefresh = MinRefresh,
                MaxRefresh = MaxRefresh,
                MinRetry = MinRetry,
                MaxRetry = MaxRetry,
                MinExpire = MinExpire,
                MaxExpire = MaxExpire,
                MinMinimum = MinMinimum,
                MaxMinimum = MaxMinimum
            }
        };

        WriteObject(profile);
    }
}
