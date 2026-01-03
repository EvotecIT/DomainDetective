using System.Management.Automation;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Creates a DNS TTL desired state policy fragment.</summary>
/// <para>The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.</para>
[Cmdlet(VerbsCommon.New, "DDDesiredStateTtl")]
[OutputType(typeof(DesiredStateProfile))]
public sealed class CmdletNewDesiredStateTtl : PSCmdlet {
    /// <para>Enable/disable the TTL desired state module.</para>
    [Parameter(Mandatory = false)]
    public bool? Enabled { get; set; }

    /// <para>Minimum allowed TTL for A records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinASeconds { get; set; }

    /// <para>Maximum allowed TTL for A records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxASeconds { get; set; }

    /// <para>Minimum allowed TTL for AAAA records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinAaaaSeconds { get; set; }

    /// <para>Maximum allowed TTL for AAAA records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxAaaaSeconds { get; set; }

    /// <para>Minimum allowed TTL for MX records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinMxSeconds { get; set; }

    /// <para>Maximum allowed TTL for MX records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxMxSeconds { get; set; }

    /// <para>Minimum allowed TTL for NS records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinNsSeconds { get; set; }

    /// <para>Maximum allowed TTL for NS records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxNsSeconds { get; set; }

    /// <para>Minimum allowed TTL for SOA records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinSoaSeconds { get; set; }

    /// <para>Maximum allowed TTL for SOA records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxSoaSeconds { get; set; }

    /// <para>Minimum allowed TTL for SPF TXT records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinSpfTxtSeconds { get; set; }

    /// <para>Maximum allowed TTL for SPF TXT records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxSpfTxtSeconds { get; set; }

    /// <para>Minimum allowed TTL for DMARC TXT records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinDmarcTxtSeconds { get; set; }

    /// <para>Maximum allowed TTL for DMARC TXT records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxDmarcTxtSeconds { get; set; }

    /// <para>Minimum allowed TTL for DKIM selector TXT records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinDkimSelectorTxtSeconds { get; set; }

    /// <para>Maximum allowed TTL for DKIM selector TXT records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxDkimSelectorTxtSeconds { get; set; }

    /// <para>Minimum allowed TTL for MTA-STS TXT records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinMtastsTxtSeconds { get; set; }

    /// <para>Maximum allowed TTL for MTA-STS TXT records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxMtastsTxtSeconds { get; set; }

    /// <para>Minimum allowed TTL for TLS-RPT TXT records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MinTlsRptTxtSeconds { get; set; }

    /// <para>Maximum allowed TTL for TLS-RPT TXT records (seconds).</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, int.MaxValue)]
    public int? MaxTlsRptTxtSeconds { get; set; }

    /// <para>When true, requires A record TTL to be uniform across name servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAUniformAcrossNs { get; set; }

    /// <para>When true, requires AAAA record TTL to be uniform across name servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireAaaaUniformAcrossNs { get; set; }

    /// <para>When true, requires NS record TTL to be uniform across name servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireNsUniformAcrossNs { get; set; }

    /// <para>When true, requires CNAME record TTL to be uniform across name servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireCnameUniformAcrossNs { get; set; }

    /// <para>When true, requires SPF TXT record TTL to be uniform across name servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireSpfTxtUniformAcrossNs { get; set; }

    /// <para>When true, requires DMARC TXT record TTL to be uniform across name servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireDmarcTxtUniformAcrossNs { get; set; }

    /// <para>When true, requires DKIM selector TXT record TTL to be uniform across name servers.</para>
    [Parameter(Mandatory = false)]
    public bool? RequireDkimTxtUniformAcrossNs { get; set; }

    /// <summary>Creates a TTL policy fragment as a DesiredStateProfile.</summary>
    protected override void ProcessRecord() {
        var profile = new DesiredStateProfile {
            Ttl = new DesiredStateTtlPolicy {
                Enabled = Enabled,
                MinASeconds = MinASeconds,
                MaxASeconds = MaxASeconds,
                MinAaaaSeconds = MinAaaaSeconds,
                MaxAaaaSeconds = MaxAaaaSeconds,
                MinMxSeconds = MinMxSeconds,
                MaxMxSeconds = MaxMxSeconds,
                MinNsSeconds = MinNsSeconds,
                MaxNsSeconds = MaxNsSeconds,
                MinSoaSeconds = MinSoaSeconds,
                MaxSoaSeconds = MaxSoaSeconds,
                MinSpfTxtSeconds = MinSpfTxtSeconds,
                MaxSpfTxtSeconds = MaxSpfTxtSeconds,
                MinDmarcTxtSeconds = MinDmarcTxtSeconds,
                MaxDmarcTxtSeconds = MaxDmarcTxtSeconds,
                MinDkimSelectorTxtSeconds = MinDkimSelectorTxtSeconds,
                MaxDkimSelectorTxtSeconds = MaxDkimSelectorTxtSeconds,
                MinMtastsTxtSeconds = MinMtastsTxtSeconds,
                MaxMtastsTxtSeconds = MaxMtastsTxtSeconds,
                MinTlsRptTxtSeconds = MinTlsRptTxtSeconds,
                MaxTlsRptTxtSeconds = MaxTlsRptTxtSeconds,
                RequireAUniformAcrossNs = RequireAUniformAcrossNs,
                RequireAaaaUniformAcrossNs = RequireAaaaUniformAcrossNs,
                RequireNsUniformAcrossNs = RequireNsUniformAcrossNs,
                RequireCnameUniformAcrossNs = RequireCnameUniformAcrossNs,
                RequireSpfTxtUniformAcrossNs = RequireSpfTxtUniformAcrossNs,
                RequireDmarcTxtUniformAcrossNs = RequireDmarcTxtUniformAcrossNs,
                RequireDkimTxtUniformAcrossNs = RequireDkimTxtUniformAcrossNs
            }
        };

        WriteObject(profile);
    }
}
