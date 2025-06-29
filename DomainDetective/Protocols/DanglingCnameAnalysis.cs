using DnsClientX;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Resolves CNAME targets and detects dangling references.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class DanglingCnameAnalysis {
    /// <summary>Gets or sets DNS configuration for queries.</summary>
    public DnsConfiguration DnsConfiguration { get; set; }
    /// <summary>Gets or sets override for DNS queries.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }
    /// <summary>Gets a value indicating whether a CNAME exists for the domain.</summary>
    public bool CnameRecordExists { get; private set; }
    /// <summary>Gets the CNAME target if one was found.</summary>
    public string? Target { get; private set; }
    /// <summary>Gets a value indicating whether the target resolves.</summary>
    public bool TargetResolves { get; private set; }
    /// <summary>Gets a value indicating whether the target belongs to a known service.</summary>
    public bool KnownService { get; private set; }
    /// <summary>If DNS lookups fail, explains why.</summary>
    public string? FailureReason { get; private set; }
    /// <summary>Gets a value indicating whether the CNAME is dangling.</summary>
    public bool IsDangling => CnameRecordExists && !TargetResolves;
    /// <summary>Gets a value indicating whether the target is an unclaimed service.</summary>
    public bool UnclaimedService => IsDangling && KnownService;

    private static readonly string[] _serviceDomains = new[] {
        "azurewebsites.net",
        "github.io",
        "herokudns.com",
        "cloudfront.net"
    };

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
        if (QueryDnsOverride != null) {
            return await QueryDnsOverride(name, type);
        }
        return await DnsConfiguration.QueryDNS(name, type);
    }

    /// <summary>
    /// Queries the CNAME record for a domain and checks the target.
    /// </summary>
    public async Task Analyze(string domainName, InternalLogger logger, CancellationToken ct = default) {
        CnameRecordExists = false;
        Target = null;
        TargetResolves = false;
        KnownService = false;
        FailureReason = null;
        ct.ThrowIfCancellationRequested();
        DnsAnswer[] cname;
        try {
            cname = await QueryDns(domainName, DnsRecordType.CNAME);
        } catch (Exception ex) {
            FailureReason = $"DNS lookup failed: {ex.Message}";
            logger?.WriteError("DNS lookup failed for {0}: {1}", domainName, ex.Message);
            return;
        }
        if (cname == null || cname.Length == 0) {
            logger?.WriteVerbose("No CNAME record found.");
            return;
        }

        Target = cname[0].Data.TrimEnd('.');
        CnameRecordExists = true;
        logger?.WriteVerbose("CNAME target {0}", Target);

        KnownService = _serviceDomains.Any(s => Target.EndsWith(s, StringComparison.OrdinalIgnoreCase));
        DnsAnswer[] a;
        DnsAnswer[] aaaa;
        try {
            a = await QueryDns(Target, DnsRecordType.A);
            aaaa = await QueryDns(Target, DnsRecordType.AAAA);
        } catch (Exception ex) {
            FailureReason = $"DNS lookup failed: {ex.Message}";
            logger?.WriteError("DNS lookup failed for {0}: {1}", Target, ex.Message);
            return;
        }
        TargetResolves = (a != null && a.Any()) || (aaaa != null && aaaa.Any());

        if (!TargetResolves) {
            logger?.WriteWarning("CNAME target {0} does not resolve", Target);
        }
    }
}
