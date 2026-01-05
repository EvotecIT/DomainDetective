using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>
/// Detects if CNAME records point to known flattening services like Cloudflare.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class FlatteningServiceAnalysis : IHasAssessments
{
    /// <summary>Domain under analysis.</summary>
    public string? Subject { get; private set; }
    /// <summary>DNS configuration for lookups.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();
    /// <summary>Override DNS query logic.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    /// <summary>Indicates whether a CNAME record exists.</summary>
    public bool CnameRecordExists { get; private set; }
    /// <summary>The target of the CNAME record.</summary>
    public string? Target { get; private set; }
    /// <summary>True when the CNAME points to a known flattening service.</summary>
    public bool IsFlatteningService { get; private set; }

    /// <summary>Flattened A/AAAA addresses resolved for the apex.</summary>
    public List<string> Addresses { get; } = new();

    /// <summary>Structured assessments captured during flattening service detection.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>Recommendations derived from assessments.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    private static readonly string[] _flatteningDomains = new[]
    {
        "cloudflare.net"
    };

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (QueryDnsOverride != null)
        {
            return await QueryDnsOverride(name, type);
        }

        return await DnsConfiguration.QueryDNS(name, type, cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Queries the domain CNAME and determines if it belongs to a flattening service.
    /// </summary>
    public async Task Analyze(string domainName, InternalLogger logger, CancellationToken ct = default)
    {
        Subject = domainName;
        CnameRecordExists = false;
        Target = null;
        IsFlatteningService = false;
        Addresses.Clear();
        ct.ThrowIfCancellationRequested();
        using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "CNAME", target: domainName) : null;

        var cname = await QueryDns(domainName, DnsRecordType.CNAME, ct);
        if (cname == null || cname.Length == 0)
        {
            logger?.WriteVerbose("No CNAME record found.");
            return;
        }

        Target = cname[0].Data.TrimEnd('.');
        CnameRecordExists = true;
        logger?.WriteVerbose("CNAME target {0}", Target);

        IsFlatteningService = Target != null && _flatteningDomains.Any(d => DomainHelper.IsDomainOrSubdomainOf(Target, d));
        if (IsFlatteningService)
        {
            logger?.WriteWarningCode(FlatteningServiceCodes.UsesFlatteningService, "CNAME uses a known flattening service");

            var a = await QueryDns(domainName, DnsRecordType.A, ct);
            var aaaa = await QueryDns(domainName, DnsRecordType.AAAA, ct);

            foreach (var ans in a.Concat(aaaa))
            {
                var addr = ans.Data.TrimEnd('.');
                if (!string.IsNullOrWhiteSpace(addr))
                {
                    Addresses.Add(addr);
                }
            }

            if (Addresses.Count > 0)
            {
                logger?.WriteInformationCode(FlatteningServiceCodes.ResolvedAddresses, "flattening service resolved addresses");
            }
        }
    }
}
