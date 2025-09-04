using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Resolves CNAME chains and detects resolution issues or loops.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class CnameAnalysis : IHasAssessments {
    /// <summary>Domain under analysis.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets DNS configuration for queries.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();
    /// <summary>Gets or sets override for DNS queries.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }
    /// <summary>Gets a value indicating whether a CNAME exists for the domain.</summary>
    public bool CnameRecordExists { get; private set; }
    /// <summary>Gets the final CNAME target if one was found.</summary>
    public string? Target { get; private set; }
    /// <summary>Gets a value indicating whether the target resolves.</summary>
    public bool TargetResolves { get; private set; }
    /// <summary>Gets a value indicating whether a loop was detected.</summary>
    public bool LoopDetected { get; private set; }

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
        if (QueryDnsOverride != null) {
            return await QueryDnsOverride(name, type);
        }
        return await DnsConfiguration.QueryDNS(name, type);
    }

    /// <summary>
    /// Analyzes CNAME records for the given domain.
    /// </summary>
    public async Task Analyze(string domainName, InternalLogger logger, CancellationToken ct = default) {
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "CNAME", target: domainName);
        Subject = domainName;
        CnameRecordExists = false;
        Target = null;
        TargetResolves = false;
        LoopDetected = false;

        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var current = domainName;
        while (true) {
            ct.ThrowIfCancellationRequested();
            DnsAnswer[] cname;
            try {
                cname = await QueryDns(current, DnsRecordType.CNAME);
            } catch (Exception ex) {
                logger?.WriteErrorCode(CnameCodes.DnsLookupFailed, "DNS lookup failed for {0}: {1}", current, ex.Message);
                return;
            }
            if (cname == null || cname.Length == 0) {
                break;
            }
            CnameRecordExists = true;
            var next = cname[0].Data.TrimEnd('.');
            if (!visited.Add(next)) {
                LoopDetected = true;
                logger?.WriteErrorCode(CnameCodes.LoopDetected, "CNAME loop detected at {0}", next);
                return;
            }
            Target = next;
            current = next;
        }

        if (!CnameRecordExists) {
            logger?.WriteVerbose("No CNAME record found.");
            return;
        }

        logger?.WriteInformationCode(CnameCodes.NoLoop, "CNAME chain has no loop");

        try {
            var a = await QueryDns(Target!, DnsRecordType.A);
            var aaaa = await QueryDns(Target!, DnsRecordType.AAAA);
            TargetResolves = (a != null && a.Any()) || (aaaa != null && aaaa.Any());
        } catch (Exception ex) {
            logger?.WriteErrorCode(CnameCodes.DnsLookupFailed, "DNS lookup failed for {0}: {1}", Target, ex.Message);
            return;
        }

        if (TargetResolves) {
            logger?.WriteInformationCode(CnameCodes.TargetResolves, "CNAME target {0} resolves", Target);
        } else {
            logger?.WriteWarningCode(CnameCodes.TargetDoesNotResolve, "CNAME target {0} does not resolve", Target);
        }
    }

    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
}
