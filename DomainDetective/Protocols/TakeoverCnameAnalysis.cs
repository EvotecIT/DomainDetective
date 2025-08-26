using DnsClientX;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Detects CNAME records pointing to cloud providers prone to subdomain takeover.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class TakeoverCnameAnalysis : IHasAssessments
{
    /// <summary>DNS configuration for lookups.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();
    /// <summary>Override DNS query logic.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    /// <summary>Indicates whether a CNAME record exists.</summary>
    public bool CnameRecordExists { get; private set; }
    /// <summary>CNAME target if found.</summary>
    public string? Target { get; private set; }
    /// <summary>True when the CNAME points to a known takeover risk provider.</summary>
    public bool IsTakeoverRisk { get; private set; }

    private static HashSet<string> _providerDomains = LoadDefaultProviders();

    private static HashSet<string> LoadDefaultProviders() {
        try {
            using var stream = typeof(TakeoverCnameAnalysis).Assembly.GetManifestResourceStream("DomainDetective.takeover.json");
            if (stream != null) {
                using var reader = new StreamReader(stream);
                    var json = reader.ReadToEnd();
                    var entries = JsonSerializer.Deserialize<string[]>(json)
                        ?.Where(s => !string.IsNullOrWhiteSpace(s))
                        ?? Enumerable.Empty<string>();
                    return new HashSet<string>(entries, StringComparer.OrdinalIgnoreCase);
            }
        } catch {
            // ignore malformed resource
        }
        return new HashSet<string>(Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Loads takeover provider list from a JSON file.</summary>
    /// <param name="filePath">JSON array file path.</param>
    public static void LoadTakeoverList(string filePath) {
        if (!File.Exists(filePath)) {
            return;
        }
        try {
            using var stream = File.OpenRead(filePath);
            var entries = JsonSerializer.DeserializeAsync<string[]>(stream)
                .GetAwaiter().GetResult()
                ?.Where(s => !string.IsNullOrWhiteSpace(s))
                ?? Enumerable.Empty<string>();
            _providerDomains = new HashSet<string>(entries, StringComparer.OrdinalIgnoreCase);
        } catch {
            // ignore malformed list
        }
    }

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type)
    {
        if (QueryDnsOverride != null)
        {
            return await QueryDnsOverride(name, type);
        }

        return await DnsConfiguration.QueryDNS(name, type);
    }

    /// <summary>
    /// Queries the domain CNAME and determines if it belongs to a risky provider.
    /// </summary>
    public async Task Analyze(string domainName, InternalLogger logger, CancellationToken ct = default)
    {
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "TAKEOVER", target: domainName);
        CnameRecordExists = false;
        Target = null;
        IsTakeoverRisk = false;
        ct.ThrowIfCancellationRequested();

        var cname = await QueryDns(domainName, DnsRecordType.CNAME);
        if (cname == null || cname.Length == 0)
        {
            logger?.WriteVerbose("No CNAME record found.");
            return;
        }

        Target = cname[0].Data.TrimEnd('.');
        CnameRecordExists = true;
        logger?.WriteVerbose("CNAME target {0}", Target);

        IsTakeoverRisk = _providerDomains.Any(d => Target.EndsWith(d, StringComparison.OrdinalIgnoreCase));
        if (IsTakeoverRisk)
        {
            logger?.WriteWarningCode(TakeoverCnameCodes.RiskyProvider, "CNAME target {0} is hosted on a takeover prone provider", Target);
        }
    }

    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
}
