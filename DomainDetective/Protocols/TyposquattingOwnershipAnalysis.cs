using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Options for building and comparing source-domain ownership signals.
/// </summary>
public sealed class TyposquattingOwnershipProfileOptions
{
    /// <summary>When true, ownership comparison is enabled.</summary>
    public bool Enabled { get; set; }

    /// <summary>When true, WHOIS registrar data is collected for the source domain.</summary>
    public bool IncludeWhois { get; set; } = true;

    /// <summary>When true, IP enrichment is collected for the source domain.</summary>
    public bool IncludeIpEnrichment { get; set; } = true;

    /// <summary>When true, source MX hosts are included in ownership comparison.</summary>
    public bool IncludeMx { get; set; } = true;

    /// <summary>Optional override for WHOIS profile collection.</summary>
    public Func<string, CancellationToken, Task<WhoisAnalysis?>>? WhoisOverride { get; set; }

    /// <summary>Optional override for IP enrichment profile collection.</summary>
    public Func<string, CancellationToken, Task<IpEnrichmentAnalysis?>>? IpEnrichmentOverride { get; set; }
}

/// <summary>
/// Ownership baseline for the source domain under analysis.
/// </summary>
public sealed class TyposquattingOwnershipProfile
{
    /// <summary>Gets or sets the domain value.</summary>
    public string Domain { get; init; } = string.Empty;
    /// <summary>Gets or sets the registrar value.</summary>
    public string Registrar { get; init; } = string.Empty;
    /// <summary>Gets or sets the name servers value.</summary>
    public IReadOnlyList<string> NameServers { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the mail exchangers value.</summary>
    public IReadOnlyList<string> MailExchangers { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the a records value.</summary>
    public IReadOnlyList<string> ARecords { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the aaaa records value.</summary>
    public IReadOnlyList<string> AaaaRecords { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the asns value.</summary>
    public IReadOnlyList<int> Asns { get; init; } = Array.Empty<int>();
    /// <summary>Represents the has any signals value.</summary>
    public bool HasAnySignals =>
        !string.IsNullOrWhiteSpace(Registrar)
        || NameServers.Count > 0
        || MailExchangers.Count > 0
        || ARecords.Count > 0
        || AaaaRecords.Count > 0
        || Asns.Count > 0;
}

/// <summary>
/// Ownership comparison result for a single candidate.
/// </summary>
public sealed class TyposquattingOwnershipMatch
{
    /// <summary>Gets or sets the likely owned value.</summary>
    public bool LikelyOwned { get; init; }
    /// <summary>Gets or sets the confidence score value.</summary>
    public int ConfidenceScore { get; init; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; init; } = string.Empty;
    /// <summary>Gets or sets the signals value.</summary>
    public IReadOnlyList<string> Signals { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the likely external value.</summary>
    public bool LikelyExternal { get; init; }
    /// <summary>Gets or sets the external confidence score value.</summary>
    public int ExternalConfidenceScore { get; init; }
    /// <summary>Gets or sets the external summary value.</summary>
    public string ExternalSummary { get; init; } = string.Empty;
    /// <summary>Gets or sets the external signals value.</summary>
    public IReadOnlyList<string> ExternalSignals { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Builds source profiles and compares candidates against them.
/// </summary>
public static class TyposquattingOwnershipAnalyzer
{
    /// <summary>Builds profile async.</summary>
    public static async Task<TyposquattingOwnershipProfile?> BuildProfileAsync(
        string domain,
        DnsConfiguration dnsConfiguration,
        Func<string, DnsRecordType, Task<DnsAnswer[]>> queryDns,
        TyposquattingOwnershipProfileOptions options,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domain) || options == null || !options.Enabled)
        {
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var aRecords = NormalizeDnsAnswers(await queryDns(domain, DnsRecordType.A).ConfigureAwait(false));
        var aaaaRecords = NormalizeDnsAnswers(await queryDns(domain, DnsRecordType.AAAA).ConfigureAwait(false));
        var nameServers = NormalizeDnsAnswers(await queryDns(domain, DnsRecordType.NS).ConfigureAwait(false));
        var mailExchangers = options.IncludeMx
            ? TyposquattingMailInfrastructure.NormalizeMxHosts(NormalizeDnsAnswers(await queryDns(domain, DnsRecordType.MX).ConfigureAwait(false)))
            : Array.Empty<string>();

        WhoisAnalysis? whois = null;
        if (options.IncludeWhois)
        {
            if (options.WhoisOverride != null)
            {
                whois = await options.WhoisOverride(domain, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                whois = new WhoisAnalysis
                {
                    DnsConfiguration = dnsConfiguration
                };
                await whois.QueryWhoisServer(domain, cancellationToken).ConfigureAwait(false);
                await whois.QueryIana(domain, cancellationToken).ConfigureAwait(false);
            }
        }

        IpEnrichmentAnalysis? ip = null;
        if (options.IncludeIpEnrichment)
        {
            if (options.IpEnrichmentOverride != null)
            {
                ip = await options.IpEnrichmentOverride(domain, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                ip = new IpEnrichmentAnalysis
                {
                    DnsConfiguration = dnsConfiguration
                };
                await ip.AnalyzeAsync(domain, additionalIpAddresses: null, logger: null, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
        }

        var asns = ip?.AsnCounts?.Keys
            .Distinct()
            .OrderBy(value => value)
            .ToArray() ?? Array.Empty<int>();

        return new TyposquattingOwnershipProfile
        {
            Domain = domain,
            Registrar = whois?.Registrar ?? string.Empty,
            NameServers = nameServers,
            MailExchangers = mailExchangers,
            ARecords = aRecords,
            AaaaRecords = aaaaRecords,
            Asns = asns
        };
    }

    /// <summary>Executes the compare candidates operation.</summary>
    public static void CompareCandidates(IReadOnlyList<TyposquattingCandidate>? candidates, TyposquattingOwnershipProfile? profile)
    {
        if (candidates == null || candidates.Count == 0 || profile == null || !profile.HasAnySignals)
        {
            return;
        }

        foreach (var candidate in candidates)
        {
            candidate.Ownership = CompareCandidate(candidate, profile);
        }
    }

    /// <summary>Executes the compare candidate operation.</summary>
    public static TyposquattingOwnershipMatch CompareCandidate(TyposquattingCandidate candidate, TyposquattingOwnershipProfile profile)
    {
        if (candidate == null)
        {
            throw new ArgumentNullException(nameof(candidate));
        }
        if (profile == null)
        {
            throw new ArgumentNullException(nameof(profile));
        }

        var ownershipSignals = new List<string>();
        var ownershipScore = 0;
        var externalSignals = new List<string>();
        var externalScore = 0;
        var candidateRegistrar = candidate.Enrichment?.Whois?.Registrar;
        string? normalizedProfileRegistrar = null;
        if (!string.IsNullOrWhiteSpace(profile.Registrar))
        {
            normalizedProfileRegistrar = profile.Registrar.Trim();
        }

        string? normalizedCandidateRegistrar = null;
        if (!string.IsNullOrWhiteSpace(candidateRegistrar))
        {
            normalizedCandidateRegistrar = candidateRegistrar!.Trim();
        }

        if (normalizedProfileRegistrar != null && normalizedCandidateRegistrar != null)
        {
            if (string.Equals(normalizedCandidateRegistrar, normalizedProfileRegistrar, StringComparison.OrdinalIgnoreCase))
            {
                ownershipScore += 35;
                ownershipSignals.Add("matches registrar");
            }
            else
            {
                externalScore += 20;
                externalSignals.Add("uses a different registrar");
            }
        }

        var nsOverlap = candidate.NsRecords
            .Intersect(profile.NameServers, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (nsOverlap.Length > 0)
        {
            ownershipScore += 35;
            ownershipSignals.Add("shares authoritative name servers");
        }
        else if (candidate.NsRecords.Count > 0 && profile.NameServers.Count > 0)
        {
            externalScore += 25;
            externalSignals.Add("uses different authoritative name servers");
        }

        var candidateMxHosts = TyposquattingMailInfrastructure.NormalizeMxHosts(candidate.MxRecords);
        var mxOverlap = candidateMxHosts
            .Intersect(profile.MailExchangers, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (mxOverlap.Length > 0)
        {
            ownershipScore += 20;
            ownershipSignals.Add("shares mail exchangers");
        }
        else if (candidateMxHosts.Count > 0 && profile.MailExchangers.Count > 0)
        {
            externalScore += 20;
            externalSignals.Add("uses different mail exchangers");
        }

        var candidateAddresses = candidate.ARecords
            .Concat(candidate.AaaaRecords)
            .ToArray();
        var sourceAddresses = profile.ARecords
            .Concat(profile.AaaaRecords)
            .ToArray();
        var addressOverlap = candidateAddresses
            .Intersect(sourceAddresses, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (addressOverlap.Length > 0)
        {
            ownershipScore += 45;
            ownershipSignals.Add("shares apex IP infrastructure");
        }
        else if (candidateAddresses.Length > 0 && sourceAddresses.Length > 0)
        {
            externalScore += 30;
            externalSignals.Add("resolves on different IP infrastructure");
        }

        var candidateAsns = candidate.Enrichment?.IpEnrichment?.AsnCounts?.Keys
            .Distinct()
            .ToArray() ?? Array.Empty<int>();
        var asnOverlap = candidateAsns
            .Intersect(profile.Asns)
            .ToArray();
        if (asnOverlap.Length > 0)
        {
            ownershipScore += 20;
            ownershipSignals.Add("shares ASN ownership hints");
        }
        else if (candidateAsns.Length > 0 && profile.Asns.Count > 0)
        {
            externalScore += 15;
            externalSignals.Add("maps to different ASN ownership hints");
        }

        ownershipScore = Math.Max(0, Math.Min(100, ownershipScore));
        externalScore = Math.Max(0, Math.Min(100, externalScore));
        var likelyOwned = ownershipScore >= 45;
        var likelyExternal = !likelyOwned && externalScore >= 35;
        return new TyposquattingOwnershipMatch
        {
            LikelyOwned = likelyOwned,
            ConfidenceScore = ownershipScore,
            Signals = ownershipSignals.ToArray(),
            Summary = ownershipSignals.Count > 0 ? string.Join(", ", ownershipSignals) : "no ownership overlap detected",
            LikelyExternal = likelyExternal,
            ExternalConfidenceScore = externalScore,
            ExternalSignals = externalSignals.ToArray(),
            ExternalSummary = externalSignals.Count > 0 ? string.Join(", ", externalSignals) : "no explicit external distinctiveness detected"
        };
    }

    private static IReadOnlyList<string> NormalizeDnsAnswers(DnsAnswer[]? answers)
    {
        if (answers == null || answers.Length == 0)
        {
            return Array.Empty<string>();
        }

        return answers
            .Select(static answer => (answer.Data ?? answer.DataRaw ?? string.Empty).Trim().TrimEnd('.'))
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
