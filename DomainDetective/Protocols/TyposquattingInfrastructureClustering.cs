using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// Shared infrastructure cluster built from registrar, name server, and ASN overlaps.
/// </summary>
public sealed class TyposquattingInfrastructureCluster
{
    public string Id { get; init; } = string.Empty;
    public string Label { get; init; } = string.Empty;
    public IReadOnlyList<string> Domains { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> SharedSignals { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Registrars { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> NameServers { get; init; } = Array.Empty<string>();
    public IReadOnlyList<int> Asns { get; init; } = Array.Empty<int>();
    public int HighestRiskScore { get; init; }
    public int ThreatListedCount { get; init; }
    public bool HasMultipleCandidates => Domains.Count > 1;
}

/// <summary>
/// Builds connected clusters of likely external typosquatting candidates that share infrastructure signals.
/// </summary>
public static class TyposquattingInfrastructureClusterAnalyzer
{
    public static IReadOnlyList<TyposquattingInfrastructureCluster> BuildClusters(IReadOnlyList<TyposquattingCandidate>? candidates)
    {
        if (candidates == null || candidates.Count == 0)
        {
            return Array.Empty<TyposquattingInfrastructureCluster>();
        }

        var eligible = candidates
            .Where(static candidate => candidate != null)
            .Where(static candidate => candidate.AppearsRegistered)
            .Where(static candidate => candidate.Ownership?.LikelyOwned != true)
            .Where(static candidate => candidate.Ownership?.LikelyExternal == true || candidate.Enrichment != null)
            .ToList();
        if (eligible.Count == 0)
        {
            return Array.Empty<TyposquattingInfrastructureCluster>();
        }

        var signalMap = eligible.ToDictionary(
            static candidate => candidate,
            BuildSignals,
            ReferenceEqualityComparer<TyposquattingCandidate>.Instance);
        var tokenOwners = new Dictionary<string, List<TyposquattingCandidate>>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in signalMap)
        {
            foreach (var token in entry.Value.Tokens)
            {
                if (!tokenOwners.TryGetValue(token, out var owners))
                {
                    owners = new List<TyposquattingCandidate>();
                    tokenOwners[token] = owners;
                }

                owners.Add(entry.Key);
            }
        }

        var adjacency = new Dictionary<TyposquattingCandidate, HashSet<TyposquattingCandidate>>(ReferenceEqualityComparer<TyposquattingCandidate>.Instance);
        foreach (var candidate in eligible)
        {
            adjacency[candidate] = new HashSet<TyposquattingCandidate>(ReferenceEqualityComparer<TyposquattingCandidate>.Instance);
        }

        foreach (var owners in tokenOwners.Values)
        {
            if (owners.Count < 2)
            {
                continue;
            }

            for (var i = 0; i < owners.Count; i++)
            {
                for (var j = i + 1; j < owners.Count; j++)
                {
                    adjacency[owners[i]].Add(owners[j]);
                    adjacency[owners[j]].Add(owners[i]);
                }
            }
        }

        var visited = new HashSet<TyposquattingCandidate>(ReferenceEqualityComparer<TyposquattingCandidate>.Instance);
        var clusters = new List<TyposquattingInfrastructureCluster>();
        var index = 1;

        foreach (var candidate in eligible.OrderBy(static candidate => candidate.Domain, StringComparer.OrdinalIgnoreCase))
        {
            if (!visited.Add(candidate))
            {
                continue;
            }

            var component = new List<TyposquattingCandidate>();
            var queue = new Queue<TyposquattingCandidate>();
            queue.Enqueue(candidate);

            while (queue.Count > 0)
            {
                var current = queue.Dequeue();
                component.Add(current);
                foreach (var neighbor in adjacency[current])
                {
                    if (visited.Add(neighbor))
                    {
                        queue.Enqueue(neighbor);
                    }
                }
            }

            var cluster = BuildCluster(component, signalMap, index++);
            clusters.Add(cluster);
            foreach (var member in component)
            {
                member.InfrastructureCluster = cluster;
            }
        }

        return clusters
            .OrderByDescending(static cluster => cluster.Domains.Count)
            .ThenByDescending(static cluster => cluster.HighestRiskScore)
            .ThenBy(static cluster => cluster.Label, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static TyposquattingInfrastructureCluster BuildCluster(
        IReadOnlyList<TyposquattingCandidate> component,
        IReadOnlyDictionary<TyposquattingCandidate, CandidateInfrastructureSignals> signalMap,
        int index)
    {
        var registrars = component
            .SelectMany(candidate => signalMap[candidate].Registrars)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var nameServers = component
            .SelectMany(candidate => signalMap[candidate].NameServers)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var asns = component
            .SelectMany(candidate => signalMap[candidate].Asns)
            .Distinct()
            .OrderBy(static value => value)
            .ToArray();

        var sharedSignals = BuildSharedSignalSummary(component, signalMap);
        var label = BuildLabel(index, registrars, nameServers, asns);
        return new TyposquattingInfrastructureCluster
        {
            Id = "cluster-" + index.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Label = label,
            Domains = component
                .Select(static candidate => candidate.Domain)
                .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            SharedSignals = sharedSignals,
            Registrars = registrars,
            NameServers = nameServers,
            Asns = asns,
            HighestRiskScore = component.Max(static candidate => candidate.RiskScore),
            ThreatListedCount = component.Count(static candidate => candidate.Enrichment?.ThreatIntel?.Listings?.Any(listing => listing.IsListed) == true)
        };
    }

    private static CandidateInfrastructureSignals BuildSignals(TyposquattingCandidate candidate)
    {
        var registrars = string.IsNullOrWhiteSpace(candidate.Enrichment?.Whois?.Registrar)
            ? Array.Empty<string>()
            : new[] { candidate.Enrichment!.Whois!.Registrar!.Trim() };
        var nameServers = candidate.NsRecords
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var asns = candidate.Enrichment?.IpEnrichment?.AsnCounts?.Keys
            .Distinct()
            .OrderBy(static value => value)
            .ToArray() ?? Array.Empty<int>();

        var tokens = new List<string>();
        foreach (var registrar in registrars)
        {
            tokens.Add("registrar:" + registrar);
        }

        foreach (var nameServer in nameServers)
        {
            tokens.Add("ns:" + nameServer);
        }

        foreach (var asn in asns)
        {
            tokens.Add("asn:" + asn.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        return new CandidateInfrastructureSignals
        {
            Registrars = registrars,
            NameServers = nameServers,
            Asns = asns,
            Tokens = tokens
        };
    }

    private static IReadOnlyList<string> BuildSharedSignalSummary(
        IReadOnlyList<TyposquattingCandidate> component,
        IReadOnlyDictionary<TyposquattingCandidate, CandidateInfrastructureSignals> signalMap)
    {
        var shared = new List<string>();
        var registrarCounts = component
            .SelectMany(candidate => signalMap[candidate].Registrars)
            .GroupBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .Where(static group => group.Count() > 1)
            .OrderByDescending(static group => group.Count())
            .ThenBy(static group => group.Key, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var nsCounts = component
            .SelectMany(candidate => signalMap[candidate].NameServers)
            .GroupBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .Where(static group => group.Count() > 1)
            .OrderByDescending(static group => group.Count())
            .ThenBy(static group => group.Key, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var asnCounts = component
            .SelectMany(candidate => signalMap[candidate].Asns)
            .GroupBy(static value => value)
            .Where(static group => group.Count() > 1)
            .OrderByDescending(static group => group.Count())
            .ThenBy(static group => group.Key)
            .ToArray();

        if (registrarCounts.Length > 0)
        {
            shared.Add("shared registrar");
        }

        if (nsCounts.Length > 0)
        {
            shared.Add("shared authoritative name servers");
        }

        if (asnCounts.Length > 0)
        {
            shared.Add("shared ASN infrastructure");
        }

        if (shared.Count == 0)
        {
            shared.Add("shared external infrastructure");
        }

        return shared;
    }

    private static string BuildLabel(int index, IReadOnlyList<string> registrars, IReadOnlyList<string> nameServers, IReadOnlyList<int> asns)
    {
        if (registrars.Count > 0)
        {
            return "Cluster " + index.ToString(System.Globalization.CultureInfo.InvariantCulture) + " - " + registrars[0];
        }

        if (nameServers.Count > 0)
        {
            return "Cluster " + index.ToString(System.Globalization.CultureInfo.InvariantCulture) + " - " + nameServers[0];
        }

        if (asns.Count > 0)
        {
            return "Cluster " + index.ToString(System.Globalization.CultureInfo.InvariantCulture) + " - AS" + asns[0].ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        return "Cluster " + index.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private sealed class CandidateInfrastructureSignals
    {
        public IReadOnlyList<string> Registrars { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> NameServers { get; init; } = Array.Empty<string>();
        public IReadOnlyList<int> Asns { get; init; } = Array.Empty<int>();
        public IReadOnlyList<string> Tokens { get; init; } = Array.Empty<string>();
    }

    private sealed class ReferenceEqualityComparer<T> : IEqualityComparer<T>
        where T : class
    {
        public static ReferenceEqualityComparer<T> Instance { get; } = new();

        public bool Equals(T? x, T? y)
        {
            return ReferenceEquals(x, y);
        }

        public int GetHashCode(T obj)
        {
            return System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(obj);
        }
    }
}
