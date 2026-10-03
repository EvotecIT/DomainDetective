using DnsClientX;
using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>The shared RFC 9989 policy and organizational-domain discovery owner.</summary>
internal sealed class DmarcPolicyDiscovery {
    private readonly Func<string, CancellationToken, Task<DnsAnswer[]>> _query;
    private readonly Dictionary<string, Entry?> _cache = new(StringComparer.OrdinalIgnoreCase);

    internal DmarcPolicyDiscovery(Func<string, CancellationToken, Task<DnsAnswer[]>> query) => _query = query;

    internal async Task<Result> DiscoverAsync(string domain, CancellationToken token) {
        domain = Normalize(domain);
        Entry? exact = await QueryAsync(domain, token).ConfigureAwait(false);
        if (exact?.SyntaxValid == true) return CreateResult(exact, exact.Psd == "n" ? domain : null);
        var entries = await WalkAsync(domain, token, startEntry: null, exactQueried: true).ConfigureAwait(false);
        string organizational = SelectOrganizationalDomain(domain, entries);
        Entry? policy = entries.FirstOrDefault(entry => entry.Domain == organizational)
            ?? entries.FirstOrDefault(entry => entry.Psd == "y");
        return CreateResult(policy ?? exact ?? _cache.Values.FirstOrDefault(entry => entry != null), organizational);
    }

    internal async Task<string> FindOrganizationalDomainAsync(string domain, CancellationToken token) {
        domain = Normalize(domain);
        return SelectOrganizationalDomain(domain,
            await WalkAsync(domain, token, await QueryAsync(domain, token).ConfigureAwait(false), exactQueried: true).ConfigureAwait(false));
    }

    private async Task<List<Entry>> WalkAsync(string domain, CancellationToken token, Entry? startEntry, bool exactQueried) {
        var entries = new List<Entry>();
        if (startEntry?.Applicable == true) entries.Add(startEntry);
        if (startEntry?.Applicable == true && (startEntry.Psd == "n" || startEntry.Psd == "y")) return entries;
        string current = domain;
        int queries = exactQueried ? 1 : 0;
        while (queries < 8) {
            var labels = current.Split('.');
            if (labels.Length <= 1) break;
            // The initial long-name query plus the seven rightmost suffixes is the complete bounded walk.
            current = string.Join(".", labels.Skip(labels.Length >= 8 ? labels.Length - 7 : 1));
            Entry? entry = await QueryAsync(current, token).ConfigureAwait(false);
            queries++;
            if (entry?.Applicable != true) continue;
            entries.Add(entry);
            if (entry.Psd == "n" || entry.Psd == "y") break;
        }
        return entries;
    }

    private async Task<Entry?> QueryAsync(string domain, CancellationToken token) {
        token.ThrowIfCancellationRequested();
        if (_cache.TryGetValue(domain, out var cached)) return cached;
        var answers = await _query("_dmarc." + domain, token).ConfigureAwait(false);
        var records = answers.Where(answer => answer.Type == DnsRecordType.TXT
            && DmarcAnalysis.IsDmarcPolicyRecord(answer.TxtConcatenatedData)).ToArray();
        var tags = new Dictionary<string, string>(StringComparer.Ordinal);
        bool syntaxValid = records.Length == 1 && DmarcPolicyTags.TryRead(records[0].TxtConcatenatedData, out tags);
        Entry? entry = records.Length > 0 ? new Entry(domain, answers, tags, syntaxValid) : null;
        _cache[domain] = entry;
        return entry;
    }

    private static string SelectOrganizationalDomain(string start, List<Entry> entries) {
        foreach (Entry entry in entries) {
            if (entry.Psd == "n") return entry.Domain;
            if (entry.Psd == "y" && entry.Domain != start) {
                string[] labels = start.Split('.');
                int psdLabels = entry.Domain.Split('.').Length;
                return string.Join(".", labels.Skip(labels.Length - psdLabels - 1));
            }
        }
        return entries.LastOrDefault()?.Domain ?? start;
    }

    private static string Normalize(string name) => DomainHelper.ValidateIdn(name).ToLowerInvariant();

    private Result CreateResult(Entry? policy, string? organization) => new(policy, organization,
        _cache.Values.Where(entry => entry != null && entry != policy && !entry.SyntaxValid).Cast<Entry>().ToArray());

    internal sealed class Entry {
        internal Entry(string domain, DnsAnswer[] answers, Dictionary<string, string> tags, bool syntaxValid) {
            Domain = domain; Answers = answers; Tags = tags; SyntaxValid = syntaxValid;
        }
        internal string Domain { get; }
        internal DnsAnswer[] Answers { get; }
        internal Dictionary<string, string> Tags { get; }
        internal bool SyntaxValid { get; }
        internal bool Applicable => SyntaxValid && (DmarcPolicyTags.HasValidPolicy(Tags) || DmarcPolicyTags.HasReportingFallback(Tags));
        internal string? Psd => Tags.TryGetValue("psd", out var value) ? value : null;
    }

    internal sealed class Result {
        internal Result(Entry? policy, string? organizationalDomain, Entry[] rejected) { Policy = policy; OrganizationalDomain = organizationalDomain; Rejected = rejected; }
        internal Entry? Policy { get; }
        internal string? OrganizationalDomain { get; }
        internal Entry[] Rejected { get; }
    }
}
