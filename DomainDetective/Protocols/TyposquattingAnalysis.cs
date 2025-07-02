using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Generates common typosquatting variants and checks if they resolve.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class TyposquattingAnalysis
{
    private static readonly Dictionary<char, char[]> _homoglyphs = new()
    {
        ['0'] = new[] { 'o' },
        ['o'] = new[] { '0' },
        ['1'] = new[] { 'l', 'i' },
        ['l'] = new[] { '1', 'i' },
        ['i'] = new[] { '1', 'l' },
        ['5'] = new[] { 's' },
        ['s'] = new[] { '5' },
        ['a'] = new[] { '@' },
        ['@'] = new[] { 'a' },
        ['e'] = new[] { '3' },
        ['3'] = new[] { 'e' }
    };

    /// <summary>DNS configuration for lookups.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();
    /// <summary>Override DNS query logic.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    internal PublicSuffixList PublicSuffixList { get; set; } = new();
    
    /// <summary>All generated variants.</summary>
    public List<string> Variants { get; private set; } = new();
    /// <summary>Variants that resolve in DNS.</summary>
    public List<string> ActiveDomains { get; private set; } = new();

    /// <summary>Maximum allowed Levenshtein distance when generating variants.</summary>
    public int LevenshteinThreshold { get; set; } = 1;

    /// <summary>Flag to detect homoglyph characters in input.</summary>
    public bool DetectHomoglyphs { get; set; } = true;

    /// <summary>Indicates whether input contains homoglyph characters.</summary>
    public bool ContainsHomoglyphs { get; private set; }

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type)
    {
        if (QueryDnsOverride != null)
        {
            return await QueryDnsOverride(name, type);
        }

        return await DnsConfiguration.QueryDNS(name, type);
    }

    private static (string Prefix, string Label, string Suffix) SplitDomain(string domainName, PublicSuffixList list)
    {
        var clean = domainName.Trim('.');
        var parts = clean.Split('.');
        if (parts.Length == 1)
        {
            return (string.Empty, clean, string.Empty);
        }

        for (int i = 0; i < parts.Length; i++)
        {
            var candidate = string.Join(".", parts.Skip(i));
            if (list.IsPublicSuffix(candidate))
            {
                var labelIndex = i - 1;
                if (labelIndex >= 0)
                {
                    var prefix = string.Join(".", parts.Take(labelIndex));
                    if (prefix.Length > 0)
                    {
                        prefix += ".";
                    }
                    var suffix = "." + string.Join(".", parts.Skip(labelIndex + 1));
                    return (prefix, parts[labelIndex], suffix);
                }
            }
        }

        var idx = clean.IndexOf('.');
        var pre = string.Empty;
        var lbl = clean;
        var sfx = string.Empty;
        if (idx > 0)
        {
            pre = string.Empty;
            lbl = clean.Substring(0, idx);
            sfx = clean.Substring(idx);
        }

        return (pre, lbl, sfx);
    }

    private static IEnumerable<string> BuildVariants(string domainName, PublicSuffixList list, int threshold)
    {
        var (prefix, label, suffix) = SplitDomain(domainName, list);
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // missing letter
        for (int i = 0; i < label.Length; i++)
        {
            var v = label.Remove(i, 1);
            if (v.Length > 0)
            {
                var candidate = prefix + v + suffix;
                if (StringAlgorithms.LevenshteinDistance(domainName, candidate) <= threshold)
                {
                    set.Add(candidate);
                }
            }
        }

        // extra letter
        for (int i = 0; i < label.Length; i++)
        {
            var v = label.Insert(i, label[i].ToString());
            var candidate = prefix + v + suffix;
            if (StringAlgorithms.LevenshteinDistance(domainName, candidate) <= threshold)
            {
                set.Add(candidate);
            }
        }

        // homoglyphs
        for (int i = 0; i < label.Length; i++)
        {
            if (_homoglyphs.TryGetValue(char.ToLowerInvariant(label[i]), out var subs))
            {
                foreach (var sub in subs)
                {
                    var v = label.Substring(0, i) + sub + label.Substring(i + 1);
                    var candidate = prefix + v + suffix;
                    if (StringAlgorithms.LevenshteinDistance(domainName, candidate) <= threshold)
                    {
                        set.Add(candidate);
                    }
                }
            }
        }

        return set;
    }

    /// <summary>
    /// Generates variants of <paramref name="domainName"/> and checks if they resolve.
    /// </summary>
    public async Task Analyze(string domainName, InternalLogger logger, CancellationToken ct = default)
    {
        var list = PublicSuffixList ?? new PublicSuffixList();
        ContainsHomoglyphs = DetectHomoglyphs && StringAlgorithms.ContainsHomoglyphs(domainName);
        if (ContainsHomoglyphs)
        {
            logger?.WriteWarning("Domain contains homoglyph characters: {0}", domainName);
        }

        Variants = BuildVariants(domainName, list, LevenshteinThreshold).ToList();
        ActiveDomains = new List<string>();

        foreach (var variant in Variants)
        {
            ct.ThrowIfCancellationRequested();
            var a = await QueryDns(variant, DnsRecordType.A);
            var aaaa = await QueryDns(variant, DnsRecordType.AAAA);
            if ((a?.Length > 0) || (aaaa?.Length > 0))
            {
                ActiveDomains.Add(variant);
                logger?.WriteWarning("Potential typosquat detected: {0}", variant);
            }
        }
    }
}
