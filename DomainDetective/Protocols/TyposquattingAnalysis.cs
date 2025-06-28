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
    
    /// <summary>All generated variants.</summary>
    public List<string> Variants { get; private set; } = new();
    /// <summary>Variants that resolve in DNS.</summary>
    public List<string> ActiveDomains { get; private set; } = new();

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type)
    {
        if (QueryDnsOverride != null)
        {
            return await QueryDnsOverride(name, type);
        }

        return await DnsConfiguration.QueryDNS(name, type);
    }

    private static IEnumerable<string> BuildVariants(string domainName)
    {
        var idx = domainName.IndexOf('.');
        var label = idx > 0 ? domainName[..idx] : domainName;
        var suffix = idx > 0 ? domainName[idx..] : string.Empty;
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // missing letter
        for (int i = 0; i < label.Length; i++)
        {
            var v = label.Remove(i, 1);
            if (v.Length > 0)
            {
                set.Add(v + suffix);
            }
        }

        // extra letter
        for (int i = 0; i < label.Length; i++)
        {
            var v = label.Insert(i, label[i].ToString());
            set.Add(v + suffix);
        }

        // homoglyphs
        for (int i = 0; i < label.Length; i++)
        {
            if (_homoglyphs.TryGetValue(char.ToLowerInvariant(label[i]), out var subs))
            {
                foreach (var sub in subs)
                {
                    var v = label.Substring(0, i) + sub + label.Substring(i + 1);
                    set.Add(v + suffix);
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
        Variants = BuildVariants(domainName).ToList();
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
