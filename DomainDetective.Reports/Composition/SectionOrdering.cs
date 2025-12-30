using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Reports;

/// <summary>
/// Shared helpers for section ordering, normalization, and input-driven sequencing.
/// </summary>
public static class SectionOrdering
{
    private static readonly string[] Canonical = new[]
    {
        "MX",
        "Mail Transport Posture",
        "SPF",
        "DKIM",
        "DMARC",
        "DMARC Aggregate",
        "ARC",
        "BIMI",
        "DNSBL",
        "RPKI",
        "Registration",
        "NS",
        "SOA",
        "TTL",
        "ZoneTransfer",
        "Wildcard",
        "CAA",
        "Classification",
        "MTA-STS",
        "TLS-RPT",
        "TLS-RPT Reports",
        "MAILTLS",
        "DNSSEC",
        "DANE"
    };

    /// <summary>Canonical ordering for composition sections.</summary>
    public static IReadOnlyList<string> CanonicalSections => Canonical;

    /// <summary>Maps a health check to a canonical section key.</summary>
    public static string? SectionKeyFor(HealthCheckType h) => h switch
    {
        HealthCheckType.MX => "MX",
        HealthCheckType.SPF => "SPF",
        HealthCheckType.DKIM => "DKIM",
        HealthCheckType.DMARC => "DMARC",
        HealthCheckType.ARC => "ARC",
        HealthCheckType.BIMI => "BIMI",
        HealthCheckType.DNSBL => "DNSBL",
        HealthCheckType.RPKI => "RPKI",
        HealthCheckType.NS => "NS",
        HealthCheckType.SOA => "SOA",
        HealthCheckType.TTL => "TTL",
        HealthCheckType.ZONETRANSFER => "ZoneTransfer",
        HealthCheckType.WILDCARDDNS => "Wildcard",
        HealthCheckType.CAA => "CAA",
        HealthCheckType.MAILCLASSIFICATION => "Classification",
        HealthCheckType.MTASTS => "MTA-STS",
        HealthCheckType.TLSRPT => "TLS-RPT",
        HealthCheckType.DNSSEC => "DNSSEC",
        HealthCheckType.DANE => "DANE",
        HealthCheckType.SMTPTLS => "MAILTLS",
        HealthCheckType.STARTTLS => "MAILTLS",
        HealthCheckType.IMAPTLS => "MAILTLS",
        HealthCheckType.POP3TLS => "MAILTLS",
        _ => null
    };

    /// <summary>Normalizes user-supplied section names to canonical keys.</summary>
    public static string NormalizeSection(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return s;
        var t = s.Trim();
        var u = t.ToUpperInvariant().Replace(" ", string.Empty).Replace("-", string.Empty);
        return u switch
        {
            "DMARCAGGREGATE" => "DMARC Aggregate",
            "DMARCAGG" => "DMARC Aggregate",
            "TLSRPT" => "TLS-RPT",
            "TLSRPTREPORTS" => "TLS-RPT Reports",
            "MAILTRANSPORTPOSTURE" => "Mail Transport Posture",
            "MAILTRANSPORT" => "Mail Transport Posture",
            "REGISTRATION" => "Registration",
            "WHOIS" => "Registration",
            "RDAP" => "Registration",
            "MTASTS" => "MTA-STS",
            "ZONEXFR" => "ZoneTransfer",
            "ZONETRANSFER" => "ZoneTransfer",
            "WILDCARDDNS" => "Wildcard",
            "WILDCARD" => "Wildcard",
            "MAILCLASSIFICATION" => "Classification",
            "CLASSIFICATION" => "Classification",
            "MAILTLS" => "MAILTLS",
            "SMTPTLS" => "MAILTLS",
            "IMAPTLS" => "MAILTLS",
            "POP3TLS" => "MAILTLS",
            "STARTTLS" => "MAILTLS",
            "MX" => "MX",
            "SPF" => "SPF",
            "DKIM" => "DKIM",
            "DMARC" => "DMARC",
            "ARC" => "ARC",
            "BIMI" => "BIMI",
            "DNSBL" => "DNSBL",
            "RPKI" => "RPKI",
            "NS" => "NS",
            "SOA" => "SOA",
            "TTL" => "TTL",
            "CAA" => "CAA",
            "DNSSEC" => "DNSSEC",
            "DANE" => "DANE",
            _ => t
        };
    }

    /// <summary>Normalizes a list of section names to canonical keys.</summary>
    public static string[] NormalizeSectionList(IEnumerable<string> list)
    {
        return list?.Select(NormalizeSection)
                   .Where(x => !string.IsNullOrWhiteSpace(x))
                   .ToArray() ?? Array.Empty<string>();
    }

    /// <summary>
    /// Builds per-domain section order based on first appearance in the input stream.
    /// </summary>
    public static Dictionary<string, List<string>> DetermineSectionOrderByDomain(IReadOnlyList<object> items)
    {
        var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in items ?? Array.Empty<object>())
        {
            foreach (var it in EnumeratePossiblyNested(raw))
            {
                var subject = TryGetSubject(it);
                if (string.IsNullOrWhiteSpace(subject)) continue;
                var key = TryGetSectionKey(it);
                if (string.IsNullOrWhiteSpace(key)) continue;
                if (!map.TryGetValue(subject!, out var list))
                {
                    list = new List<string>();
                    map[subject!] = list;
                }
                if (!list.Contains(key!, StringComparer.OrdinalIgnoreCase)) list.Add(key!);
            }
        }
        return map;
    }

    /// <summary>Resolves final section order based on mode and available sections.</summary>
    public static List<string> ResolveOrder(SectionOrderMode mode, IEnumerable<string> present, IEnumerable<string>? inputOrder, IEnumerable<string>? customOrder)
    {
        var presentSet = new HashSet<string>(present ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        var ordered = new List<string>();

        void AddRange(IEnumerable<string>? order)
        {
            if (order == null) return;
            foreach (var s in NormalizeSectionList(order))
            {
                if (!presentSet.Contains(s)) continue;
                if (!ordered.Contains(s, StringComparer.OrdinalIgnoreCase)) ordered.Add(s);
            }
        }

        if (mode == SectionOrderMode.Custom) AddRange(customOrder);
        else if (mode == SectionOrderMode.Input) AddRange(inputOrder);
        AddRange(CanonicalSections);

        return ordered;
    }

    private static IEnumerable<object> EnumeratePossiblyNested(object? raw)
    {
        if (raw == null) yield break;
        if (raw is System.Collections.IEnumerable en && raw is not string)
        {
            foreach (var item in en)
            {
                if (item == null) continue;
                foreach (var inner in EnumeratePossiblyNested(item)) yield return inner;
            }
            yield break;
        }
        yield return raw;
    }

    private static string? TryGetSubject(object it)
    {
        try
        {
            var p = it.GetType().GetProperty("Subject");
            return p?.GetValue(it) as string;
        }
        catch { return null; }
    }

    private static string? TryGetSectionKey(object it)
    {
        try
        {
            var keyProp = it.GetType().GetProperty("SectionKey");
            if (keyProp != null && keyProp.GetValue(it) is string sectionKey && !string.IsNullOrWhiteSpace(sectionKey))
            {
                return NormalizeSection(sectionKey);
            }
            var p = it.GetType().GetProperty("Check");
            if (p == null) return null;
            if (p.GetValue(it) is not HealthCheckType h) return null;
            return SectionKeyFor(h);
        }
        catch { return null; }
    }
}
