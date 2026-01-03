using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

public static partial class SectionProjectors
{
    // Discovery/Infra: IP Enrichment
    public sealed class IpEnrichmentSection
    {
        public sealed class Row
        {
            public string IpAddress { get; set; } = string.Empty;
            public DomainDetective.IpAddressFamilyKind Family { get; set; }
            public DomainDetective.IpEnrichmentSourceKind SourceKind { get; set; }
            public string SourceHost { get; set; } = string.Empty;
            public string Ptr { get; set; } = string.Empty;
            public int? Asn { get; set; }
            public string AsName { get; set; } = string.Empty;
            public string Cidr { get; set; } = string.Empty;
            public string Country { get; set; } = string.Empty;
            public string Region { get; set; } = string.Empty;
        }

        public string Status { get; set; } = "-";
        public bool QuerySucceeded { get; set; }
        public bool ResultsCapped { get; set; }
        public string? FailureReason { get; set; }
        public int UniqueIps { get; set; }
        public int RowsCount { get; set; }
        public int DistinctAsns { get; set; }
        public int DistinctCountries { get; set; }
        public string TopAsns { get; set; } = "-";
        public string TopCountries { get; set; } = "-";
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<Row> Rows { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    public static IpEnrichmentSection? BuildIpEnrichment(DomainDetective.Views.IpEnrichmentInfo ip)
    {
        if (ip == null) return null;

        string TopAsnString()
        {
            try
            {
                var pairs = (ip.AsnCounts ?? new Dictionary<int, int>())
                    .OrderByDescending(kv => kv.Value)
                    .ThenBy(kv => kv.Key)
                    .Take(5)
                    .Select(kv => $"AS{kv.Key} ({kv.Value})")
                    .ToList();
                return pairs.Count > 0 ? string.Join(", ", pairs) : "-";
            }
            catch
            {
                return "-";
            }
        }

        string TopCountryString()
        {
            try
            {
                var pairs = (ip.CountryCounts ?? new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase))
                    .OrderByDescending(kv => kv.Value)
                    .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                    .Take(5)
                    .Select(kv => $"{kv.Key} ({kv.Value})")
                    .ToList();
                return pairs.Count > 0 ? string.Join(", ", pairs) : "-";
            }
            catch
            {
                return "-";
            }
        }

        var s = new IpEnrichmentSection
        {
            Status = ip.Status ?? "-",
            QuerySucceeded = ip.QuerySucceeded,
            ResultsCapped = ip.ResultsCapped,
            FailureReason = ip.FailureReason,
            UniqueIps = ip.UniqueIpCount,
            RowsCount = ip.RowCount,
            DistinctAsns = ip.DistinctAsnCount,
            DistinctCountries = ip.DistinctCountryCount,
            TopAsns = TopAsnString(),
            TopCountries = TopCountryString()
        };

        s.Summary.Add(("Status", s.Status));
        s.Summary.Add(("Query OK", s.QuerySucceeded ? "Yes" : "No"));
        if (!string.IsNullOrWhiteSpace(s.FailureReason)) s.Summary.Add(("Failure", s.FailureReason!));
        s.Summary.Add(("Unique IPs", s.UniqueIps.ToString()));
        s.Summary.Add(("Rows", s.RowsCount.ToString()));
        s.Summary.Add(("ASNs", s.DistinctAsns.ToString()));
        s.Summary.Add(("Countries", s.DistinctCountries.ToString()));
        s.Summary.Add(("Top ASNs", s.TopAsns));
        s.Summary.Add(("Top Countries", s.TopCountries));
        s.Summary.Add(("Capped", s.ResultsCapped ? "Yes" : "No"));

        try
        {
            var rows = ip.Rows ?? Array.Empty<DomainDetective.IpEnrichmentRow>();
            int take = Math.Min(rows.Count, 500);
            for (int i = 0; i < take; i++)
            {
                var r = rows[i];
                s.Rows.Add(new IpEnrichmentSection.Row
                {
                    IpAddress = r.IpAddress,
                    Family = r.AddressFamily,
                    SourceKind = r.SourceKind,
                    SourceHost = r.SourceHost,
                    Ptr = r.Ptr,
                    Asn = r.Asn,
                    AsName = r.AsName,
                    Cidr = r.Cidr,
                    Country = r.Country,
                    Region = r.Region
                });
            }
        }
        catch
        {
        }

        foreach (var a in ip.Assessments ?? Array.Empty<DomainDetective.Assessment>())
        {
            if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        }
        foreach (var p in ip.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            var t = p?.Title ?? p?.Code;
            if (!string.IsNullOrWhiteSpace(t)) s.Positives.Add(t!);
        }
        foreach (var rr in ip.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(rr)) s.References.Add(rr);

        return s;
    }
}

