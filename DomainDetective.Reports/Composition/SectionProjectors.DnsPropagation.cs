using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

public static partial class SectionProjectors
{
    // Discovery: DNS Propagation (multi-resolver visibility)
    public sealed class DnsPropagationSection
    {
        public sealed class ServerRow
        {
            public string ServerIp { get; set; } = string.Empty;
            public string HostName { get; set; } = string.Empty;
            public string Country { get; set; } = string.Empty;
            public string Location { get; set; } = string.Empty;
            public string Asn { get; set; } = string.Empty;
            public string AsnName { get; set; } = string.Empty;
            public bool Success { get; set; }
            public int DurationMs { get; set; }
            public string AnswerSetKey { get; set; } = string.Empty;
            public bool IsMajority { get; set; }
            public string Answers { get; set; } = string.Empty;
            public string Error { get; set; } = string.Empty;
        }

        public sealed class AnswerSetRow
        {
            public string AnswerSetKey { get; set; } = string.Empty;
            public int Servers { get; set; }
            public int Countries { get; set; }
            public int Locations { get; set; }
            public string SampleServers { get; set; } = string.Empty;
        }

        public sealed class CountryRow
        {
            public string Country { get; set; } = string.Empty;
            public int Servers { get; set; }
            public int Success { get; set; }
            public int Errors { get; set; }
            public int Majority { get; set; }
            public int NonMajority { get; set; }
        }

        public string Status { get; set; } = "-";
        public DnsRecordType RecordType { get; set; }
        public bool QuerySucceeded { get; set; }
        public int ServerCount { get; set; }
        public int SuccessCount { get; set; }
        public int ErrorCount { get; set; }
        public int DistinctAnswerSets { get; set; }
        public string? MajorityAnswerSet { get; set; }
        public TimeSpan? MinDuration { get; set; }
        public TimeSpan? MaxDuration { get; set; }
        public TimeSpan? AvgDuration { get; set; }
        public bool ResultsCapped { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<AnswerSetRow> AnswerSets { get; } = new();
        public List<CountryRow> Countries { get; } = new();
        public List<ServerRow> Servers { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    public static DnsPropagationSection? BuildDnsPropagation(DomainDetective.Views.DnsPropagationInfo dp)
    {
        if (dp == null) return null;

        var s = new DnsPropagationSection
        {
            Status = dp.Status ?? "-",
            RecordType = dp.RecordType,
            QuerySucceeded = dp.QuerySucceeded,
            ServerCount = dp.ServerCount,
            SuccessCount = dp.ServerSuccessCount,
            ErrorCount = dp.ServerErrorCount,
            DistinctAnswerSets = dp.DistinctAnswerSets,
            MajorityAnswerSet = dp.MajorityAnswerSet,
            MinDuration = dp.MinDuration,
            MaxDuration = dp.MaxDuration,
            AvgDuration = dp.AvgDuration,
            ResultsCapped = dp.ResultsCapped
        };

        s.Summary.Add(("Status", s.Status));
        s.Summary.Add(("Record", s.RecordType.ToString()));
        s.Summary.Add(("Query OK", s.QuerySucceeded ? "Yes" : "No"));
        s.Summary.Add(("Servers", s.ServerCount.ToString()));
        s.Summary.Add(("OK", s.SuccessCount.ToString()));
        s.Summary.Add(("Errors", s.ErrorCount.ToString()));
        s.Summary.Add(("Distinct Answer Sets", s.DistinctAnswerSets.ToString()));
        if (!string.IsNullOrWhiteSpace(s.MajorityAnswerSet))
        {
            s.Summary.Add(("Majority Set", s.MajorityAnswerSet!));
        }
        if (s.MinDuration.HasValue) s.Summary.Add(("Min RTT", $"{s.MinDuration.Value.TotalMilliseconds:0} ms"));
        if (s.AvgDuration.HasValue) s.Summary.Add(("Avg RTT", $"{s.AvgDuration.Value.TotalMilliseconds:0} ms"));
        if (s.MaxDuration.HasValue) s.Summary.Add(("Max RTT", $"{s.MaxDuration.Value.TotalMilliseconds:0} ms"));
        s.Summary.Add(("Capped", s.ResultsCapped ? "Yes" : "No"));

        // Group successful answers into normalized answer sets
        var results = dp.Results ?? Array.Empty<DomainDetective.DnsPropagationResult>();
        var groups = new Dictionary<string, List<DomainDetective.DnsComparisonEntry>>(StringComparer.OrdinalIgnoreCase);
        try { groups = DomainDetective.DnsPropagationAnalysis.CompareResults(results); } catch { }

        var answerKeyByServerIp = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in groups)
        {
            foreach (var e in kv.Value ?? new List<DomainDetective.DnsComparisonEntry>())
            {
                if (e != null && !string.IsNullOrWhiteSpace(e.IPAddress) && !answerKeyByServerIp.ContainsKey(e.IPAddress))
                {
                    answerKeyByServerIp[e.IPAddress] = kv.Key;
                }
            }
        }

        foreach (var kv in groups.OrderByDescending(x => x.Value?.Count ?? 0).ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
        {
            var servers = kv.Value ?? new List<DomainDetective.DnsComparisonEntry>();
            var countries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var locations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in servers)
            {
                if (e == null) continue;
                if (e.Country.HasValue) countries.Add(DomainDetective.CountryIdExtensions.ToName(e.Country.Value));
                if (e.Location.HasValue) locations.Add(DomainDetective.LocationIdExtensions.ToName(e.Location.Value));
            }
            var ips = servers.Select(e => e?.IPAddress).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToList();
            s.AnswerSets.Add(new DnsPropagationSection.AnswerSetRow
            {
                AnswerSetKey = kv.Key,
                Servers = servers.Count,
                Countries = countries.Count,
                Locations = locations.Count,
                SampleServers = ips.Count > 0 ? string.Join(", ", ips) : "-"
            });
        }

        string JoinAnswers(IEnumerable<string>? records, int cap)
        {
            try
            {
                if (records == null) return "-";
                var list = records.Where(r => !string.IsNullOrWhiteSpace(r)).ToList();
                if (list.Count == 0) return "-";
                var take = list.Take(cap).ToList();
                var extra = list.Count - take.Count;
                return extra > 0 ? string.Join(", ", take) + $" (+{extra})" : string.Join(", ", take);
            }
            catch
            {
                return "-";
            }
        }

        foreach (var r in results)
        {
            if (r == null || r.Server == null) continue;
            var ip = r.Server.IPAddress?.ToString() ?? string.Empty;
            var key = (!string.IsNullOrWhiteSpace(ip) && answerKeyByServerIp.TryGetValue(ip, out var k)) ? k : string.Empty;
            var isMajority = !string.IsNullOrWhiteSpace(key) && !string.IsNullOrWhiteSpace(s.MajorityAnswerSet) && string.Equals(key, s.MajorityAnswerSet, StringComparison.OrdinalIgnoreCase);
            var country = r.Server.Country.HasValue ? DomainDetective.CountryIdExtensions.ToName(r.Server.Country.Value) : "-";
            var location = r.Server.Location.HasValue ? DomainDetective.LocationIdExtensions.ToName(r.Server.Location.Value) : "-";
            s.Servers.Add(new DnsPropagationSection.ServerRow
            {
                ServerIp = ip,
                HostName = string.IsNullOrWhiteSpace(r.Server.HostName) ? "-" : r.Server.HostName,
                Country = string.IsNullOrWhiteSpace(country) ? "-" : country,
                Location = string.IsNullOrWhiteSpace(location) ? "-" : location,
                Asn = string.IsNullOrWhiteSpace(r.Server.ASN) ? "-" : r.Server.ASN,
                AsnName = string.IsNullOrWhiteSpace(r.Server.ASNName) ? "-" : r.Server.ASNName,
                Success = r.Success,
                DurationMs = (int)Math.Round(r.Duration.TotalMilliseconds),
                AnswerSetKey = string.IsNullOrWhiteSpace(key) ? "-" : key,
                IsMajority = isMajority,
                Answers = JoinAnswers(r.Records, 5),
                Error = string.IsNullOrWhiteSpace(r.Error) ? "-" : r.Error
            });
        }

        foreach (var g in s.Servers
                     .GroupBy(r => r.Country ?? "-", StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(gr => gr.Count())
                     .ThenBy(gr => gr.Key, StringComparer.OrdinalIgnoreCase))
        {
            var total = g.Count();
            var ok = g.Count(x => x.Success);
            var err = total - ok;
            var maj = g.Count(x => x.Success && x.IsMajority);
            var nonMaj = g.Count(x => x.Success && !x.IsMajority);
            s.Countries.Add(new DnsPropagationSection.CountryRow
            {
                Country = string.IsNullOrWhiteSpace(g.Key) ? "-" : g.Key,
                Servers = total,
                Success = ok,
                Errors = err,
                Majority = maj,
                NonMajority = nonMaj
            });
        }

        foreach (var a in dp.Assessments ?? Array.Empty<DomainDetective.Assessment>())
        {
            if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        }
        foreach (var p in dp.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            var t = p?.Title ?? p?.Code;
            if (!string.IsNullOrWhiteSpace(t)) s.Positives.Add(t!);
        }
        foreach (var rr in dp.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(rr)) s.References.Add(rr);

        return s;
    }
}
