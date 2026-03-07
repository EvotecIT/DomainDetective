using System;
using System.Collections.Generic;
using System.Linq;



namespace DomainDetective.Reports;

public static partial class SectionProjectors
{
    public static SubdomainsSection? BuildSubdomains(DomainDetective.Views.SubdomainsInfo sub)
    {
        if (sub == null) return null;
        var s = new SubdomainsSection
        {
            Status = sub.Status ?? "-",
            QuerySucceeded = sub.QuerySucceeded,
            FailureReason = sub.FailureReason,
            SubdomainCount = sub.SubdomainCount,
            CertificateObservationCount = sub.CertificateObservationCount,
            DistinctIssuerCount = sub.DistinctIssuerCount,
            ResolutionReduced = sub.ResolutionReduced,
            ResultsCapped = sub.ResultsCapped
        };

        string range = "-";
        if (sub.FirstSeenUtc.HasValue || sub.LastSeenUtc.HasValue)
        {
            var a = sub.FirstSeenUtc?.ToString("yyyy-MM-dd") ?? "-";
            var b = sub.LastSeenUtc?.ToString("yyyy-MM-dd") ?? "-";
            range = a + " .. " + b;
        }

        s.Summary.Add(("Status", s.Status));
        s.Summary.Add(("Query OK", s.QuerySucceeded ? "Yes" : "No"));
        if (!string.IsNullOrWhiteSpace(s.FailureReason)) s.Summary.Add(("Failure", s.FailureReason!));
        s.Summary.Add(("Subdomains", s.SubdomainCount.ToString()));
        s.Summary.Add(("CT Rows", s.CertificateObservationCount.ToString()));
        s.Summary.Add(("CT Processing", s.ResultsCapped ? "Capped" : "OK"));
        s.Summary.Add(("Issuer Diversity", s.DistinctIssuerCount.ToString()));
        s.Summary.Add(("Seen (UTC)", range));
        s.Summary.Add(("DNS Verification", sub.Raw?.VerifyStillResolves == true ? (s.ResolutionReduced ? "Capped" : "Yes") : "No"));

        var rows = sub.Subdomains ?? Array.Empty<DomainDetective.SubdomainDiscoveryEntry>();
        int take = Math.Min(rows.Count, 200);
        for (int i = 0; i < take; i++)
        {
            var r = rows[i];
            s.Rows.Add(new SubdomainsSection.Row
            {
                Name = r.Name,
                FirstSeenUtc = r.FirstSeenUtc?.ToString("yyyy-MM-dd") ?? "-",
                LastSeenUtc = r.LastSeenUtc?.ToString("yyyy-MM-dd") ?? "-",
                Resolution = r.ResolutionStatus.ToString()
            });
        }

        foreach (var a in sub.Assessments ?? Array.Empty<DomainDetective.Assessment>())
        {
            if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        }
        foreach (var p in sub.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            var tt = p?.Title ?? p?.Code;
            if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!);
        }
        foreach (var rr in sub.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(rr)) s.References.Add(rr);

        return s;
    }

    public static DnsInventorySection? BuildDnsInventory(DomainDetective.Views.DnsInventoryInfo inv)
    {
        if (inv == null) return null;

        var s = new DnsInventorySection
        {
            Status = inv.Status ?? "-",
            QuerySucceeded = inv.QuerySucceeded,
            FailureReason = inv.FailureReason,
            RecordTypesQueried = inv.RecordTypesQueried,
            RecordTypesFailed = inv.RecordTypesFailed,
            TotalRecords = inv.TotalRecords,
            IncludeAuthorities = inv.IncludeAuthorities,
            IncludeAdditional = inv.IncludeAdditional
        };

        s.Summary.Add(("Status", s.Status));
        s.Summary.Add(("Query OK", s.QuerySucceeded ? "Yes" : "No"));
        if (!string.IsNullOrWhiteSpace(s.FailureReason)) s.Summary.Add(("Failure", s.FailureReason!));
        s.Summary.Add(("Types Queried", s.RecordTypesQueried.ToString()));
        s.Summary.Add(("Types Failed", s.RecordTypesFailed.ToString()));
        s.Summary.Add(("Records", s.TotalRecords.ToString()));
        s.Summary.Add(("DNS Provider", inv.Provider != DomainDetective.Providers.Dns.DnsProvider.Unknown ? inv.Provider.ToString() : "-"));
        s.Summary.Add(("Mail Provider", inv.MailProvider != DomainDetective.Providers.Email.MailProviderKind.Unknown ? inv.MailProvider.ToString() : "-"));
        s.Summary.Add(("Apex CNAME Provider", inv.CnameTargetProvider != DomainDetective.Providers.Dns.DnsCnameTargetProvider.Unknown ? inv.CnameTargetProvider.ToString() : "-"));
        s.Summary.Add(("Apex CNAME Flags", inv.CnameTargetFlags != DomainDetective.Providers.Dns.DnsCnameTargetFlags.None ? inv.CnameTargetFlags.ToString() : "-"));
        s.Summary.Add(("TXT Signals", inv.TxtSignals != DomainDetective.Providers.Dns.DnsTxtSignals.None ? inv.TxtSignals.ToString() : "-"));
        s.Summary.Add(("CAA Issuers", inv.CaaIssuers != DomainDetective.Providers.Dns.DnsCaaIssuers.None ? inv.CaaIssuers.ToString() : "-"));
        s.Summary.Add(("Authority Included", s.IncludeAuthorities ? "Yes" : "No"));
        s.Summary.Add(("Additional Included", s.IncludeAdditional ? "Yes" : "No"));

        try
        {
            const int maxRows = 400;
            foreach (var q in inv.Queries)
            {
                foreach (var r in q.Records)
                {
                    if (s.Rows.Count >= maxRows) break;
                    s.Rows.Add(new DnsInventorySection.Row
                    {
                        QueryType = q.RecordType,
                        Section = r.Section,
                        RecordType = r.Type,
                        Name = r.Name,
                        Ttl = r.Ttl,
                        Data = r.Data
                    });
                }
                if (s.Rows.Count >= maxRows) break;
            }
        }
        catch
        {
        }

        foreach (var a in inv.Assessments ?? Array.Empty<DomainDetective.Assessment>())
        {
            if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        }
        foreach (var p in inv.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            var tt = p?.Title ?? p?.Code;
            if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!);
        }
        foreach (var rr in inv.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(rr)) s.References.Add(rr);

        return s;
    }

    public static DnsTraceSection? BuildDnsTrace(DomainDetective.Views.DnsTraceInfo tr)
    {
        if (tr == null) return null;

        var s = new DnsTraceSection
        {
            Status = tr.Status ?? "-",
            TraceSucceeded = tr.TraceSucceeded,
            FailureReason = tr.FailureReason,
            TraceQueries = tr.TraceQueries,
            TraceQueriesFailed = tr.TraceQueriesFailed,
            TotalSteps = tr.TotalSteps
        };

        s.Summary.Add(("Status", s.Status));
        s.Summary.Add(("Trace OK", s.TraceSucceeded ? "Yes" : "No"));
        if (!string.IsNullOrWhiteSpace(s.FailureReason)) s.Summary.Add(("Failure", s.FailureReason!));
        s.Summary.Add(("Queries", s.TraceQueries.ToString()));
        s.Summary.Add(("Queries Failed", s.TraceQueriesFailed.ToString()));
        s.Summary.Add(("Steps", s.TotalSteps.ToString()));
        try
        {
            var raw = tr.Raw;
            if (raw != null)
            {
                s.Summary.Add(("IPv6 Roots", raw.IncludeIpv6RootServers ? "Yes" : "No"));
                s.Summary.Add(("Max Depth", raw.MaxDepth.ToString()));
                s.Summary.Add(("Max Steps", raw.MaxTotalSteps.ToString()));
            }
        }
        catch { }

        string FormatList(IReadOnlyList<string>? list, int take)
        {
            if (list == null || list.Count == 0) return "-";
            var items = list.Where(x => !string.IsNullOrWhiteSpace(x)).Take(take).ToList();
            if (items.Count == 0) return "-";
            var extra = list.Count - items.Count;
            return extra > 0 ? string.Join(", ", items) + $" (+{extra})" : string.Join(", ", items);
        }

        try
        {
            const int maxRows = 400;
            foreach (var q in tr.Queries ?? Array.Empty<DomainDetective.DnsTraceQuery>())
            {
                foreach (var st in q.Steps)
                {
                    if (s.Rows.Count >= maxRows) break;
                    s.Rows.Add(new DnsTraceSection.Row
                    {
                        TraceType = q.RecordType,
                        Kind = st.Kind,
                        Depth = st.Depth,
                        Server = st.Server,
                        Name = st.QueryName,
                        RecordType = st.RecordType,
                        ResponseStatus = st.ResponseStatus,
                        Answers = st.AnswerCount,
                        Authorities = st.AuthorityCount,
                        Additional = st.AdditionalCount,
                        RttMs = st.RoundTripTimeMs,
                        CnameTarget = string.IsNullOrWhiteSpace(st.CnameTarget) ? "-" : st.CnameTarget!,
                        NextServers = FormatList(st.NextServers, 3)
                    });
                }
                if (s.Rows.Count >= maxRows) break;
            }
        }
        catch { }

        foreach (var a in tr.Assessments ?? Array.Empty<DomainDetective.Assessment>())
        {
            if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        }
        foreach (var p in tr.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            var tt = p?.Title ?? p?.Code;
            if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!);
        }
        foreach (var rr in tr.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(rr)) s.References.Add(rr);

        return s;
    }
}
