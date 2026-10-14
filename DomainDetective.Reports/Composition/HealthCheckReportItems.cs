using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.TimeSeries.DmarcAggregate;
using DomainDetective.TimeSeries.Registration;
using DomainDetective.TimeSeries.TlsRpt;

namespace DomainDetective.Reports;

/// <summary>Projects completed health-check results and optional stored history into reusable report views.</summary>
public static class HealthCheckReportItems {
    /// <summary>Collects supported views without performing new network checks; conversion failures remain explicit.</summary>
    public static List<object> BuildItems(DomainHealthCheck healthCheck, string domain, string? storePath, bool includeDnsTrace, List<string> conversionErrors)
    {
        if (healthCheck == null) { throw new ArgumentNullException(nameof(healthCheck)); }
        var items = new List<object>();
        if (conversionErrors == null)
        {
            throw new ArgumentNullException(nameof(conversionErrors));
        }

        // Core DNS/mail policy checks from this run
        void TryAdd(string name, Func<object> factory)
        {
            try
            {
                items.Add(factory());
            }
            catch (Exception ex)
            {
                conversionErrors.Add($"{name}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        void TryAddRange<T>(string name, Func<IEnumerable<T>> factory)
        {
            try
            {
                var values = factory();
                if (values != null)
                {
                    items.AddRange(values.Cast<object>());
                }
            }
            catch (Exception ex)
            {
                conversionErrors.Add($"{name}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // A verified run converts every check it ran through the library's shared check-to-view conversion, so new
        // checks appear without a list to maintain. Without a run on record, fall back to the known analyses below.
        if (healthCheck.LastVerifiedChecks.Count > 0)
        {
            var checks = healthCheck.LastVerifiedChecks.Where(check => includeDnsTrace || check != HealthCheckType.DNSTRACE);
            items.AddRange(DomainDetective.Views.Converters.ConvertChecks(healthCheck, checks, conversionErrors));
        }
        else
        {
            AddKnownAnalyses();
        }

        void AddKnownAnalyses()
        {
            TryAdd("MX", () => DomainDetective.Views.Converters.Convert(healthCheck.MXAnalysis));
            TryAdd("SPF", () => DomainDetective.Views.Converters.Convert(healthCheck.SpfAnalysis));
            TryAddRange("DKIM", () => DomainDetective.Views.Converters.Convert(healthCheck.DKIMAnalysis));
            TryAdd("DMARC", () => DomainDetective.Views.Converters.Convert(healthCheck.DmarcAnalysis));
            TryAdd("TYPOSQUATTING", () => DomainDetective.Views.Converters.Convert(healthCheck.TyposquattingAnalysis));
            TryAdd("CAA", () => DomainDetective.Views.Converters.Convert(healthCheck.CAAAnalysis));
            TryAdd("DNSBL", () => DomainDetective.Views.Converters.Convert(healthCheck.DNSBLAnalysis));
            TryAdd("RPKI", () => DomainDetective.Views.Converters.Convert(healthCheck.RpkiAnalysis));
            TryAdd("NS", () => DomainDetective.Views.Converters.Convert(healthCheck.NSAnalysis));
            TryAdd("SOA", () => DomainDetective.Views.Converters.Convert(healthCheck.SOAAnalysis));
            TryAdd("TTL", () => DomainDetective.Views.Converters.Convert(healthCheck.DnsTtlAnalysis));
            TryAdd("ZONETRANSFER", () => DomainDetective.Views.Converters.Convert(healthCheck.ZoneTransferAnalysis));
            TryAdd("WILDCARDDNS", () => DomainDetective.Views.Converters.Convert(healthCheck.WildcardDnsAnalysis));
            TryAdd("MTASTS", () => DomainDetective.Views.Converters.Convert(healthCheck.MTASTSAnalysis));
            TryAdd("TLSRPT", () => DomainDetective.Views.Converters.Convert(healthCheck.TLSRPTAnalysis));
            TryAdd("DANE", () => DomainDetective.Views.Converters.Convert(healthCheck.DaneAnalysis));
            TryAdd("DNSSEC", () => DomainDetective.Views.Converters.Convert(healthCheck.DnsSecAnalysis));
            TryAdd("CTTIMELINE", () => DomainDetective.Views.Converters.Convert(healthCheck.CtTimelineAnalysis));
            TryAdd("SUBDOMAINS", () => DomainDetective.Views.Converters.Convert(healthCheck.SubdomainsAnalysis));
            TryAdd("DNSINVENTORY", () => DomainDetective.Views.Converters.Convert(healthCheck.DnsInventoryAnalysis));
            TryAdd("DNSAMPLIFICATION", () => DomainDetective.Views.Converters.Convert(healthCheck.DnsAmplificationAnalysis));
            TryAdd("DNSOVERTLS", () => DomainDetective.Views.Converters.Convert(healthCheck.DnsOverTlsAnalysis));
            if (!string.IsNullOrWhiteSpace(healthCheck.HttpAnalysis.Subject))
            {
                TryAdd("HTTP", () => DomainDetective.Views.Converters.Convert(healthCheck.HttpAnalysis));
            }
            if (!string.IsNullOrWhiteSpace(healthCheck.IpEnrichmentAnalysis.Subject))
            {
                TryAdd("IPENRICHMENT", () => DomainDetective.Views.Converters.Convert(healthCheck.IpEnrichmentAnalysis));
            }
            try
            {
                var set = healthCheck.DnsPropagationSet;
                if (set != null && set.Items.Count > 0)
                {
                    foreach (var a in set.Items)
                    {
                        TryAdd("DNSPROPAGATION", () => DomainDetective.Views.Converters.Convert(a));
                    }
                }
            }
            catch (Exception ex)
            {
                conversionErrors.Add($"DNSPROPAGATION: {ex.GetType().Name}: {ex.Message}");
            }
            if (includeDnsTrace)
            {
                TryAdd("DNSTRACE", () => DomainDetective.Views.Converters.Convert(healthCheck.DnsTraceAnalysis));
            }

            if (healthCheck.ArcAnalysis.ArcHeadersFound || healthCheck.ArcAnalysis.Assessments.Count > 0) {
                TryAdd("ARC", () => DomainDetective.Views.Converters.Convert(healthCheck.ArcAnalysis));
            }
            TryAdd("BIMI", () => DomainDetective.Views.Converters.Convert(healthCheck.BimiAnalysis));
            TryAdd("SMTPTLS", () => DomainDetective.Views.Converters.Convert(healthCheck.SmtpTlsAnalysis));
            TryAdd("IMAPTLS", () => DomainDetective.Views.Converters.Convert(healthCheck.ImapTlsAnalysis));
            TryAdd("POP3TLS", () => DomainDetective.Views.Converters.Convert(healthCheck.Pop3TlsAnalysis));
            TryAdd("MICROSOFT365", () => DomainDetective.Views.Converters.Convert(healthCheck.Microsoft365TenantAnalysis));
            TryAdd("AGENTREADINESS", () => DomainDetective.Views.Converters.Convert(healthCheck.AgentReadinessAnalysis));
            TryAdd("SITEMAP", () => DomainDetective.Views.Converters.Convert(healthCheck.SitemapAnalysis));
        }

        // Optional time-series sections from a store (only when data exists)
        if (!string.IsNullOrWhiteSpace(storePath))
        {
            try
            {
                var dmarcStore = new DmarcAggregateTimeSeriesStore(storePath!);
                var snaps = dmarcStore.LoadSnapshots(domain);
                if (snaps.Count > 0) items.Add(DomainDetective.Views.Converters.Convert(snaps, domain));
            }
            catch (Exception ex)
            {
                conversionErrors.Add($"DMARC-AGGREGATE-STORE: {ex.GetType().Name}: {ex.Message}");
            }

            try
            {
                var tlsStore = new TlsRptTimeSeriesStore(storePath!);
                var snaps = tlsStore.LoadSnapshots(domain);
                if (snaps.Count > 0) items.Add(DomainDetective.Views.Converters.Convert(snaps, domain));
            }
            catch (Exception ex)
            {
                conversionErrors.Add($"TLSRPT-STORE: {ex.GetType().Name}: {ex.Message}");
            }

            try
            {
                var regStore = new RegistrationTimeSeriesStore(storePath!);
                var snaps = regStore.LoadSnapshots(domain);
                if (snaps.Count > 0) items.Add(DomainDetective.Views.Converters.Convert(snaps, domain));
            }
            catch (Exception ex)
            {
                conversionErrors.Add($"REGISTRATION-STORE: {ex.GetType().Name}: {ex.Message}");
            }
        }

        var completed = items.Where(item => CompositionUtilities.ExtractSubjects(new[] { item }).Count > 0).ToList();
        var represented = new HashSet<Assessment>();
        foreach (var item in completed) {
            if (item.GetType().GetProperty("Assessments")?.GetValue(item) is IEnumerable<Assessment> assessments) {
                foreach (var assessment in assessments) { represented.Add(assessment); }
            }
        }
        var additional = healthCheck.GetAllAssessments().Where(a => !represented.Contains(a)).ToArray();
        if (additional.Length > 0) { completed.Add(new AssessmentEvidenceInfo(domain, additional)); }
        return completed;
    }

}
