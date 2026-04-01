using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters {
    public static Microsoft365OverviewInfo ConvertMicrosoft365Overview(DomainHealthCheck health, string subject) {
        var tenant = Convert(health.Microsoft365TenantAnalysis);
        var spf = Convert(health.SpfAnalysis);
        var dkim = Convert(health.DKIMAnalysis).ToArray();
        var dmarc = Convert(health.DmarcAnalysis);
        var mx = Convert(health.MXAnalysis);
        var mtasts = Convert(health.MTASTSAnalysis);
        var tlsRpt = Convert(health.TLSRPTAnalysis);
        var bimi = Convert(health.BimiAnalysis);
        var caa = Convert(health.CAAAnalysis);
        var dane = Convert(health.DaneAnalysis);
        var dnssec = DnsSecConverter.Convert(health.DnsSecAnalysis);
        var ns = Convert(health.NSAnalysis);
        var assessments = health.GetAllAssessments().ToArray();

        return ConvertMicrosoft365Overview(subject, tenant, spf, dkim, dmarc, mx, mtasts, tlsRpt, bimi, caa, dane, dnssec, ns, assessments);
    }

    public static Microsoft365OverviewInfo ConvertMicrosoft365Overview(
        string subject,
        Microsoft365TenantInfo tenant,
        SpfRecordInfo spf,
        IReadOnlyList<DkimRecordInfo> dkim,
        DmarcRecordInfo dmarc,
        MxInfo mx,
        MtastsInfo mtasts,
        TlsRptInfo tlsRpt,
        BimiRecordInfo bimi,
        CaaInfo caa,
        DaneRecordInfo dane,
        DnsSecInfo dnssec,
        NsInfo ns,
        IEnumerable<Assessment> assessmentsSource,
        bool browserLimited = false) {
        var assessments = OverviewAssessmentFilter.ForOverview(assessmentsSource, browserLimited).ToArray();
        var warnings = assessments.Count(static assessment => assessment.Severity == AssessmentSeverity.Warning);
        var errors = assessments.Count(static assessment => assessment.Severity == AssessmentSeverity.Error);

        var checks = new[] {
            BuildSpfStatus(spf),
            BuildDkimStatus(dkim),
            BuildDmarcStatus(dmarc),
            BuildMxStatus(mx),
            BuildMtastsStatus(mtasts),
            BuildTlsRptStatus(tlsRpt),
            BuildBimiStatus(bimi),
            BuildCaaStatus(caa),
            BuildDaneStatus(dane),
            BuildDnssecStatus(dnssec),
            BuildNsStatus(ns)
        };

        var highlights = new List<string>();
        if (tenant.Highlights != null) {
            highlights.AddRange(tenant.Highlights.Where(static value => !string.IsNullOrWhiteSpace(value)).Take(6));
        }

        var failingChecks = checks.Count(static check => check.State == AggregateCheckState.Fail);
        if (failingChecks > 0) {
            highlights.Add($"{failingChecks} core mail or DNS controls need attention.");
        }

        return new Microsoft365OverviewInfo {
            Subject = subject,
            Tenant = tenant,
            WarningCount = warnings,
            ErrorCount = errors,
            DetectedServiceCount = tenant.Services.Count(static service => service.Status == Microsoft365DetectionStatus.Detected),
            StrongServiceCount = tenant.Services.Count(static service => service.Status == Microsoft365DetectionStatus.Detected && service.Confidence == Microsoft365DetectionConfidence.Strong),
            ModerateServiceCount = tenant.Services.Count(static service => service.Status == Microsoft365DetectionStatus.Detected && service.Confidence == Microsoft365DetectionConfidence.Moderate),
            WeakServiceCount = tenant.Services.Count(static service => service.Status == Microsoft365DetectionStatus.Detected && service.Confidence == Microsoft365DetectionConfidence.Weak),
            AcceptedDomainCount = tenant.TenantDomains.Count(static domain => domain.Role == Microsoft365TenantDomainRole.AcceptedCustomDomain),
            KnownSubdomainCount = tenant.KnownSubdomains.Count,
            DetectedApplicationCount = tenant.DetectedDnsApplications.Count,
            Spf = spf,
            Dkim = dkim,
            Dmarc = dmarc,
            Mx = mx,
            Mtasts = mtasts,
            TlsRpt = tlsRpt,
            Bimi = bimi,
            Caa = caa,
            Dane = dane,
            Dnssec = dnssec,
            Ns = ns,
            MailDnsChecks = checks,
            Highlights = highlights.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            Assessments = assessments,
            Recommendations = OverviewRecommendationFilter.ForProblems(assessments),
            Positives = OverviewRecommendationFilter.ForPositives(assessments)
        };
    }

    private static AggregateCheckStatusInfo BuildSpfStatus(SpfRecordInfo info) => new AggregateCheckStatusInfo {
        Key = "spf",
        Label = "SPF",
        State = !info.SpfRecordExists ? AggregateCheckState.Fail : info.ErrorCount > 0 || info.PermError ? AggregateCheckState.Fail : info.WarningCount > 0 || info.ExceedsDnsLookups || info.MultipleSpfRecords ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = !info.SpfRecordExists ? "Missing" : info.AllMechanism ?? "Published",
        Detail = info.SpfRecordExists ? $"{info.DnsLookupsCount}/10 lookups, providers {info.ProviderCounts.Count}" : "No SPF policy published."
    };

    private static AggregateCheckStatusInfo BuildDkimStatus(IReadOnlyList<DkimRecordInfo> selectors) => new AggregateCheckStatusInfo {
        Key = "dkim",
        Label = "DKIM",
        State = selectors.Count == 0 ? AggregateCheckState.Fail : selectors.Any(static selector => selector.ErrorCount > 0) ? AggregateCheckState.Fail : selectors.Any(static selector => selector.WarningCount > 0 || selector.WeakKey) ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = selectors.Count == 0 ? "Missing" : $"{selectors.Count(static selector => selector.DkimRecordExists && selector.ValidPublicKey && !selector.WeakKey)}/{selectors.Count} valid",
        Detail = selectors.Count == 0 ? "No selectors were discovered." : $"Selectors: {string.Join(", ", selectors.Select(static selector => selector.Selector).Take(3))}"
    };

    private static AggregateCheckStatusInfo BuildDmarcStatus(DmarcRecordInfo info) => new AggregateCheckStatusInfo {
        Key = "dmarc",
        Label = "DMARC",
        State = !info.DmarcRecordExists ? AggregateCheckState.Fail : info.ErrorCount > 0 || !info.IsPolicyValid ? AggregateCheckState.Fail : info.WarningCount > 0 || info.WeakPolicy ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = !info.DmarcRecordExists ? "Missing" : string.IsNullOrWhiteSpace(info.Policy) ? "Published" : info.Policy.ToUpperInvariant(),
        Detail = info.DmarcRecordExists ? $"Aggregate targets: {info.MailtoRua.Count + info.HttpRua.Count}" : "No DMARC policy published."
    };

    private static AggregateCheckStatusInfo BuildMxStatus(MxInfo info) => new AggregateCheckStatusInfo {
        Key = "mx",
        Label = "MX",
        State = !info.MxRecordExists ? AggregateCheckState.Fail : info.ErrorCount > 0 ? AggregateCheckState.Fail : info.WarningCount > 0 ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = info.MxRecordExists ? $"{info.MxRecords.Count} record(s)" : "Missing",
        Detail = info.MxRecordExists ? (info.ProviderPrimary ?? "Provider unknown") : "No MX routes published."
    };

    private static AggregateCheckStatusInfo BuildMtastsStatus(MtastsInfo info) => new AggregateCheckStatusInfo {
        Key = "mta-sts",
        Label = "MTA-STS",
        State = !info.PolicyPresent ? AggregateCheckState.Fail : info.ErrorCount > 0 || !info.PolicyValid ? AggregateCheckState.Fail : info.WarningCount > 0 || !info.DnsRecordPresent ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = !info.PolicyPresent ? "Missing" : info.Mode ?? "Published",
        Detail = info.PolicyPresent ? $"{info.MxPatterns?.Count ?? 0} MX pattern(s)" : "No MTA-STS policy published."
    };

    private static AggregateCheckStatusInfo BuildTlsRptStatus(TlsRptInfo info) => new AggregateCheckStatusInfo {
        Key = "tls-rpt",
        Label = "TLS-RPT",
        State = !info.TlsRptRecordExists ? AggregateCheckState.Fail : info.ErrorCount > 0 || !info.PolicyValid ? AggregateCheckState.Fail : info.WarningCount > 0 ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = !info.TlsRptRecordExists ? "Missing" : $"{info.MailtoRua.Count + info.HttpRua.Count} endpoint(s)",
        Detail = info.TlsRptRecordExists ? "Reporting configured for TLS failures." : "No TLS reporting record published."
    };

    private static AggregateCheckStatusInfo BuildBimiStatus(BimiRecordInfo info) => new AggregateCheckStatusInfo {
        Key = "bimi",
        Label = "BIMI",
        State = !info.BimiRecordExists ? AggregateCheckState.Fail : info.ErrorCount > 0 || info.InvalidLocation ? AggregateCheckState.Fail : info.WarningCount > 0 ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = !info.BimiRecordExists ? "Missing" : info.ValidVmc ? "VMC present" : "Indicator only",
        Detail = info.BimiRecordExists ? (info.Location ?? "BIMI record published.") : "No BIMI record published."
    };

    private static AggregateCheckStatusInfo BuildCaaStatus(CaaInfo info) => new AggregateCheckStatusInfo {
        Key = "caa",
        Label = "CAA",
        State = info.ValidRecords == 0 ? AggregateCheckState.Fail : info.ErrorCount > 0 || info.InvalidRecords > 0 ? AggregateCheckState.Fail : info.WarningCount > 0 || info.Conflicting ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = info.ValidRecords > 0 ? $"{info.ValidRecords} valid" : "Missing",
        Detail = info.ValidRecords > 0 ? $"{info.CanIssueCertificatesForDomain.Count} issuer authorizations" : "No CAA restrictions published."
    };

    private static AggregateCheckStatusInfo BuildDaneStatus(DaneRecordInfo info) => new AggregateCheckStatusInfo {
        Key = "dane",
        Label = "DANE",
        State = info.NumberOfRecords == 0 ? AggregateCheckState.Fail : info.ErrorCount > 0 ? AggregateCheckState.Fail : info.WarningCount > 0 || info.ValidRecordCount == 0 || info.HasInvalidRecords ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = info.NumberOfRecords > 0 ? $"{info.ValidRecordCount} valid" : "Missing",
        Detail = info.NumberOfRecords > 0 ? $"{info.RecommendedRecordCount} recommended TLSA record(s)" : "No TLSA records published."
    };

    private static AggregateCheckStatusInfo BuildDnssecStatus(DnsSecInfo info) => new AggregateCheckStatusInfo {
        Key = "dnssec",
        Label = "DNSSEC",
        State = info.ChainValid ? (info.KeyExpiresSoon ? AggregateCheckState.Warning : AggregateCheckState.Pass) : AggregateCheckState.Fail,
        Value = info.ChainValid ? "Valid" : "Broken",
        Detail = $"{info.DsRecords.Count} DS, {info.DnsKeys.Count} DNSKEY"
    };

    private static AggregateCheckStatusInfo BuildNsStatus(NsInfo info) => new AggregateCheckStatusInfo {
        Key = "ns",
        Label = "NS",
        State = !info.NsRecordExists ? AggregateCheckState.Fail : info.ErrorCount > 0 ? AggregateCheckState.Fail : info.WarningCount > 0 || !info.AtLeastTwoRecords ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = info.NsRecordExists ? $"{info.NsRecords.Count} nameserver(s)" : "Missing",
        Detail = info.NsRecordExists ? $"ASN diversity: {info.AsnDistinctCount}" : "No authoritative nameservers published."
    };
}

public sealed class Microsoft365OverviewInfo {
    public string Subject { get; set; } = string.Empty;
    public bool IsPartial { get; set; }
    public bool IsBrowserLimited { get; set; }
    public bool ServedFromCache { get; set; }
    public string StageLabel { get; set; } = string.Empty;
    public DateTimeOffset GeneratedAtUtc { get; set; }
    public DateTimeOffset? CompletedAtUtc { get; set; }
    public Microsoft365TenantInfo Tenant { get; set; } = new Microsoft365TenantInfo();
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public int DetectedServiceCount { get; set; }
    public int StrongServiceCount { get; set; }
    public int ModerateServiceCount { get; set; }
    public int WeakServiceCount { get; set; }
    public int AcceptedDomainCount { get; set; }
    public int KnownSubdomainCount { get; set; }
    public int DetectedApplicationCount { get; set; }
    public SpfRecordInfo? Spf { get; set; }
    public IReadOnlyList<DkimRecordInfo> Dkim { get; set; } = Array.Empty<DkimRecordInfo>();
    public DmarcRecordInfo? Dmarc { get; set; }
    public MxInfo? Mx { get; set; }
    public MtastsInfo? Mtasts { get; set; }
    public TlsRptInfo? TlsRpt { get; set; }
    public BimiRecordInfo? Bimi { get; set; }
    public CaaInfo? Caa { get; set; }
    public DaneRecordInfo? Dane { get; set; }
    public DnsSecInfo? Dnssec { get; set; }
    public NsInfo? Ns { get; set; }
    public IReadOnlyList<string> PendingSections { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> UnavailableSections { get; set; } = Array.Empty<string>();
    public IReadOnlyList<AggregateCheckStatusInfo> MailDnsChecks { get; set; } = Array.Empty<AggregateCheckStatusInfo>();
    public IReadOnlyList<string> Highlights { get; set; } = Array.Empty<string>();
    public IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = Array.Empty<RecommendationAdvice>();
}
