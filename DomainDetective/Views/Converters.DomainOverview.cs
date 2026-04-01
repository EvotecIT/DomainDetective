using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters {
    public static DomainOverviewInfo ConvertDomainOverview(DomainHealthCheck health, string subject) {
        var dnsInventory = Convert(health.DnsInventoryAnalysis);
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
        var soa = Convert(health.SOAAnalysis);
        var http = Convert(health.HttpAnalysis);
        var certificate = Convert(health.CertificateAnalysis);
        var securityTxt = Convert(health.SecurityTXTAnalysis);
        var rdap = Convert(health.RdapAnalysis);
        var dnsbl = Convert(health.DNSBLAnalysis);
        var subdomains = Convert(health.SubdomainsAnalysis);
        var assessments = health.GetAllAssessments().ToArray();

        return ConvertDomainOverview(
            subject,
            dnsInventory,
            spf,
            dkim,
            dmarc,
            mx,
            mtasts,
            tlsRpt,
            bimi,
            caa,
            dane,
            dnssec,
            ns,
            soa,
            http,
            certificate,
            securityTxt,
            rdap,
            dnsbl,
            subdomains,
            assessments);
    }

    public static DomainOverviewInfo ConvertDomainOverview(
        string subject,
        DnsInventoryInfo dnsInventory,
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
        SoaInfo soa,
        HttpInfo http,
        CertificateInfo certificate,
        SecurityTxtInfo securityTxt,
        RdapInfo rdap,
        DnsblInfo dnsbl,
        SubdomainsInfo subdomains,
        IEnumerable<Assessment> assessmentsSource,
        bool browserLimited = false) {
        var assessments = OverviewAssessmentFilter.ForOverview(assessmentsSource, browserLimited).ToArray();
        var summary = BuildDomainSummary(spf, dkim, dmarc, mx, dnssec, rdap);

        int infoCount = 0;
        int warningCount = 0;
        int errorCount = 0;
        foreach (var assessment in assessments) {
            switch (assessment.Severity) {
                case AssessmentSeverity.Info:
                    infoCount++;
                    break;
                case AssessmentSeverity.Warning:
                    warningCount++;
                    break;
                case AssessmentSeverity.Error:
                    errorCount++;
                    break;
            }
        }

        var mailDnsChecks = new[] {
            BuildDomainSpfStatus(spf),
            BuildDomainDkimStatus(dkim),
            BuildDomainDmarcStatus(dmarc),
            BuildDomainMxStatus(mx),
            BuildDomainMtastsStatus(mtasts),
            BuildDomainTlsRptStatus(tlsRpt),
            BuildDomainBimiStatus(bimi),
            BuildDomainCaaStatus(caa),
            BuildDomainDaneStatus(dane),
            BuildDomainDnssecStatus(dnssec),
            BuildDomainNsStatus(ns),
            BuildDomainSoaStatus(soa)
        };

        var webRegistrationChecks = new[] {
            BuildHttpStatus(http),
            BuildCertificateStatus(certificate),
            BuildSecurityTxtStatus(securityTxt),
            BuildRdapStatus(rdap),
            BuildDnsblStatus(dnsbl),
            BuildSubdomainStatus(subdomains)
        };

        var highlights = new List<string>();
        highlights.AddRange(summary.Hints ?? Array.Empty<string>());
        if (dnsInventory.MailProvider != Providers.Email.MailProviderKind.Unknown) {
            highlights.Add("Mail provider: " + dnsInventory.MailProvider);
        }
        if (dnsInventory.Provider != Providers.Dns.DnsProvider.Unknown) {
            highlights.Add("DNS provider: " + dnsInventory.Provider);
        }
        if (http.IsReachable) {
            highlights.Add($"Web posture: grade {http.Grade}");
        }
        if (subdomains.SubdomainCount > 0) {
            highlights.Add($"Discovered {subdomains.SubdomainCount} subdomain(s).");
        }

        return new DomainOverviewInfo {
            Subject = subject,
            Summary = summary,
            TotalAssessments = infoCount + warningCount + errorCount,
            InfoCount = infoCount,
            WarningCount = warningCount,
            ErrorCount = errorCount,
            DnsProvider = dnsInventory.Provider.ToString(),
            MailProvider = dnsInventory.MailProvider.ToString(),
            DetectedApplicationCount = dnsInventory.DetectedDnsApplications.Count,
            HttpGrade = http.Grade.ToString(),
            HttpReachable = http.IsReachable,
            SecurityTxtPublished = securityTxt.RecordPresent,
            DaysUntilExpiration = rdap.DaysUntilExpiration,
            SubdomainCount = subdomains.SubdomainCount,
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
            Soa = soa,
            Http = http,
            Certificate = certificate,
            SecurityTxt = securityTxt,
            Rdap = rdap,
            Dnsbl = dnsbl,
            Subdomains = subdomains,
            DetectedApplications = dnsInventory.DetectedDnsApplications ?? Array.Empty<DetectedDnsApplication>(),
            SubdomainSample = (subdomains.Subdomains ?? Array.Empty<SubdomainDiscoveryEntry>()).Select(static item => item.Name).Where(static item => !string.IsNullOrWhiteSpace(item)).Take(12).ToArray(),
            MailDnsChecks = mailDnsChecks,
            WebRegistrationChecks = webRegistrationChecks,
            Highlights = highlights.Where(static value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            Assessments = assessments,
            Recommendations = OverviewRecommendationFilter.ForProblems(assessments),
            Positives = OverviewRecommendationFilter.ForPositives(assessments)
        };
    }

    private static DomainSummary BuildDomainSummary(
        SpfRecordInfo spf,
        IReadOnlyList<DkimRecordInfo> dkim,
        DmarcRecordInfo dmarc,
        MxInfo mx,
        DnsSecInfo dnssec,
        RdapInfo rdap) {
        var spfValid = spf.SpfRecordExists &&
                       spf.StartsCorrectly &&
                       !spf.ExceedsDnsLookups &&
                       !spf.MultipleSpfRecords &&
                       !spf.PermError;

        var dmarcValid = dmarc.DmarcRecordExists &&
                         dmarc.StartsCorrectly &&
                         dmarc.IsPolicyValid &&
                         dmarc.IsPctValid &&
                         dmarc.HasMandatoryTags &&
                         !dmarc.MultipleRecords &&
                         !dmarc.ExceedsCharacterLimit &&
                         dmarc.ValidDkimAlignment &&
                         dmarc.ValidSpfAlignment;

        var dkimValid = dkim.Any(static item =>
            item.DkimRecordExists && item.StartsCorrectly && item.PublicKeyExists &&
            item.ValidPublicKey && item.KeyTypeExists && item.ValidKeyType && item.ValidFlags);

        var hints = new List<string>();
        AddHintIfNeeded(hints, !spfValid, HealthCheckType.SPF);
        AddHintIfNeeded(hints, !dmarcValid, HealthCheckType.DMARC);
        AddHintIfNeeded(hints, !dkimValid, HealthCheckType.DKIM);
        AddHintIfNeeded(hints, !mx.MxRecordExists, HealthCheckType.MX);
        AddHintIfNeeded(hints, !dnssec.ChainValid, HealthCheckType.DNSSEC);

        var daysUntilExpiration = rdap.DaysUntilExpiration ?? 0;
        var isExpired = rdap.RecordAvailable && daysUntilExpiration < 0;
        var expiresSoon = rdap.RecordAvailable && daysUntilExpiration >= 0 && daysUntilExpiration <= 30;
        if (isExpired || expiresSoon) {
            hints.Add("Renew the domain registration.");
        }

        return new DomainSummary {
            HasSpfRecord = spf.SpfRecordExists,
            SpfValid = spfValid,
            HasDmarcRecord = dmarc.DmarcRecordExists,
            DmarcPolicy = dmarc.Policy ?? string.Empty,
            DmarcValid = dmarcValid,
            HasDkimRecord = dkim.Any(static item => item.DkimRecordExists),
            DkimValid = dkimValid,
            HasMxRecord = mx.MxRecordExists,
            DnsSecValid = dnssec.ChainValid,
            DnsSecKeyExpiresSoon = dnssec.KeyExpiresSoon,
            IsPublicSuffix = false,
            ExpiryDate = rdap.ExpiryDate ?? string.Empty,
            DaysUntilExpiration = rdap.DaysUntilExpiration,
            ExpiresSoon = expiresSoon,
            IsExpired = isExpired,
            RegistrarLocked = false,
            PrivacyProtected = false,
            Hints = hints.ToArray()
        };
    }

    private static void AddHintIfNeeded(List<string> hints, bool condition, HealthCheckType type) {
        if (!condition) {
            return;
        }

        var hint = CheckDescriptions.Get(type)?.Remediation;
        if (!string.IsNullOrWhiteSpace(hint)) {
            hints.Add(hint!);
        }
    }

    private static AggregateCheckStatusInfo BuildDomainSpfStatus(SpfRecordInfo info) => new AggregateCheckStatusInfo {
        Key = "spf",
        Label = "SPF",
        State = !info.SpfRecordExists ? AggregateCheckState.Fail : info.ErrorCount > 0 || info.PermError ? AggregateCheckState.Fail : info.WarningCount > 0 ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = !info.SpfRecordExists ? "Missing" : info.AllMechanism ?? "Published",
        Detail = info.SpfRecordExists ? $"{info.DnsLookupsCount}/10 lookups" : "No SPF policy published."
    };

    private static AggregateCheckStatusInfo BuildDomainDkimStatus(IReadOnlyList<DkimRecordInfo> selectors) => new AggregateCheckStatusInfo {
        Key = "dkim",
        Label = "DKIM",
        State = selectors.Count == 0 ? AggregateCheckState.Fail : selectors.Any(static item => item.ErrorCount > 0) ? AggregateCheckState.Fail : selectors.Any(static item => item.WarningCount > 0 || item.WeakKey) ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = selectors.Count == 0 ? "Missing" : $"{selectors.Count(static item => item.ValidPublicKey && !item.WeakKey)}/{selectors.Count} valid",
        Detail = selectors.Count == 0 ? "No selectors were discovered." : string.Join(", ", selectors.Select(static item => item.Selector).Take(3))
    };

    private static AggregateCheckStatusInfo BuildDomainDmarcStatus(DmarcRecordInfo info) => new AggregateCheckStatusInfo {
        Key = "dmarc",
        Label = "DMARC",
        State = !info.DmarcRecordExists ? AggregateCheckState.Fail : info.ErrorCount > 0 || !info.IsPolicyValid ? AggregateCheckState.Fail : info.WarningCount > 0 || info.WeakPolicy ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = !info.DmarcRecordExists ? "Missing" : string.IsNullOrWhiteSpace(info.Policy) ? "Published" : info.Policy.ToUpperInvariant(),
        Detail = info.DmarcRecordExists ? $"{info.MailtoRua.Count + info.HttpRua.Count} report target(s)" : "No DMARC policy published."
    };

    private static AggregateCheckStatusInfo BuildDomainMxStatus(MxInfo info) => new AggregateCheckStatusInfo {
        Key = "mx",
        Label = "MX",
        State = !info.MxRecordExists ? AggregateCheckState.Fail : info.ErrorCount > 0 ? AggregateCheckState.Fail : info.WarningCount > 0 ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = info.MxRecordExists ? $"{info.MxRecords.Count} record(s)" : "Missing",
        Detail = info.MxRecordExists ? (info.ProviderPrimary ?? "Provider unknown") : "No MX routes published."
    };

    private static AggregateCheckStatusInfo BuildDomainMtastsStatus(MtastsInfo info) => new AggregateCheckStatusInfo {
        Key = "mta-sts",
        Label = "MTA-STS",
        State = !info.PolicyPresent ? AggregateCheckState.Fail : info.ErrorCount > 0 || !info.PolicyValid ? AggregateCheckState.Fail : info.WarningCount > 0 || !info.DnsRecordPresent ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = !info.PolicyPresent ? "Missing" : info.Mode ?? "Published",
        Detail = info.PolicyPresent ? $"{info.MxPatterns?.Count ?? 0} MX pattern(s)" : "No MTA-STS policy published."
    };

    private static AggregateCheckStatusInfo BuildDomainTlsRptStatus(TlsRptInfo info) => new AggregateCheckStatusInfo {
        Key = "tls-rpt",
        Label = "TLS-RPT",
        State = !info.TlsRptRecordExists ? AggregateCheckState.Fail : info.ErrorCount > 0 || !info.PolicyValid ? AggregateCheckState.Fail : info.WarningCount > 0 ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = !info.TlsRptRecordExists ? "Missing" : $"{info.MailtoRua.Count + info.HttpRua.Count} endpoint(s)",
        Detail = info.TlsRptRecordExists ? "TLS reporting configured." : "No TLS reporting record published."
    };

    private static AggregateCheckStatusInfo BuildDomainBimiStatus(BimiRecordInfo info) => new AggregateCheckStatusInfo {
        Key = "bimi",
        Label = "BIMI",
        State = !info.BimiRecordExists ? AggregateCheckState.Fail : info.ErrorCount > 0 || info.InvalidLocation ? AggregateCheckState.Fail : info.WarningCount > 0 ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = !info.BimiRecordExists ? "Missing" : info.ValidVmc ? "VMC present" : "Indicator only",
        Detail = info.BimiRecordExists ? (info.Location ?? "BIMI record published.") : "No BIMI record published."
    };

    private static AggregateCheckStatusInfo BuildDomainCaaStatus(CaaInfo info) => new AggregateCheckStatusInfo {
        Key = "caa",
        Label = "CAA",
        State = info.ValidRecords == 0 ? AggregateCheckState.Fail : info.ErrorCount > 0 || info.InvalidRecords > 0 ? AggregateCheckState.Fail : info.WarningCount > 0 ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = info.ValidRecords > 0 ? $"{info.ValidRecords} valid" : "Missing",
        Detail = info.ValidRecords > 0 ? $"{info.CanIssueCertificatesForDomain.Count} issuer authorization(s)" : "No CAA restrictions published."
    };

    private static AggregateCheckStatusInfo BuildDomainDaneStatus(DaneRecordInfo info) => new AggregateCheckStatusInfo {
        Key = "dane",
        Label = "DANE",
        State = info.NumberOfRecords == 0 ? AggregateCheckState.Fail : info.ErrorCount > 0 ? AggregateCheckState.Fail : info.WarningCount > 0 || info.ValidRecordCount == 0 || info.HasInvalidRecords ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = info.NumberOfRecords > 0 ? $"{info.ValidRecordCount} valid" : "Missing",
        Detail = info.NumberOfRecords > 0 ? $"{info.RecommendedRecordCount} recommended TLSA record(s)" : "No TLSA records published."
    };

    private static AggregateCheckStatusInfo BuildDomainDnssecStatus(DnsSecInfo info) => new AggregateCheckStatusInfo {
        Key = "dnssec",
        Label = "DNSSEC",
        State = info.ChainValid ? (info.KeyExpiresSoon ? AggregateCheckState.Warning : AggregateCheckState.Pass) : AggregateCheckState.Fail,
        Value = info.ChainValid ? "Valid" : "Broken",
        Detail = $"{info.DsRecords.Count} DS, {info.DnsKeys.Count} DNSKEY"
    };

    private static AggregateCheckStatusInfo BuildDomainNsStatus(NsInfo info) => new AggregateCheckStatusInfo {
        Key = "ns",
        Label = "NS",
        State = !info.NsRecordExists ? AggregateCheckState.Fail : info.ErrorCount > 0 ? AggregateCheckState.Fail : info.WarningCount > 0 || !info.AtLeastTwoRecords ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = info.NsRecordExists ? $"{info.NsRecords.Count} nameserver(s)" : "Missing",
        Detail = info.NsRecordExists ? $"ASN diversity: {info.AsnDistinctCount}" : "No authoritative nameservers published."
    };

    private static AggregateCheckStatusInfo BuildDomainSoaStatus(SoaInfo info) => new AggregateCheckStatusInfo {
        Key = "soa",
        Label = "SOA",
        State = !info.RecordExists ? AggregateCheckState.Fail : info.ErrorCount > 0 ? AggregateCheckState.Fail : info.WarningCount > 0 ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = info.RecordExists ? info.SerialNumber.ToString() : "Missing",
        Detail = info.RecordExists ? $"{info.PrimaryNameServer} / refresh {info.Refresh}s" : "No SOA record published."
    };

    private static AggregateCheckStatusInfo BuildHttpStatus(HttpInfo info) => new AggregateCheckStatusInfo {
        Key = "http",
        Label = "HTTP",
        State = !info.IsReachable ? AggregateCheckState.Fail : info.ErrorCount > 0 ? AggregateCheckState.Fail : info.WarningCount > 0 ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = !info.IsReachable ? "Offline" : $"Grade {info.Grade}",
        Detail = info.IsReachable ? $"Status {(info.StatusCode?.ToString() ?? "?")} / HSTS {(info.HstsPresent ? "on" : "off")}" : (info.FailureReason ?? "Host was not reachable.")
    };

    private static AggregateCheckStatusInfo BuildCertificateStatus(CertificateInfo info) => new AggregateCheckStatusInfo {
        Key = "cert",
        Label = "Certificate",
        State = !info.IsReachable ? AggregateCheckState.Fail : info.ErrorCount > 0 || !info.IsValid ? AggregateCheckState.Fail : info.WarningCount > 0 || info.WeakKey ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = !info.IsReachable ? "Missing" : (string.IsNullOrWhiteSpace(info.TlsProtocol) ? "Present" : info.TlsProtocol),
        Detail = info.IsReachable ? (info.ValidTo.HasValue ? $"Expires {info.ValidTo.Value:yyyy-MM-dd}" : "Certificate published.") : "No TLS certificate was obtained."
    };

    private static AggregateCheckStatusInfo BuildSecurityTxtStatus(SecurityTxtInfo info) => new AggregateCheckStatusInfo {
        Key = "security-txt",
        Label = "Security.txt",
        State = !info.RecordPresent ? AggregateCheckState.Fail : info.ErrorCount > 0 || !info.RecordValid ? AggregateCheckState.Fail : info.WarningCount > 0 ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = info.RecordPresent ? "Published" : "Missing",
        Detail = info.RecordPresent ? $"{info.ContactEmail.Count + info.ContactWebsite.Count} contact(s)" : "No security.txt disclosure file found."
    };

    private static AggregateCheckStatusInfo BuildRdapStatus(RdapInfo info) => new AggregateCheckStatusInfo {
        Key = "rdap",
        Label = "RDAP",
        State = !info.RecordAvailable ? AggregateCheckState.Fail : info.ErrorCount > 0 || info.HasHoldStatus ? AggregateCheckState.Fail : info.WarningCount > 0 ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = !info.RecordAvailable ? "Unavailable" : (info.DaysUntilExpiration.HasValue ? $"{info.DaysUntilExpiration.Value} days" : "Available"),
        Detail = info.RecordAvailable ? (info.Registrar ?? "Registrar unknown") : "Registration data was not available."
    };

    private static AggregateCheckStatusInfo BuildDnsblStatus(DnsblInfo info) => new AggregateCheckStatusInfo {
        Key = "dnsbl",
        Label = "DNSBL",
        State = info.HostsListed > 0 ? AggregateCheckState.Fail : info.ErrorCount > 0 ? AggregateCheckState.Fail : info.WarningCount > 0 ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = info.HostsListed > 0 ? $"{info.HostsListed} listed" : "Clear",
        Detail = $"{info.Targets.Count} target(s), {info.Listings.Count} listing(s)"
    };

    private static AggregateCheckStatusInfo BuildSubdomainStatus(SubdomainsInfo info) => new AggregateCheckStatusInfo {
        Key = "subdomains",
        Label = "Subdomains",
        State = info.ErrorCount > 0 ? AggregateCheckState.Fail : info.WarningCount > 0 ? AggregateCheckState.Warning : AggregateCheckState.Info,
        Value = $"{info.SubdomainCount} found",
        Detail = $"{info.ResolvesCount} resolve, {info.DoesNotResolveCount} do not"
    };
}

public sealed class DomainOverviewInfo {
    public string Subject { get; set; } = string.Empty;
    public bool IsPartial { get; set; }
    public bool IsBrowserLimited { get; set; }
    public bool ServedFromCache { get; set; }
    public string StageLabel { get; set; } = string.Empty;
    public DateTimeOffset GeneratedAtUtc { get; set; }
    public DateTimeOffset? CompletedAtUtc { get; set; }
    public DomainSummary Summary { get; set; } = new DomainSummary();
    public int TotalAssessments { get; set; }
    public int InfoCount { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string DnsProvider { get; set; } = string.Empty;
    public string MailProvider { get; set; } = string.Empty;
    public int DetectedApplicationCount { get; set; }
    public string HttpGrade { get; set; } = string.Empty;
    public bool HttpReachable { get; set; }
    public bool SecurityTxtPublished { get; set; }
    public int? DaysUntilExpiration { get; set; }
    public int SubdomainCount { get; set; }
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
    public SoaInfo? Soa { get; set; }
    public HttpInfo? Http { get; set; }
    public CertificateInfo? Certificate { get; set; }
    public SecurityTxtInfo? SecurityTxt { get; set; }
    public RdapInfo? Rdap { get; set; }
    public DnsblInfo? Dnsbl { get; set; }
    public SubdomainsInfo? Subdomains { get; set; }
    public IReadOnlyList<string> PendingSections { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> UnavailableSections { get; set; } = Array.Empty<string>();
    public IReadOnlyList<DetectedDnsApplication> DetectedApplications { get; set; } = Array.Empty<DetectedDnsApplication>();
    public IReadOnlyList<string> SubdomainSample { get; set; } = Array.Empty<string>();
    public IReadOnlyList<AggregateCheckStatusInfo> MailDnsChecks { get; set; } = Array.Empty<AggregateCheckStatusInfo>();
    public IReadOnlyList<AggregateCheckStatusInfo> WebRegistrationChecks { get; set; } = Array.Empty<AggregateCheckStatusInfo>();
    public IReadOnlyList<string> Highlights { get; set; } = Array.Empty<string>();
    public IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = Array.Empty<RecommendationAdvice>();
}
