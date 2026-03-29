using System;
using System.Collections.Generic;
using System.Linq;


namespace DomainDetective.Reports;

public static partial class SectionProjectors
{
    public sealed class SimpleFinding
    {
        public string Severity { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public SimpleFinding() {}
        public SimpleFinding(string severity, string code, string target, string message) { Severity = severity; Code = code; Target = target; Message = message; }
    }

    public sealed class SpfSection
    {
        public string Status { get; set; } = "-";
        public int DnsLookupsCount { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
        // Extras for parity with Word and richer Excel/HTML
        public string? SpfRecord { get; set; }
        public List<(string Qualifier, string Type, string Value, string Provider)> Mechanisms { get; } = new();
        public int FlattenedUniqueIpCount { get; set; }
        public int FlattenedDuplicateIpCount { get; set; }
        public int FlattenedTokenCount { get; set; }
        public List<(string Title, string Url)> ProviderHelp { get; } = new();
        public List<string> Highlights { get; } = new();
    }

    public sealed class DmarcSection
    {
        public string Status { get; set; } = "-";
        public string Policy { get; set; } = "-";
        public int RuaCount { get; set; }
        public int RufCount { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
        // Extras
        public string? DmarcRecord { get; set; }
        public string? DkimAlignment { get; set; }
        public string? SpfAlignment { get; set; }
        public List<string> MailtoRua { get; } = new();
        public List<string> HttpRua { get; } = new();
        public List<string> MailtoRuf { get; } = new();
        public List<string> HttpRuf { get; } = new();
        public List<string> Highlights { get; } = new();
    }

    public sealed class DkimSection
    {
        public sealed class Row
        {
            public string Selector { get; set; } = string.Empty;
            public string Status { get; set; } = "-";
            public string KeyBits { get; set; } = string.Empty;
            public string Hash { get; set; } = string.Empty;
            public bool Weak { get; set; }
            public string Flags { get; set; } = string.Empty;
            public int? TtlSeconds { get; set; }
            public bool CnameResolved { get; set; }
            public int? CnameTtlSeconds { get; set; }
            public string Record { get; set; } = string.Empty;
        }
        public List<Row> Rows { get; } = new List<Row>();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
        public List<string> Highlights { get; } = new();
    }

    // MX (Mail Exchanger) — compact DTO
    public sealed class MxSection
    {
        public string Status { get; set; } = "-";
        public bool HasBackup { get; set; }
        public bool Ipv6 { get; set; }
        public bool NullMx { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
        public List<string> Records { get; } = new();
        public string? MailTlsSmtp { get; set; }
        public string? MailTlsImap { get; set; }
        public string? MailTlsPop { get; set; }
    }

    // Transport: MTA‑STS
    public sealed class MtastsSection
    {
        public string Status { get; set; } = "-";
        public string Mode { get; set; } = "-";
        public int? MaxAge { get; set; }
        public bool DnsRecordPresent { get; set; }
        public bool PolicyValid { get; set; }
        public bool MxAligned { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    // Transport: TLS‑RPT
    public sealed class TlsRptSection
    {
        public string Status { get; set; } = "-";
        public int RuaCount { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    // Reputation: DNSBL
    public sealed class DnsblSection
    {
        public string Status { get; set; } = "-";
        public int ProvidersChecked { get; set; }
        public int HostsChecked { get; set; }
        public int HostsListed { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    // DNS: NS / SOA / CAA / DNSSEC
    public sealed class NsSection { public string Status { get; set; } = "-"; public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }
    public sealed class SoaSection { public string Status { get; set; } = "-"; public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }
    public sealed class CaaSection { public string Status { get; set; } = "-"; public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }
    public sealed class DnssecSection { public string Status { get; set; } = "-"; public bool HasDs { get; set; } public bool Validates { get; set; } public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }
    public sealed class DaneSection { public string Status { get; set; } = "-"; public string? TlsaUsage { get; set; } public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }

    // Mail TLS (SMTP/IMAP/POP3)
    public sealed class MailTlsSection
    {
        public sealed class Row { public string Service { get; set; } = string.Empty; public string Status { get; set; } = "-"; public string? Protocol { get; set; } }
        public List<Row> Rows { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    // Mail Transport Posture (rollup: MX + MailTLS + MTA-STS + TLS-RPT + DANE)
    public sealed class MailTransportPostureSection
    {
        public string Status { get; set; } = "-";
        public int WarningCount { get; set; }
        public int ErrorCount { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    // Other
    public sealed class RpkiSection { public string Status { get; set; } = "-"; public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }
    public sealed class ZoneTransferSection { public string Status { get; set; } = "-"; public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }
    public sealed class WildcardSection { public string Status { get; set; } = "-"; public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }

    // Discovery: Subdomains (CT-backed)
    public sealed class SubdomainsSection
    {
        public sealed class Row
        {
            public string Name { get; set; } = string.Empty;
            public string FirstSeenUtc { get; set; } = string.Empty;
            public string LastSeenUtc { get; set; } = string.Empty;
            public string Resolution { get; set; } = string.Empty;
        }

        public string Status { get; set; } = "-";
        public bool QuerySucceeded { get; set; }
        public int SubdomainCount { get; set; }
        public int CertificateObservationCount { get; set; }
        public int DistinctIssuerCount { get; set; }
        public bool ResolutionReduced { get; set; }
        public bool ResultsCapped { get; set; }
        public string? FailureReason { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<Row> Rows { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    public sealed class TyposquattingSection
    {
        public sealed class CampaignRow
        {
            public string Label { get; set; } = string.Empty;
            public string Severity { get; set; } = string.Empty;
            public int CampaignScore { get; set; }
            public int CandidateCount { get; set; }
            public int ActiveCount { get; set; }
            public int ReachableWebCount { get; set; }
            public int ThreatListedCount { get; set; }
            public int LikelyMaliciousCount { get; set; }
            public int LikelyImpersonationCount { get; set; }
            public int LikelyImpersonatingCount { get; set; }
            public int LikelyVisualCloneCount { get; set; }
            public int HighestRiskScore { get; set; }
            public string TopCandidateDomain { get; set; } = string.Empty;
            public string TopCandidateDisposition { get; set; } = string.Empty;
            public string Summary { get; set; } = string.Empty;
            public string PivotSummary { get; set; } = string.Empty;
            public string PrimaryRegistrar { get; set; } = string.Empty;
            public int RegistrarConcentrationPercent { get; set; }
            public string PrimaryHostingProvider { get; set; } = string.Empty;
            public int HostingConcentrationPercent { get; set; }
            public string PrimaryCountry { get; set; } = string.Empty;
            public int CountryConcentrationPercent { get; set; }
            public string PrimaryAbuseContact { get; set; } = string.Empty;
            public int ActionabilityScore { get; set; }
            public string Actionability { get; set; } = string.Empty;
            public string ActionabilitySummary { get; set; } = string.Empty;
            public string RecommendedAction { get; set; } = string.Empty;
        }

        public sealed class Row
        {
            public string Domain { get; set; } = string.Empty;
            public string Kind { get; set; } = string.Empty;
            public int EditDistance { get; set; }
            public bool Resolves { get; set; }
            public bool AppearsRegistered { get; set; }
            public int RiskScore { get; set; }
            public string RiskLevel { get; set; } = string.Empty;
            public string RiskSummary { get; set; } = string.Empty;
            public string Disposition { get; set; } = string.Empty;
            public string DispositionSummary { get; set; } = string.Empty;
            public string InfrastructureClusterLabel { get; set; } = string.Empty;
            public int InfrastructureClusterSize { get; set; }
            public string InfrastructureClusterSummary { get; set; } = string.Empty;
            public int ACount { get; set; }
            public int AaaaCount { get; set; }
            public int NsCount { get; set; }
            public int MxCount { get; set; }
            public string Registrar { get; set; } = string.Empty;
            public int? HttpStatusCode { get; set; }
            public bool ThreatListed { get; set; }
            public int TechnologyCount { get; set; }
            public int EnrichedIpCount { get; set; }
            public bool LikelyOwned { get; set; }
            public int OwnershipConfidence { get; set; }
            public string OwnershipSummary { get; set; } = string.Empty;
            public bool LikelyExternal { get; set; }
            public int ExternalConfidence { get; set; }
            public string ExternalSummary { get; set; } = string.Empty;
            public int ContentSimilarityScore { get; set; }
            public bool LikelyImpersonating { get; set; }
            public string ContentSimilaritySummary { get; set; } = string.Empty;
            public int VisualSimilarityScore { get; set; }
            public bool LikelyVisualClone { get; set; }
            public int? VisualSimilarityDistance { get; set; }
            public string VisualMatchKind { get; set; } = string.Empty;
            public string VisualMatchType { get; set; } = string.Empty;
            public string VisualMatchedSourceUrl { get; set; } = string.Empty;
            public string VisualCandidateArtifactUrl { get; set; } = string.Empty;
            public string VisualSimilaritySummary { get; set; } = string.Empty;
            public string EnrichmentSummary { get; set; } = string.Empty;
        }

        public string Status { get; set; } = "-";
        public int CandidateCount { get; set; }
        public int ActiveCount { get; set; }
        public int RegisteredCount { get; set; }
        public int EnrichedCount { get; set; }
        public int ReachableWebCount { get; set; }
        public int ThreatListedCount { get; set; }
        public int HighRiskCount { get; set; }
        public int LikelyOwnedCount { get; set; }
        public int LikelyExternalCount { get; set; }
        public bool OwnershipProfileBuilt { get; set; }
        public int LikelyImpersonatingCount { get; set; }
        public bool ContentProfileBuilt { get; set; }
        public int LikelyVisualCloneCount { get; set; }
        public bool VisualProfileBuilt { get; set; }
        public int ClusteredCandidateCount { get; set; }
        public int InfrastructureClusterCount { get; set; }
        public int MultiCandidateInfrastructureClusterCount { get; set; }
        public int LargestInfrastructureClusterSize { get; set; }
        public int HighPriorityCampaignCount { get; set; }
        public int CriticalCampaignCount { get; set; }
        public int AvailableCount { get; set; }
        public int DefensiveOwnedDispositionCount { get; set; }
        public int MonitorCount { get; set; }
        public int LikelyImpersonationDispositionCount { get; set; }
        public int LikelyMaliciousCount { get; set; }
        public bool ContainsHomoglyphs { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<CampaignRow> Campaigns { get; } = new();
        public List<Row> Rows { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    // Discovery: DNS Inventory (common record types)
    public sealed class DnsInventorySection
    {
        public sealed class Row
        {
            public DnsClientX.DnsRecordType QueryType { get; set; }
            public DomainDetective.DnsInventorySection Section { get; set; }
            public DnsClientX.DnsRecordType RecordType { get; set; }
            public string Name { get; set; } = string.Empty;
            public int Ttl { get; set; }
            public string Data { get; set; } = string.Empty;
        }

        public string Status { get; set; } = "-";
        public bool QuerySucceeded { get; set; }
        public int RecordTypesQueried { get; set; }
        public int RecordTypesFailed { get; set; }
        public int TotalRecords { get; set; }
        public bool IncludeAuthorities { get; set; }
        public bool IncludeAdditional { get; set; }
        public string? FailureReason { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<Row> Rows { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    // Discovery: DNS Trace (iterative root-to-answer)
    public sealed class DnsTraceSection
    {
        public sealed class Row
        {
            public DnsClientX.DnsRecordType TraceType { get; set; }
            public DomainDetective.DnsTraceStepKind Kind { get; set; }
            public int Depth { get; set; }
            public string Server { get; set; } = string.Empty;
            public string Name { get; set; } = string.Empty;
            public DnsClientX.DnsRecordType RecordType { get; set; }
            public DnsClientX.DnsResponseCode ResponseStatus { get; set; }
            public int Answers { get; set; }
            public int Authorities { get; set; }
            public int Additional { get; set; }
            public int RttMs { get; set; }
            public string CnameTarget { get; set; } = string.Empty;
            public string NextServers { get; set; } = string.Empty;
        }

        public string Status { get; set; } = "-";
        public bool TraceSucceeded { get; set; }
        public string? FailureReason { get; set; }
        public int TraceQueries { get; set; }
        public int TraceQueriesFailed { get; set; }
        public int TotalSteps { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<Row> Rows { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    // Discovery: Certificate Transparency (CT) Timeline
    public sealed class CtTimelineSection
    {
        public sealed class BucketRow
        {
            public string Month { get; set; } = string.Empty;
            public int Certificates { get; set; }
            public int Issuers { get; set; }
        }

        public sealed class RecentRow
        {
            public string EntryUtc { get; set; } = string.Empty;
            public string NotAfterUtc { get; set; } = string.Empty;
            public string Issuer { get; set; } = string.Empty;
            public string CommonName { get; set; } = string.Empty;
            public CtCertificateValidityStatus Validity { get; set; }
            public bool Wildcard { get; set; }
        }

        public string Status { get; set; } = "-";
        public bool QuerySucceeded { get; set; }
        public bool ResultsCapped { get; set; }
        public string? FailureReason { get; set; }
        public int Observations { get; set; }
        public int UniqueCertificates { get; set; }
        public int ActiveCertificates { get; set; }
        public int ExpiredCertificates { get; set; }
        public int NotYetValidCertificates { get; set; }
        public int WildcardCertificates { get; set; }
        public int IssuedLast7Days { get; set; }
        public int IssuedLast30Days { get; set; }
        public string FirstSeenUtc { get; set; } = "-";
        public string LastSeenUtc { get; set; } = "-";
        public int DistinctIssuers { get; set; }
        public string TopIssuers { get; set; } = "-";
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<BucketRow> Timeline { get; } = new();
        public List<RecentRow> RecentCertificates { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    // Web: HTTP (headers + basic posture)
    public sealed class HttpSection
    {
        public sealed class HeaderRow
        {
            public string Name { get; set; } = string.Empty;
            public string Value { get; set; } = string.Empty;
        }

        public string Status { get; set; } = "-";
        public bool IsReachable { get; set; }
        public int? StatusCode { get; set; }
        public string? FailureReason { get; set; }
        public string? EffectiveUrl { get; set; }
        public HttpRequestMethod Method { get; set; }
        public bool TlsValidationDisabled { get; set; }
        public string? ProxyUsed { get; set; }
        public bool HstsPresent { get; set; }
        public bool Http2Supported { get; set; }
        public bool Http3Supported { get; set; }
        public bool CspFrameAncestorsPresent { get; set; }
        public int MissingSecurityHeaderCount { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<HeaderRow> PresentSecurityHeaders { get; } = new();
        public List<string> MissingSecurityHeaders { get; } = new();
        public List<HeaderRow> InformationDisclosureHeaders { get; } = new();
        public List<HeaderRow> CachingHeaders { get; } = new();
        public List<string> DeprecatedPresent { get; } = new();
        public List<string> DeprecatedMissing { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    public sealed class Microsoft365Section
    {
        public sealed class ServiceRow
        {
            public string Service { get; set; } = string.Empty;
            public string Status { get; set; } = "-";
            public string Confidence { get; set; } = "-";
            public string Evidence { get; set; } = string.Empty;
        }

        public sealed class DomainRow
        {
            public string Domain { get; set; } = string.Empty;
            public string Role { get; set; } = string.Empty;
            public string Confidence { get; set; } = "-";
            public string Evidence { get; set; } = string.Empty;
        }

        public sealed class SubdomainRow
        {
            public string Name { get; set; } = string.Empty;
            public string Role { get; set; } = string.Empty;
            public string Resolution { get; set; } = string.Empty;
        }

        public sealed class ApplicationRow
        {
            public string Name { get; set; } = string.Empty;
            public string Category { get; set; } = string.Empty;
            public string EvidenceKind { get; set; } = string.Empty;
            public string Confidence { get; set; } = "-";
            public string Evidence { get; set; } = string.Empty;
        }

        public sealed class EvidenceRow
        {
            public string Label { get; set; } = string.Empty;
            public string Category { get; set; } = string.Empty;
            public string Confidence { get; set; } = "-";
            public string Evidence { get; set; } = string.Empty;
        }

        public string Status { get; set; } = "-";
        public bool IsMicrosoft365Tenant { get; set; }
        public string DetectionConfidence { get; set; } = "-";
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
        public List<string> Highlights { get; } = new();
        public List<ServiceRow> Services { get; } = new();
        public List<DomainRow> Domains { get; } = new();
        public List<SubdomainRow> Subdomains { get; } = new();
        public List<ApplicationRow> Applications { get; } = new();
        public List<EvidenceRow> Evidence { get; } = new();
    }

}
