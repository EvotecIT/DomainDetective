using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// Builds storage-free portfolio snapshots from DomainDetective analysis results.
/// </summary>
public static partial class DomainPortfolioSnapshotBuilder {
    /// <summary>
    /// Builds a portfolio snapshot from a populated <see cref="DomainHealthCheck"/>.
    /// </summary>
    /// <param name="subject">Domain or host represented by the snapshot.</param>
    /// <param name="healthCheck">Health check that contains analysis results.</param>
    /// <param name="checks">Optional subset of checks to include.</param>
    /// <param name="capturedAtUtc">Optional capture time. Defaults to the current UTC time.</param>
    /// <returns>Storage-free portfolio snapshot.</returns>
    public static DomainPortfolioSnapshot Build(
        string subject,
        DomainHealthCheck healthCheck,
        IEnumerable<HealthCheckType>? checks = null,
        DateTimeOffset? capturedAtUtc = null) {
        if (string.IsNullOrWhiteSpace(subject)) throw new ArgumentException("Subject is required.", nameof(subject));
        if (healthCheck == null) throw new ArgumentNullException(nameof(healthCheck));

        var selected = checks != null
            ? new HashSet<HealthCheckType>(checks)
            : null;

        var snapshot = new DomainPortfolioSnapshot {
            Subject = subject.Trim(),
            CapturedAtUtc = capturedAtUtc?.ToUniversalTime() ?? DateTimeOffset.UtcNow,
            EvaluatorVersion = typeof(DomainHealthCheck).Assembly.GetName().Version?.ToString() ?? string.Empty
        };

        var analyses = GetSelectedAnalyses(healthCheck, selected)
            .Where(static item => item.Value != null)
            .OrderBy(static item => item.Key.ToString(), StringComparer.OrdinalIgnoreCase)
            .Select(static pair => BuildSection(pair.Key, pair.Value!))
            .Where(static section => section.Facts.Count != 0 || section.Assessments.Count != 0);

        foreach (var section in analyses) {
            snapshot.Sections.Add(section);
            snapshot.Assessments.AddRange(section.Assessments);
        }

        snapshot.Summaries = BuildSummaries(snapshot);
        return snapshot;
    }

    private static IEnumerable<KeyValuePair<HealthCheckType, object?>> GetSelectedAnalyses(
        DomainHealthCheck healthCheck,
        HashSet<HealthCheckType>? selected) {
        if (selected == null) {
            return healthCheck.GetAnalysisMap();
        }

        if (selected.Count == 0) {
            return Array.Empty<KeyValuePair<HealthCheckType, object?>>();
        }

        return selected.Select(check => new KeyValuePair<HealthCheckType, object?>(check, healthCheck.GetAnalysisFor(check)));
    }

    /// <summary>
    /// Builds typed high-value summary projections from snapshot sections.
    /// </summary>
    /// <param name="snapshot">Snapshot with populated sections.</param>
    /// <returns>Typed summary projections.</returns>
    public static DomainPortfolioSummaries BuildSummaries(DomainPortfolioSnapshot snapshot) {
        if (snapshot == null) throw new ArgumentNullException(nameof(snapshot));

        var facts = new SnapshotFactLookup(snapshot);
        return new DomainPortfolioSummaries {
            Registration = BuildRegistrationSummary(snapshot, facts),
            Dns = BuildDnsSummary(facts),
            Certificate = BuildCertificateSummary(snapshot, facts),
            Mail = BuildMailSummary(facts),
            Website = BuildWebsiteSummary(facts)
        };
    }

    /// <summary>
    /// Builds a portfolio snapshot from this health check.
    /// </summary>
    /// <param name="healthCheck">Health check that contains analysis results.</param>
    /// <param name="subject">Domain or host represented by the snapshot.</param>
    /// <param name="checks">Optional subset of checks to include.</param>
    /// <param name="capturedAtUtc">Optional capture time. Defaults to the current UTC time.</param>
    /// <returns>Storage-free portfolio snapshot.</returns>
    public static DomainPortfolioSnapshot ToPortfolioSnapshot(
        this DomainHealthCheck healthCheck,
        string subject,
        IEnumerable<HealthCheckType>? checks = null,
        DateTimeOffset? capturedAtUtc = null)
        => Build(subject, healthCheck, checks, capturedAtUtc);

    private static DomainPortfolioSection BuildSection(HealthCheckType check, object analysis) {
        var assessments = analysis is IHasAssessments hasAssessments
            ? hasAssessments.Assessments.Where(static item => item != null).ToList()
            : new List<Assessment>();

        var section = new DomainPortfolioSection {
            Key = check.ToString(),
            DisplayName = ResolveDisplayName(check),
            Area = ResolveArea(check),
            Assessments = assessments
        };

        section.WarningCount = assessments.Count(static item => item.Severity == AssessmentSeverity.Warning);
        section.ErrorCount = assessments.Count(static item => item.Severity == AssessmentSeverity.Error);
        section.Status = section.ErrorCount > 0 ? "Error" : section.WarningCount > 0 ? "Warning" : "OK";
        section.Facts.AddRange(ExtractFacts(analysis));
        return section;
    }

    private static string ResolveDisplayName(HealthCheckType check) {
        var description = CheckDescriptions.Get(check);
        var summary = description?.Summary;
        if (!string.IsNullOrWhiteSpace(summary)) return summary!.Trim();
        return check.ToString();
    }

    internal static string ResolveArea(HealthCheckType check)
        => check switch {
            HealthCheckType.NS or
            HealthCheckType.DELEGATION or
            HealthCheckType.SOA or
            HealthCheckType.EDNSSUPPORT or
            HealthCheckType.REVERSEDNS or
            HealthCheckType.FCRDNS or
            HealthCheckType.DNSSEC or
            HealthCheckType.CAA or
            HealthCheckType.TTL or
            HealthCheckType.WILDCARDDNS or
            HealthCheckType.ZONETRANSFER or
            HealthCheckType.DNSHEALTH or
            HealthCheckType.APEXADDRESS or
            HealthCheckType.SUBDOMAINS or
            HealthCheckType.DNSINVENTORY or
            HealthCheckType.DNSTRACE or
            HealthCheckType.DNSPROPAGATION or
            HealthCheckType.DNSAMPLIFICATION or
            HealthCheckType.DNSOVERTLS => "DNS",
            HealthCheckType.MX or
            HealthCheckType.SPF or
            HealthCheckType.DKIM or
            HealthCheckType.DMARC or
            HealthCheckType.BIMI or
            HealthCheckType.MTASTS or
            HealthCheckType.TLSRPT or
            HealthCheckType.STARTTLS or
            HealthCheckType.SMTPTLS or
            HealthCheckType.IMAPTLS or
            HealthCheckType.POP3TLS or
            HealthCheckType.SMTPAUTH or
            HealthCheckType.SMTPBANNER or
            HealthCheckType.MAILLATENCY or
            HealthCheckType.SMIMEA or
            HealthCheckType.AUTODISCOVER or
            HealthCheckType.OPENRELAY or
            HealthCheckType.SPFFLATTENED or
            HealthCheckType.FLATTENINGSERVICE or
            HealthCheckType.MAILCLASSIFICATION or
            HealthCheckType.MESSAGEHEADER or
            HealthCheckType.ARC => "Mail",
            HealthCheckType.RDAP or
            HealthCheckType.WHOIS => "Registration",
            HealthCheckType.HTTP or
            HealthCheckType.CERT or
            HealthCheckType.DANE or
            HealthCheckType.SECURITYTXT or
            HealthCheckType.ROBOTS or
            HealthCheckType.HPKP or
            HealthCheckType.DIRECTORYEXPOSURE or
            HealthCheckType.WEBSITE or
            HealthCheckType.CTTIMELINE => "Web",
            HealthCheckType.IDENTITYPROVIDER or
            HealthCheckType.CONTACT or
            HealthCheckType.MICROSOFT365 => "Identity",
            HealthCheckType.RPKI or
            HealthCheckType.DNSBL or
            HealthCheckType.OPENRESOLVER or
            HealthCheckType.DANGLINGCNAME or
            HealthCheckType.SNMP or
            HealthCheckType.NTP or
            HealthCheckType.TYPOSQUATTING or
            HealthCheckType.THREATINTEL or
            HealthCheckType.THREATFEED or
            HealthCheckType.IPNEIGHBOR or
            HealthCheckType.IPENRICHMENT or
            HealthCheckType.PORTSCAN or
            HealthCheckType.PORTAVAILABILITY or
            HealthCheckType.DNSTUNNELING => "Security",
            _ => "General"
        };
}
