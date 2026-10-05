using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Views;
using static DomainDetective.Reports.AreaText;

namespace DomainDetective.Reports;

/// <summary>Microsoft 365: whether the domain belongs to a tenant, how sign-in is exposed, and which workloads run there.</summary>
internal sealed class Microsoft365AreaModule : IAssessmentAreaModule {
    public IReadOnlyList<HealthCheckType> Checks { get; } = new[] { HealthCheckType.MICROSOFT365 };

    public bool Describe(CheckAssessment check, int maxRows) {
        Microsoft365TenantInfo? info = check.Sources.OfType<Microsoft365TenantInfo>().FirstOrDefault();
        if (info == null || SectionProjectors.BuildMicrosoft365(info) is not { } section) return false;
        if (!info.IsMicrosoft365Tenant) {
            check.Metrics.Add(Metric("Tenant", "Not detected", MetricState.Neutral));
            Fact(check, "Problem", info.FailureReason);
            return true;
        }

        check.Metrics.Add(Metric("Tenant", "Detected", MetricState.Neutral, section.DetectionConfidence + " confidence"));
        int detected = section.Services.Count(static s => s.Status == "Detected");
        check.Metrics.Add(Metric("Detected workloads", N(detected)));
        check.Metrics.Add(Metric("User enumeration", Value(section, "User Enumeration"), Exposure(info.UserEnumerationStatus)));
        check.Metrics.Add(Metric("Smart lockout", Value(section, "Smart Lockout")));

        foreach (string label in new[] { "Tenant Name", "Tenant Namespace Domain", "Company", "Tenant ID", "Domain Type", "Identity Provider",
                     "Federation", "Cloud Instance", "Region", "Auth Path", "Throttling", "Accepted Domains", "Domain Evidence" }) {
            string value = Value(section, label);
            if (value != "-" && value != "Unknown") Fact(check, label, value);
        }

        Table(check, "Microsoft 365 workloads", new[] { "Workload", "Status", "Confidence", "Observed via", "Evidence" },
            (info.Services ?? Array.Empty<Microsoft365ServiceDetection>()).Zip(section.Services, (service, row) => (IReadOnlyList<string?>)new[] {
                row.Service, row.Status, row.Confidence,
                service.Status == Microsoft365DetectionStatus.Detected ? ExecutiveSummaryBuilder.FormatMicrosoft365WorkloadEvidenceSource(service.EvidenceSource) : "-",
                row.Evidence
            }), maxRows);
        Table(check, "Tenant domains", new[] { "Domain", "Role", "Confidence", "Evidence" },
            section.Domains.Select(static d => (IReadOnlyList<string?>)new[] { d.Domain, d.Role, d.Confidence, d.Evidence }), maxRows);
        Table(check, "Known subdomains", new[] { "Name", "Role", "Resolution" },
            section.Subdomains.Select(static s => (IReadOnlyList<string?>)new[] { s.Name, s.Role, s.Resolution }), maxRows);
        Table(check, "DNS applications", new[] { "Application", "Category", "Evidence kind", "Confidence", "Evidence" },
            section.Applications.Select(static a => (IReadOnlyList<string?>)new[] { a.Name, a.Category, a.EvidenceKind, a.Confidence, a.Evidence }), maxRows);
        Table(check, "Evidence", new[] { "Signal", "Category", "Confidence", "Evidence" },
            section.Evidence.Select(static e => (IReadOnlyList<string?>)new[] { e.Label, e.Category, e.Confidence, e.Evidence }), maxRows);
        return true;
    }

    private static string Value(SectionProjectors.Microsoft365Section section, string label)
        => section.Summary.FirstOrDefault(s => s.Key == label).Value ?? "-";

    private static MetricState Exposure(Microsoft365AuthExposureStatus status)
        => status == Microsoft365AuthExposureStatus.Exposed ? MetricState.Warning : MetricState.Neutral;
}

/// <summary>Desired state: how the domain compares with the state its owner declared, and with best practice.</summary>
internal sealed class DesiredStateAreaModule : IAssessmentAreaModule {
    /// <summary>Desired state names no check; the builder files it under <see cref="Key"/>.</summary>
    internal const string Key = "desired-state";

    public IReadOnlyList<HealthCheckType> Checks { get; } = Array.Empty<HealthCheckType>();

    public bool Describe(CheckAssessment check, int maxRows) {
        DesiredStateInfo? info = check.Sources.OfType<DesiredStateInfo>().FirstOrDefault();
        if (info == null || SectionProjectors.BuildDesiredState(info) is not { } section) return false;

        check.Metrics.Add(Metric("Conforms", YesNo(section.Conforms), section.Conforms ? MetricState.Good : MetricState.Error));
        check.Metrics.Add(Metric("Desired errors", N(section.DesiredErrorCount), section.DesiredErrorCount > 0 ? MetricState.Error : MetricState.Good));
        check.Metrics.Add(Metric("Desired warnings", N(section.DesiredWarningCount), section.DesiredWarningCount > 0 ? MetricState.Warning : MetricState.Good));
        if (!section.IsBaselineOnly) {
            check.Metrics.Add(Metric("Best-practice errors", N(section.BestPracticeErrorCount), section.BestPracticeErrorCount > 0 ? MetricState.Error : MetricState.Good));
            check.Metrics.Add(Metric("Best-practice warnings", N(section.BestPracticeWarningCount), section.BestPracticeWarningCount > 0 ? MetricState.Warning : MetricState.Good));
        }
        Fact(check, "Mode", FormatMode(info.Mode));

        // Departures from the declared state are this check's findings; best-practice gaps stay evidence, because the
        // checks they come from (SPF, DMARC, ...) already report them.
        foreach (Assessment assessment in info.DesiredAssessments ?? Array.Empty<Assessment>()) {
            if (assessment == null || assessment.Severity == AssessmentSeverity.Info || string.IsNullOrWhiteSpace(assessment.Message)) continue;
            if (check.Findings.Any(f => f.Code == assessment.Code && f.Message == assessment.Message.Trim())) continue;
            check.Findings.Add(new CheckFinding { Severity = assessment.Severity, Code = assessment.Code, Message = assessment.Message.Trim(), Target = assessment.Target });
        }

        Table(check, "Best-practice findings", new[] { "Severity", "Code", "Target", "Finding" },
            section.BestPracticeFindings.Select(static f => (IReadOnlyList<string?>)new[] { f.Severity, f.Code, f.Target, f.Message }), maxRows);
        List(check, "Best practice met", section.BestPracticePositives, maxRows);
        return true;
    }

    private static string FormatMode(DomainDetective.DesiredState.DesiredStateMode mode)
        => System.Text.RegularExpressions.Regex.Replace(mode.ToString(), "([a-z])([A-Z])", "$1 $2");
}
