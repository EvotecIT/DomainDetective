using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.TimeSeries.Registration;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static RegistrationDriftInfo Convert(IReadOnlyList<RegistrationSnapshot> snapshots, string? subjectOverride = null)
    {
        var list = (snapshots ?? Array.Empty<RegistrationSnapshot>())
            .Where(s => s != null)
            .OrderBy(s => s.CapturedAtUtc)
            .ToList();

        var subject = !string.IsNullOrWhiteSpace(subjectOverride)
            ? subjectOverride!
            : (list.LastOrDefault()?.Domain ?? string.Empty);

        var current = list.LastOrDefault();
        var previous = list.Count > 1 ? list[list.Count - 2] : null;
        var drift = (previous != null && current != null)
            ? RegistrationDriftDetector.Compute(previous, current)
            : null;

        var assessments = new List<Assessment>();

        if (current == null)
        {
            assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Code = "Registration.NoData",
                Category = "Registration",
                Target = subject,
                Message = "No registration snapshots were found for this domain."
            });
        }
        else
        {
            if (!current.HasRdap && !current.HasWhois)
            {
                assessments.Add(new Assessment
                {
                    Severity = AssessmentSeverity.Warning,
                    Code = "Registration.Source.Missing",
                    Category = "Registration",
                    Target = subject,
                    Message = "Neither RDAP nor WHOIS data was available for this registration snapshot."
                });
            }

            AddExpiryAssessments(subject, current, assessments);

            if (drift != null && previous != null)
            {
                if (drift.Changes.Count == 0)
                {
                    assessments.Add(new Assessment
                    {
                        Severity = AssessmentSeverity.Info,
                        Code = "Registration.Drift.None",
                        Category = "Registration",
                        Target = subject,
                        Message = "No registration drift detected since the previous snapshot."
                    });
                }
                else
                {
                    foreach (var c in drift.Changes)
                    {
                        AddChangeAssessment(subject, previous, current, c, assessments);
                    }
                }
            }
        }

        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);

        return new RegistrationDriftInfo
        {
            SectionKey = "Registration",
            Area = AreaForKind(HealthCheckType.WHOIS),
            Subject = subject,
            SnapshotCount = list.Count,
            Current = current,
            Previous = previous,
            Drift = drift,
            Snapshots = list,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = BuildSummary(current, drift),
            Recommendations = recs,
            Positives = positives,
            References = new[]
            {
                "https://www.rfc-editor.org/rfc/rfc7483",
                "https://www.rfc-editor.org/rfc/rfc3912"
            }
        };
    }

    private static void AddExpiryAssessments(string subject, RegistrationSnapshot current, List<Assessment> assessments)
    {
        if (current.ExpiresAtUtc.HasValue)
        {
            var exp = current.ExpiresAtUtc.Value;
            var delta = exp - current.CapturedAtUtc;
            if (delta <= TimeSpan.Zero)
            {
                assessments.Add(new Assessment
                {
                    Severity = AssessmentSeverity.Error,
                    Code = "Registration.Expiry.Expired",
                    Category = "Registration",
                    Target = subject,
                    Message = $"Registration expiry appears to be in the past (on {exp.UtcDateTime:yyyy-MM-dd})."
                });
            }
            else if (delta <= TimeSpan.FromDays(30))
            {
                assessments.Add(new Assessment
                {
                    Severity = AssessmentSeverity.Warning,
                    Code = "Registration.Expiry.Soon",
                    Category = "Registration",
                    Target = subject,
                    Message = $"Registration expires in {Math.Ceiling(delta.TotalDays)} days (on {exp.UtcDateTime:yyyy-MM-dd})."
                });
            }
            return;
        }

        if (!string.IsNullOrWhiteSpace(current.ExpiresAtRaw))
        {
            assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Code = "Registration.Expiry.Unparsed",
                Category = "Registration",
                Target = subject,
                Message = $"Registration expiration date could not be parsed (raw: {TrimForDisplay(current.ExpiresAtRaw, 80)})."
            });
        }
    }

    private static void AddChangeAssessment(string subject, RegistrationSnapshot previous, RegistrationSnapshot current, RegistrationChange change, List<Assessment> assessments)
    {
        if (change == null)
        {
            return;
        }

        switch (change.Kind)
        {
            case RegistrationChangeKind.RegistrarChanged:
                assessments.Add(new Assessment
                {
                    Severity = AssessmentSeverity.Warning,
                    Code = "Registration.Drift.RegistrarChanged",
                    Category = "Registration",
                    Target = subject,
                    Message = $"Registrar changed from '{change.Before ?? "?"}' to '{change.After ?? "?"}' since the previous snapshot."
                });
                break;
            case RegistrationChangeKind.RegistrarIdChanged:
                assessments.Add(new Assessment
                {
                    Severity = AssessmentSeverity.Warning,
                    Code = "Registration.Drift.RegistrarIdChanged",
                    Category = "Registration",
                    Target = subject,
                    Message = $"Registrar ID changed from '{change.Before ?? "?"}' to '{change.After ?? "?"}' since the previous snapshot."
                });
                break;
            case RegistrationChangeKind.ExpiresAtChanged:
                AddExpiryChangeAssessment(subject, previous, current, change, assessments);
                break;
            case RegistrationChangeKind.NameServersChanged:
                assessments.Add(new Assessment
                {
                    Severity = AssessmentSeverity.Warning,
                    Code = "Registration.Drift.NameServersChanged",
                    Category = "Registration",
                    Target = subject,
                    Message = BuildListChangeMessage("Name servers changed", change)
                });
                break;
            case RegistrationChangeKind.StatusChanged:
                assessments.Add(new Assessment
                {
                    Severity = AssessmentSeverity.Warning,
                    Code = "Registration.Drift.StatusChanged",
                    Category = "Registration",
                    Target = subject,
                    Message = BuildListChangeMessage("RDAP status changed", change)
                });
                break;
            case RegistrationChangeKind.RegistrarLockedChanged:
                assessments.Add(new Assessment
                {
                    Severity = (string.Equals(change.After, "true", StringComparison.OrdinalIgnoreCase))
                        ? AssessmentSeverity.Info
                        : AssessmentSeverity.Warning,
                    Code = "Registration.Drift.RegistrarLockedChanged",
                    Category = "Registration",
                    Target = subject,
                    Message = $"Registrar lock changed from '{change.Before ?? "?"}' to '{change.After ?? "?"}' since the previous snapshot."
                });
                break;
            case RegistrationChangeKind.WhoisAvailabilityChanged:
            case RegistrationChangeKind.RdapAvailabilityChanged:
                if (string.Equals(change.After, "false", StringComparison.OrdinalIgnoreCase))
                {
                    assessments.Add(new Assessment
                    {
                        Severity = AssessmentSeverity.Warning,
                        Code = "Registration.Drift.SourceDegraded",
                        Category = "Registration",
                        Target = subject,
                        Message = $"{change.Kind} (now unavailable)."
                    });
                }
                break;
            default:
                break;
        }
    }

    private static void AddExpiryChangeAssessment(string subject, RegistrationSnapshot previous, RegistrationSnapshot current, RegistrationChange change, List<Assessment> assessments)
    {
        var prev = previous.ExpiresAtUtc;
        var cur = current.ExpiresAtUtc;
        if (!prev.HasValue || !cur.HasValue)
        {
            assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Code = "Registration.Drift.ExpiryChanged",
                Category = "Registration",
                Target = subject,
                Message = $"Registration expiration changed from '{change.Before ?? "?"}' to '{change.After ?? "?"}' since the previous snapshot."
            });
            return;
        }

        var deltaDays = (cur.Value - prev.Value).TotalDays;
        if (deltaDays >= 1)
        {
            assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Code = "Registration.Drift.ExpiryExtended",
                Category = "Registration",
                Target = subject,
                Message = $"Registration expiration extended by {Math.Round(deltaDays, 0, MidpointRounding.AwayFromZero).ToString(CultureInfo.InvariantCulture)} days (now {cur.Value.UtcDateTime:yyyy-MM-dd})."
            });
        }
        else if (deltaDays <= -1)
        {
            assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Code = "Registration.Drift.ExpiryShortened",
                Category = "Registration",
                Target = subject,
                Message = $"Registration expiration shortened by {Math.Round(Math.Abs(deltaDays), 0, MidpointRounding.AwayFromZero).ToString(CultureInfo.InvariantCulture)} days (now {cur.Value.UtcDateTime:yyyy-MM-dd})."
            });
        }
        else
        {
            assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Code = "Registration.Drift.ExpiryAdjusted",
                Category = "Registration",
                Target = subject,
                Message = $"Registration expiration updated (now {cur.Value.UtcDateTime:yyyy-MM-dd})."
            });
        }
    }

    private static string BuildListChangeMessage(string prefix, RegistrationChange change)
    {
        var parts = new List<string> { prefix };
        if (change.Added != null && change.Added.Count > 0)
        {
            parts.Add($"+{string.Join(", ", change.Added.Take(6))}{(change.Added.Count > 6 ? ", …" : string.Empty)}");
        }
        if (change.Removed != null && change.Removed.Count > 0)
        {
            parts.Add($"-{string.Join(", ", change.Removed.Take(6))}{(change.Removed.Count > 6 ? ", …" : string.Empty)}");
        }
        return string.Join(": ", parts);
    }

    private static string TrimForDisplay(string? value, int maxLen)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }
        var t = value!.Trim();
        if (t.Length <= maxLen)
        {
            return t;
        }
        return t.Substring(0, Math.Max(0, maxLen - 1)) + "…";
    }

    private static string BuildSummary(RegistrationSnapshot? current, RegistrationDrift? drift)
    {
        if (current == null)
        {
            return "no snapshots";
        }

        var registrar = string.IsNullOrWhiteSpace(current.Registrar) ? "?" : current.Registrar!.Trim();
        var expiry = current.ExpiresAtUtc.HasValue
            ? current.ExpiresAtUtc.Value.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
            : (string.IsNullOrWhiteSpace(current.ExpiresAtRaw) ? "?" : TrimForDisplay(current.ExpiresAtRaw, 24));
        var changes = drift?.Changes?.Count ?? 0;

        return $"registrar {registrar}; expires {expiry}; changes {changes}";
    }
}

public sealed class RegistrationDriftInfo
{
    public string SectionKey { get; set; } = "Registration";
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = string.Empty;

    public int SnapshotCount { get; set; }
    public RegistrationSnapshot? Current { get; set; }
    public RegistrationSnapshot? Previous { get; set; }
    public RegistrationDrift? Drift { get; set; }
    public IReadOnlyList<RegistrationSnapshot> Snapshots { get; set; } = Array.Empty<RegistrationSnapshot>();

    public IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    public string Status { get; set; } = "OK";
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = Array.Empty<string>();
}
