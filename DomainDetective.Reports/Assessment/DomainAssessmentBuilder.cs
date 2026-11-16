using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>Options for <see cref="DomainAssessmentBuilder"/>.</summary>
public sealed class DomainAssessmentOptions {
    /// <summary>Report title.</summary>
    public string? Title { get; set; }

    /// <summary>Domain order: alphabetical (default) or order of first appearance in the input.</summary>
    public DomainOrder DomainOrder { get; set; } = DomainOrder.Alphabetical;

    /// <summary>Maximum rows or items kept per evidence block. Defaults to 500.</summary>
    public int MaxEvidenceRows { get; set; } = 500;

    /// <summary>Time recorded as the generation time. Defaults to now.</summary>
    public DateTimeOffset? GeneratedAtUtc { get; set; }

    /// <summary>
    /// Skips inputs that do not name a domain instead of listing them in
    /// <see cref="DomainAssessmentReport.UnassignedInputs"/>. Useful when converting every check of a health check,
    /// where checks that did not run have no subject.
    /// </summary>
    public bool IgnoreInputsWithoutDomain { get; set; }
}

/// <summary>
/// Builds a <see cref="DomainAssessmentReport"/> from DomainDetective view objects (the output of
/// <c>DomainDetective.Views.Converters.Convert(...)</c>), the same input every composition renderer takes.
/// </summary>
public static class DomainAssessmentBuilder {
    /// <summary>Builds the assessment for the given views.</summary>
    /// <param name="items">View objects, optionally nested in lists.</param>
    /// <param name="options">Optional settings.</param>
    /// <returns>The assessment report.</returns>
    public static DomainAssessmentReport Build(IReadOnlyList<object> items, DomainAssessmentOptions? options = null) {
        options ??= new DomainAssessmentOptions();
        int maxRows = Math.Max(1, options.MaxEvidenceRows);
        var report = new DomainAssessmentReport {
            Title = string.IsNullOrWhiteSpace(options.Title) ? "Domain assessment" : options.Title!.Trim(),
            GeneratedAtUtc = options.GeneratedAtUtc ?? DateTimeOffset.UtcNow
        };

        var domains = new Dictionary<string, DomainAssessment>(StringComparer.OrdinalIgnoreCase);
        var firstSeen = new List<string>();
        var leftovers = new List<(string Domain, AssessmentEvidenceInfo Info)>();
        foreach (object item in CompositionUtilities.Flatten(items ?? Array.Empty<object>())) {
            // Findings no check view carried belong to the check they name; they are placed once every check exists.
            if (item is AssessmentEvidenceInfo evidenceInfo) {
                string? owner = NormalizeDomain(evidenceInfo.Subject);
                if (owner == null) continue;
                if (!domains.ContainsKey(owner)) {
                    domains[owner] = new DomainAssessment { Domain = owner };
                    firstSeen.Add(owner);
                }
                leftovers.Add((owner, evidenceInfo));
                continue;
            }
            if (item is DomainDetective.Views.DomainRiskProfileInfo riskProfile) {
                string? profileDomain = NormalizeDomain(riskProfile.Subject);
                if (profileDomain == null) continue;
                if (!domains.TryGetValue(profileDomain, out DomainAssessment? owner)) {
                    owner = new DomainAssessment { Domain = profileDomain };
                    domains[profileDomain] = owner;
                    firstSeen.Add(profileDomain);
                }
                owner.RiskProfile = riskProfile.Profile;
                continue;
            }
            DomainAssessmentViewReader reader = DomainAssessmentViewReader.For(item.GetType());
            string? domain = reader.IsView ? NormalizeDomain(reader.Subject(item)) : null;
            if (domain == null) {
                if (!options.IgnoreInputsWithoutDomain) report.UnassignedInputs.Add(item.GetType().Name);
                continue;
            }
            if (!domains.TryGetValue(domain, out DomainAssessment? assessment)) {
                assessment = new DomainAssessment { Domain = domain };
                domains[domain] = assessment;
                firstSeen.Add(domain);
            }
            AddView(assessment, item, reader);
        }

        IEnumerable<string> order = options.DomainOrder == DomainOrder.Alphabetical
            ? firstSeen.OrderBy(static d => d, StringComparer.OrdinalIgnoreCase)
            : firstSeen;
        foreach (var (owner, info) in leftovers) {
            if (!domains.TryGetValue(owner, out DomainAssessment? target)) continue;
            PlaceLeftovers(target, info);
        }
        foreach (string name in order) {
            DomainAssessment domain = domains[name];
            foreach (CheckAssessment check in domain.Checks) Finish(check, maxRows);
            Score(domain);
            report.Domains.Add(domain);
        }

        int[] scores = report.Domains.Where(static d => d.Score.HasValue).Select(static d => d.Score!.Value).ToArray();
        report.Score = scores.Length == 0 ? null : (int)Math.Round(scores.Average(), MidpointRounding.AwayFromZero);
        report.Coverage = DomainAssessmentCatalog.ScoreCoverage(report.Domains.SelectMany(static d => d.Checks));
        report.Grade = DomainAssessmentCatalog.GradeFor(report.Score);
        return report;
    }

    /// <summary>Normalizes a view subject (domain, host or URL) to the domain it belongs to.</summary>
    internal static string? NormalizeDomain(string? subject) {
        if (string.IsNullOrWhiteSpace(subject)) return null;
        string value = subject!.Trim();
        if (Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) && !string.IsNullOrEmpty(uri.Host) && value.IndexOf("://", StringComparison.Ordinal) > 0) {
            value = uri.Host;
        }
        value = value.TrimEnd('.').ToLowerInvariant();
        // Some views describe something other than a domain (ARC reports "Message Headers"); they have no domain.
        if (value.Length == 0 || value.Any(char.IsWhiteSpace)) return null;
        return value;
    }

    private static void AddView(DomainAssessment domain, object view, DomainAssessmentViewReader reader) {
        HealthCheckType? kind = reader.Check(view);
        // Views built by hand (for example in PowerShell) often leave Check at its default, DMARC; the view type then
        // tells which check it is. A non-DMARC view whose type names no check is kept as its own, unnamed check.
        if (kind == default(HealthCheckType) && view is not DomainDetective.Views.CheckFailureInfo &&
            !view.GetType().Name.StartsWith("Dmarc", StringComparison.OrdinalIgnoreCase)) {
            kind = InferCheck(view.GetType());
        }
        AnalysisArea area = reader.Area(view) ?? AnalysisArea.General;
        if (area == AnalysisArea.General && kind.HasValue) area = DomainDetective.Views.Converters.AreaFor(kind.Value);
        string key = kind?.ToString().ToLowerInvariant() ?? KeyFromType(view.GetType());
        (string Key, string Title, AnalysisArea Area) described = default;
        if (!kind.HasValue && DescriptiveViews.TryGetValue(view.GetType().Name, out described)) {
            key = described.Key;
            area = described.Area;
        }
        CheckAssessment? check = domain.Checks.FirstOrDefault(c => c.Key == key);
        if (check == null) {
            (string title, string? longTitle) = kind.HasValue ? DomainAssessmentCatalog.TitleFor(kind.Value)
                : described.Title != null ? (described.Title, null)
                : (DomainAssessmentViewReader.Humanize(key), null);
            CheckDescription? description = kind.HasValue ? CheckDescriptions.Get(kind.Value) : null;
            check = new CheckAssessment {
                Key = key,
                Check = kind,
                Title = title,
                LongTitle = longTitle,
                Description = description?.Summary,
                Remediation = description?.Remediation,
                Area = area,
                // Views that name no check (aggregates such as DomainOverallInfo, time series) describe, not grade.
                Scored = kind.HasValue && DomainAssessmentCatalog.IsScored(kind.Value),
                Weight = kind.HasValue ? DomainAssessmentCatalog.WeightFor(kind.Value) : 1
            };
            if (!string.IsNullOrWhiteSpace(description?.RfcLink)) check.References.Add(description!.RfcLink!);
            domain.Checks.Add(check);
        }
        check.Sources.Add(view);
    }

    // Views that describe history rather than one check (imported reports, drift over time); informational, but named.
    private static readonly Dictionary<string, (string Key, string Title, AnalysisArea Area)> DescriptiveViews = new(StringComparer.Ordinal) {
        ["DmarcAggregateTimeSeriesInfo"] = ("dmarc-reports", "DMARC aggregate reports", AnalysisArea.Mail),
        ["TlsRptReportsTimeSeriesInfo"] = ("tlsrpt-reports", "TLS-RPT reports", AnalysisArea.Mail),
        ["RegistrationDriftInfo"] = ("registration-drift", "Registration changes", AnalysisArea.Security),
        ["DesiredStateInfo"] = (DesiredStateAreaModule.Key, "Desired state", AnalysisArea.General)
    };

    // View types whose name does not spell their check.
    private static readonly Dictionary<string, HealthCheckType> AliasedViews = new(StringComparer.Ordinal) {
        ["Microsoft365TenantInfo"] = HealthCheckType.MICROSOFT365
    };

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<Type, HealthCheckType?> InferredChecks = new();

    /// <summary>Check named by a view type: <c>SpfRecordInfo</c> is SPF, <c>MxInfo</c> is MX, <c>WildcardDnsInfo</c> is WILDCARDDNS.</summary>
    private static HealthCheckType? InferCheck(Type type) => InferredChecks.GetOrAdd(type, static t => {
        if (AliasedViews.TryGetValue(t.Name, out HealthCheckType aliased)) return aliased;
        string key = KeyFromType(t);
        foreach (string candidate in new[] { key, Strip(key, "record"), Strip(key, "status"), Strip(Strip(key, "record"), "status") }) {
            if (Enum.TryParse(candidate, ignoreCase: true, out HealthCheckType check) && Enum.IsDefined(typeof(HealthCheckType), check)) return check;
        }
        return null;

        static string Strip(string value, string suffix)
            => value.Length > suffix.Length && value.EndsWith(suffix, StringComparison.Ordinal) ? value.Substring(0, value.Length - suffix.Length) : value;
    });

    private static string KeyFromType(Type type) {
        string name = type.Name;
        foreach (string suffix in new[] { "Info", "Summary", "View" }) {
            if (name.Length > suffix.Length && name.EndsWith(suffix, StringComparison.Ordinal)) {
                name = name.Substring(0, name.Length - suffix.Length);
                break;
            }
        }
        return name.ToLowerInvariant();
    }

    private static void Finish(CheckAssessment check, int maxRows) {
        var perSourceFacts = new List<List<CheckFact>>();
        var genericEvidence = new List<CheckEvidence>();
        foreach (object view in check.Sources) {
            DomainAssessmentViewReader reader = DomainAssessmentViewReader.For(view.GetType());
            check.EvidenceComplete &= reader.EvidenceComplete(view);
            foreach (Assessment assessment in reader.Assessments(view)) {
                if (string.IsNullOrWhiteSpace(assessment.Message)) continue;
                check.Findings.Add(new CheckFinding {
                    Severity = assessment.Severity,
                    IsEvidenceGap = DomainAssessmentViewReader.IsEvidenceGap(view, assessment),
                    Code = assessment.Code,
                    Message = assessment.Message.Trim(),
                    Target = assessment.Target
                });
            }
            AddDistinct(check.Positives, reader.Positives(view).Select(static p => string.IsNullOrWhiteSpace(p.Title) ? p.Code : p.Title));
            AddDistinct(check.Highlights, reader.Highlights(view));
            AddDistinct(check.References, reader.References(view));
            foreach (RecommendationAdvice advice in reader.Recommendations(view)) {
                if (check.Recommendations.Any(r => string.Equals(r.Code, advice.Code, StringComparison.OrdinalIgnoreCase) && string.Equals(r.Title, advice.Title, StringComparison.Ordinal))) continue;
                check.Recommendations.Add(ToGuidance(advice));
            }
            check.Summary ??= NullIfEmpty(reader.Summary(view));
            check.Narrative ??= DomainAssessmentNarratives.Resolve(view, reader);

            var facts = new List<CheckFact>();
            reader.ReadDetails(view, null, facts, genericEvidence, maxRows);
            perSourceFacts.Add(facts);
        }

        // A curated module replaces the generic property listing with the numbers and evidence that matter for the
        // check; checks without one (or with views the module does not know) keep the generic reading.
        IAssessmentAreaModule? module = AssessmentAreaModules.For(check);
        if (module != null && module.Describe(check, maxRows)) {
            perSourceFacts.Clear();
        } else {
            check.Evidence.AddRange(genericEvidence);
        }

        if (perSourceFacts.Count == 1) {
            check.Facts.AddRange(perSourceFacts[0]);
        } else if (perSourceFacts.Count > 1) {
            // Several results for one check (DKIM selectors, propagation servers): one row per result.
            var columns = perSourceFacts.SelectMany(static f => f).Select(static f => f.Label).Distinct(StringComparer.Ordinal).ToList();
            var table = new CheckEvidence { Title = check.Title + " results", Kind = CheckEvidenceKind.Table };
            table.Columns.AddRange(columns);
            foreach (List<CheckFact> facts in perSourceFacts) {
                table.Rows.Add(columns.Select(column => facts.FirstOrDefault(f => f.Label == column)?.Value ?? string.Empty).ToList());
            }
            check.Evidence.Insert(0, table);
        }

        // The same finding is often raised once per target and once without one; show it once with its targets.
        check.Findings = check.Findings
            .GroupBy(static f => (f.Severity, f.Code, f.Message, f.IsEvidenceGap))
            .Select(static g => new CheckFinding {
                Severity = g.Key.Severity,
                IsEvidenceGap = g.Key.IsEvidenceGap,
                Code = g.Key.Code,
                Message = g.Key.Message,
                Target = JoinTargets(g.Select(static f => f.Target))
            })
            .OrderByDescending(static f => f.Severity)
            .ToList();
        // Checks that only gather data (inventory, enrichment, discovery) never fail the domain: a lookup error in them is
        // missing evidence, not a finding about the domain.
        // A probe or lookup that did not finish says nothing about the domain: it is a check that couldn't run, shown in
        // grey, counted against confidence and kept out of the warnings and the things to fix.
        // SPF and DMARC decide this from the record itself: a failed include lookup behind a published record is a defect.
        bool ownGapRule = check.Check is HealthCheckType.SPF or HealthCheckType.DMARC;
        foreach (CheckFinding finding in check.Findings.Where(f => !ownGapRule && !f.IsEvidenceGap && f.Severity >= AssessmentSeverity.Warning && DescribesFailedLookup(f))) {
            finding.IsEvidenceGap = true;
            check.EvidenceComplete = false;
        }
        check.ErrorCount = check.Findings.Count(static f => !f.IsEvidenceGap && f.Severity == AssessmentSeverity.Error);
        check.WarningCount = check.Findings.Count(static f => !f.IsEvidenceGap && f.Severity == AssessmentSeverity.Warning);
        // Some views report counts without the individual assessments; the outcome must still reflect them.
        if (check.ErrorCount == 0 && check.WarningCount == 0 && !check.Findings.Any(static f => f.Severity >= AssessmentSeverity.Warning)) {
            foreach (object view in check.Sources) {
                DomainAssessmentViewReader reader = DomainAssessmentViewReader.For(view.GetType());
                if (check.Check.HasValue && DomainAssessmentCatalog.GathersData(check.Check.Value)) continue;
                check.ErrorCount += Math.Max(0, reader.ErrorCount(view) - reader.Assessments(view).Count(a => a.Severity == AssessmentSeverity.Error && DomainAssessmentViewReader.IsEvidenceGap(view, a)));
                check.WarningCount += Math.Max(0, reader.WarningCount(view) - reader.Assessments(view).Count(a => a.Severity == AssessmentSeverity.Warning && DomainAssessmentViewReader.IsEvidenceGap(view, a)));
            }
        }
        // No CAA record at all means any certificate authority may issue: report that plainly, neither as a pass that
        // implies an issuer restriction nor as a failure.
        if (check.Check == HealthCheckType.CAA && check.ErrorCount == 0 && check.WarningCount == 0 && check.EvidenceComplete
            && check.Sources.OfType<DomainDetective.Views.CaaInfo>().Any()
            && check.Sources.OfType<DomainDetective.Views.CaaInfo>().All(static v => v.ValidRecords == 0 && v.InvalidRecords == 0)) {
            check.Scored = false;
            check.Summary = AssessmentReportWording.NoCaaPolicy;
        }
        // What a data-gathering check notices (a missing PTR, a short CT history) is context for the profile, not a fix
        // for the domain. Lookalike domains and exposed subdomains are the exceptions: they are something to act on.
        if (check.Check.HasValue && DomainAssessmentCatalog.GathersData(check.Check.Value)
            && check.Check is not (HealthCheckType.TYPOSQUATTING or HealthCheckType.SUBDOMAINS)) {
            check.WarningCount = 0;
        }
        check.Outcome = check.ErrorCount > 0 ? CheckOutcome.Error
            : check.WarningCount > 0 ? CheckOutcome.Warning
            : !check.EvidenceComplete ? CheckOutcome.Incomplete
            : check.Scored ? CheckOutcome.Pass
            : CheckOutcome.Info;
        check.Score = check.EvidenceComplete ? DomainAssessmentCatalog.ScoreFor(check.ErrorCount, check.WarningCount) : null;
    }

    /// <summary>
    /// Orders a domain's checks and recomputes its score, grade, counts and area scores from them. Used when checks of
    /// different runs are combined, for example a monitoring run that refreshed some checks and kept the last results
    /// of the others.
    /// </summary>
    /// <param name="domain">Domain whose <see cref="DomainAssessment.Checks"/> are complete.</param>
    public static void Rescore(DomainAssessment domain) {
        if (domain == null) throw new ArgumentNullException(nameof(domain));
        Score(domain);
    }

    private static void Score(DomainAssessment domain) {
        domain.Checks = domain.Checks
            .OrderBy(static c => AreaIndex(c.Area))
            .ThenBy(static c => CanonicalIndex(c))
            .ThenBy(static c => c.Title, StringComparer.OrdinalIgnoreCase)
            .ToList();
        domain.Score = WeightedScore(domain.Checks);
        domain.Coverage = DomainAssessmentCatalog.ScoreCoverage(domain.Checks);
        domain.Grade = DomainAssessmentCatalog.GradeFor(domain.Score);
        domain.ErrorChecks = domain.Checks.Count(static c => c.Outcome == CheckOutcome.Error);
        domain.WarningChecks = domain.Checks.Count(static c => c.Outcome == CheckOutcome.Warning);
        domain.PassedChecks = domain.Checks.Count(static c => c.Outcome == CheckOutcome.Pass);
        domain.Areas = domain.Checks
            .GroupBy(static c => c.Area)
            .OrderBy(static g => AreaIndex(g.Key))
            .Select(static g => new AreaScore {
                Area = g.Key,
                Score = WeightedScore(g),
                Coverage = DomainAssessmentCatalog.ScoreCoverage(g),
                Incomplete = g.Where(static c => c.Scored && !c.EvidenceComplete).Select(static c => c.Title).ToList(),
                Checks = g.Count(),
                Attention = g.Count(static c => c.Outcome is CheckOutcome.Error or CheckOutcome.Warning)
            })
            .ToList();
    }

    private static int? WeightedScore(IEnumerable<CheckAssessment> checks) => DomainAssessmentCatalog.CombinedScore(checks);

    private static HealthCheckType? CategoryCheck(string category) {
        if (category.Length == 0) return null;
        if (string.Equals(category, "Certificate", StringComparison.OrdinalIgnoreCase)) return HealthCheckType.CERT;
        return Enum.TryParse(category.Replace(" ", string.Empty).Replace("-", string.Empty), true, out HealthCheckType kind) && Enum.IsDefined(typeof(HealthCheckType), kind)
            ? kind : null;
    }

    // Markers of a lookup or probe that did not finish. They name the acquisition, not the record, so an observed defect
    // ("missing glue", "key could not be validated") never matches.
    private static readonly string[] FailedLookupCodes = { "QueryFailed", "Query.Failed", "ProbeFailed", "Probe.Failed", "LookupFailed", "Lookup.Failed", "Timeout", "Unreachable", "NotChecked" };

    private static readonly string[] FailedLookupPhrases = {
        "query failed", "probe failed", "lookup failed", "request failed", "timed out", "query did not complete",
        "did not complete; ", "was not checked", "error response", "query budget exhausted", "check failed for"
    };

    // A finding that reports a lookup or probe that did not finish, rather than something found about the domain.
    private static bool DescribesFailedLookup(CheckFinding finding) {
        string code = finding.Code ?? string.Empty;
        string message = finding.Message ?? string.Empty;
        foreach (string marker in FailedLookupCodes) {
            if (code.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0) return true;
        }
        foreach (string marker in FailedLookupPhrases) {
            if (message.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0) return true;
        }
        return false;
    }

    /// <summary>
    /// Adds findings no check view carried to the check their category names. When that check has no view of its own,
    /// it is created under its real name and area (unscored, since only part of its evidence arrived); findings whose
    /// category names no check go to "Additional findings".
    /// </summary>
    private static void PlaceLeftovers(DomainAssessment domain, AssessmentEvidenceInfo info) {
        foreach (Assessment assessment in info.Assessments) {
            if (string.IsNullOrWhiteSpace(assessment.Message)) continue;
            string category = (assessment.Category ?? string.Empty).Trim();
            HealthCheckType? kind = CategoryCheck(category);
            string key = kind?.ToString().ToLowerInvariant() ?? "additional-findings";
            CheckAssessment? check = domain.Checks.FirstOrDefault(c => c.Key == key);
            // An informational note on its own is not worth a check of its own.
            if (check == null && assessment.Severity == AssessmentSeverity.Info) continue;
            if (check == null) {
                (string title, string? longTitle) = kind.HasValue ? DomainAssessmentCatalog.TitleFor(kind.Value) : ("Additional findings", null);
                check = new CheckAssessment {
                    Key = key, Check = kind, Title = title, LongTitle = longTitle,
                    Area = kind.HasValue ? DomainDetective.Views.Converters.AreaFor(kind.Value) : AnalysisArea.General,
                    Scored = false
                };
                domain.Checks.Add(check);
            }
            if (check.Findings.Any(f => f.Code == assessment.Code && f.Message == assessment.Message.Trim())) continue;
            check.Findings.Add(new CheckFinding {
                Severity = assessment.Severity, Code = assessment.Code, Message = assessment.Message.Trim(), Target = assessment.Target
            });
        }
    }

    private static int AreaIndex(AnalysisArea area) {
        int index = -1;
        for (int i = 0; i < DomainAssessmentCatalog.AreaOrder.Count; i++) {
            if (DomainAssessmentCatalog.AreaOrder[i] == area) index = i;
        }
        return index < 0 ? int.MaxValue : index;
    }

    private static int CanonicalIndex(CheckAssessment check) {
        string? section = check.Check.HasValue ? SectionOrdering.SectionKeyFor(check.Check.Value) : null;
        if (section == null) return int.MaxValue;
        for (int i = 0; i < SectionOrdering.CanonicalSections.Count; i++) {
            if (string.Equals(SectionOrdering.CanonicalSections[i], section, StringComparison.OrdinalIgnoreCase)) return i;
        }
        return int.MaxValue;
    }

    private static CheckGuidance ToGuidance(RecommendationAdvice advice) {
        var guidance = new CheckGuidance {
            Code = NullIfEmpty(advice.Code),
            Title = string.IsNullOrWhiteSpace(advice.Title) ? advice.Code : advice.Title,
            Why = NullIfEmpty(advice.Why),
            How = NullIfEmpty(advice.How),
            Impact = NullIfEmpty(advice.Impact),
            Effort = advice.Effort.ToString(),
            Verify = NullIfEmpty(advice.Verify)
        };
        guidance.Links.AddRange(advice.Links.Where(static l => !string.IsNullOrWhiteSpace(l)));
        return guidance;
    }

    private static void AddDistinct(List<string> target, IEnumerable<string?> values) {
        foreach (string? value in values) {
            if (string.IsNullOrWhiteSpace(value)) continue;
            string trimmed = value!.Trim();
            if (!target.Contains(trimmed, StringComparer.OrdinalIgnoreCase)) target.Add(trimmed);
        }
    }

    private static string? JoinTargets(IEnumerable<string?> targets) {
        var distinct = targets.Where(static t => !string.IsNullOrWhiteSpace(t)).Select(static t => t!.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return distinct.Count == 0 ? null : string.Join(", ", distinct);
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value!.Trim();
}
