using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Narratives;
using OfficeIMO.Markdown;

namespace DomainDetective.Reports.Markdown;

public static partial class MarkdownCompositionReport
{
    // Extracted per-domain writer to keep the core file lean and under 500 lines.
    private static void WritePerDomain(MarkdownDoc md, List<KeyValuePair<string, DomainBucket>> domains, OrderingOptions? ordering, Dictionary<string, List<string>> inputSectionOrder)
    {
        var mode = ordering?.SectionOrderMode ?? SectionOrderMode.Canonical;
        var custom = SectionOrdering.NormalizeSectionList(ordering?.SectionOrder ?? Array.Empty<string>());

        foreach (var kv in domains)
        {
            var d = kv.Key;
            var b = kv.Value;
            md.H1(d).H2("Overview").Table(t => t.Headers("Key","Value")
                .Row("Domain", d)
                .Row("Classification", b.Classification?.Classification ?? "-")
                .Row("Confidence", b.Classification?.Confidence ?? "-")
                .Row("Status", ComputeStatus(b))
                .Row("Warnings", ((b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + (b.Microsoft365?.WarningCount ?? 0) + (b.Typosquatting?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount)).ToString())
                .Row("Errors", ((b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + (b.Microsoft365?.ErrorCount ?? 0) + (b.Typosquatting?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount)).ToString())
                .AlignLeft(0,1));

            void RenderClassification()
            {
                var cls = b.Classification;
                if (cls == null) return;
                var narrative = cls.Raw != null ? MailClassificationNarrative.Build(cls.Raw) : null;
                md.H2("Classification");
                md.Table(t => t.Headers("Key","Value")
                    .Row("Classification", cls.Classification ?? "-")
                    .Row("Confidence", cls.Confidence ?? "-")
                    .Row("Score", cls.Score.ToString("0.##"))
                    .Row("Status", cls.Status ?? "-")
                    .Row("Primary Provider", cls.ProviderPrimary ?? "-")
                    .Row("Gateways", cls.ProviderGateways != null && cls.ProviderGateways.Count > 0 ? string.Join(", ", cls.ProviderGateways) : "-")
                    .Row("Outbound", cls.ProviderOutbound != null && cls.ProviderOutbound.Count > 0 ? string.Join(", ", cls.ProviderOutbound) : "-")
                    .AlignLeft(0,1));

                if (cls.ScoreBreakdown != null && cls.ScoreBreakdown.Count > 0)
                {
                    md.H3("Score Breakdown").Table(t => t.Headers("Metric","Value")
                        .Rows(cls.ScoreBreakdown.Select(kv2 => (IReadOnlyList<string>)new[]{ kv2.Key, kv2.Value.ToString("0.##") }))
                        .AlignLeft(0).AlignRight(1));
                }

                if (cls.ReceivingSignals != null && cls.ReceivingSignals.Count > 0)
                {
                    md.H3("Receiving Signals").Ul(cls.ReceivingSignals.ToArray());
                }
                if (cls.SendingSignals != null && cls.SendingSignals.Count > 0)
                {
                    md.H3("Sending Signals").Ul(cls.SendingSignals.ToArray());
                }
                var clsFind = (cls.Assessments ?? Array.Empty<DomainDetective.Assessment>())
                    .Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                    .Select(a => (IReadOnlyList<string>)new[]
                    {
                        a.Severity.ToString(),
                        a.Code ?? string.Empty,
                        a.Target ?? string.Empty,
                        a.Message ?? string.Empty
                    })
                    .ToList();
                if (clsFind.Count > 0)
                {
                    md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message")
                        .Rows(clsFind)
                        .AlignLeft(0,1,2,3));
                }

                RenderNarrative(md, narrative);
                var raw = cls.Raw;
                bool hasEvidence = raw != null
                    && (!string.IsNullOrWhiteSpace(raw.ClassificationReason)
                        || (raw.SPFIncludesResolved?.Count ?? 0) > 0
                        || (raw.DKIMSelectorsFound?.Count ?? 0) > 0
                        || raw.BimiEligible.HasValue
                        || (raw.BimiNotes?.Count ?? 0) > 0
                        || !string.IsNullOrWhiteSpace(raw.IdpTenantId)
                        || !string.IsNullOrWhiteSpace(raw.IdpNameSpaceType)
                        || !string.IsNullOrWhiteSpace(raw.IdpFederatedAuthUrl));
                if (hasEvidence && raw != null)
                {
                    md.H3("Evidence");
                    if (!string.IsNullOrWhiteSpace(raw.ClassificationReason))
                    {
                        md.P(p => p.Bold("Reason: ").Text(raw.ClassificationReason));
                    }
                    if (raw.SPFIncludesResolved != null && raw.SPFIncludesResolved.Count > 0)
                    {
                        md.H4("SPF Includes");
                        md.Ul(raw.SPFIncludesResolved.ToArray());
                    }
                    if (raw.DKIMSelectorsFound != null && raw.DKIMSelectorsFound.Count > 0)
                    {
                        md.H4("DKIM Selectors");
                        md.Ul(raw.DKIMSelectorsFound.ToArray());
                    }
                    if (raw.BimiEligible.HasValue)
                    {
                        md.P(p => p.Bold("BIMI eligibility: ").Text(raw.BimiEligible.Value ? "Eligible" : "Not eligible"));
                    }
                    if (!string.IsNullOrWhiteSpace(raw.BimiEligibilityReason))
                    {
                        md.P(p => p.Bold("BIMI note: ").Text(raw.BimiEligibilityReason!));
                    }
                    if (raw.BimiNotes != null && raw.BimiNotes.Count > 0)
                    {
                        md.H4("BIMI Notes");
                        md.Ul(raw.BimiNotes.ToArray());
                    }
                    if (!string.IsNullOrWhiteSpace(raw.IdpTenantId)
                        || !string.IsNullOrWhiteSpace(raw.IdpNameSpaceType)
                        || !string.IsNullOrWhiteSpace(raw.IdpFederatedAuthUrl))
                    {
                        md.H4("Identity Hints");
                        var idp = new List<string>();
                        if (!string.IsNullOrWhiteSpace(raw.IdpTenantId)) idp.Add($"Tenant: {raw.IdpTenantId}");
                        if (!string.IsNullOrWhiteSpace(raw.IdpNameSpaceType)) idp.Add($"Namespace: {raw.IdpNameSpaceType}");
                        if (!string.IsNullOrWhiteSpace(raw.IdpFederatedAuthUrl)) idp.Add($"Federation URL: {raw.IdpFederatedAuthUrl}");
                        if (idp.Count > 0) md.Ul(idp.ToArray());
                    }
                }

                if (cls.Recommendations?.Count > 0)
                    md.H3("Recommendations").Ul(cls.Recommendations.Select(r => r.Title ?? r.Code).ToArray());
                if (cls.Positives?.Count > 0)
                    md.H3("Positives").Ul(cls.Positives.Select(r => r.Title ?? r.Code).ToArray());
                RenderReferences(md, MergeReferences(cls.References, narrative?.References));
            }

            void RenderMicrosoft365()
            {
                if (b.Microsoft365 == null)
                {
                    return;
                }

                if (SectionProjectors.BuildMicrosoft365(b.Microsoft365) is not { } sec)
                {
                    return;
                }

                md.H2("Microsoft 365");
                md.Table(t => { t.Headers("Key", "Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0, 1); });
                if (sec.Highlights.Count > 0)
                {
                    md.H3("Highlights").Ul(sec.Highlights.ToArray());
                }
                if (sec.Positives.Count > 0)
                {
                    md.H3("Positives").Ul(sec.Positives.ToArray());
                }
                if (sec.Findings.Count > 0)
                {
                    var findingRows = sec.Findings.Select(a => (IReadOnlyList<string>)new[] { a.Severity, a.Code, a.Target, a.Message }).ToList();
                    md.H3("Findings").Table(t => t.Headers("Severity", "Code", "Target", "Message").Rows(findingRows).AlignLeft(0, 1, 2, 3));
                }
                if (sec.Services.Count > 0)
                {
                    var rows = sec.Services.Select(x => (IReadOnlyList<string>)new[] { x.Service, x.Status, x.Confidence, x.Evidence }).ToList();
                    md.H3("Services").Table(t => t.Headers("Service", "Status", "Confidence", "Evidence").Rows(rows).AlignLeft(0, 1, 2, 3));
                }
                if (sec.Domains.Count > 0)
                {
                    var rows = sec.Domains.Select(x => (IReadOnlyList<string>)new[] { x.Domain, x.Role, x.Confidence, x.Evidence }).ToList();
                    md.H3("Tenant Domains").Table(t => t.Headers("Domain", "Role", "Confidence", "Evidence").Rows(rows).AlignLeft(0, 1, 2, 3));
                }
                if (sec.Subdomains.Count > 0)
                {
                    var rows = sec.Subdomains.Select(x => (IReadOnlyList<string>)new[] { x.Name, x.Role, x.Resolution }).ToList();
                    md.H3("Known Subdomains").Table(t => t.Headers("Name", "Role", "Resolution").Rows(rows).AlignLeft(0, 1, 2));
                }
                if (sec.Applications.Count > 0)
                {
                    var rows = sec.Applications.Select(x => (IReadOnlyList<string>)new[] { x.Name, x.Category, x.EvidenceKind, x.Confidence, x.Evidence }).ToList();
                    md.H3("Detected DNS Applications").Table(t => t.Headers("Name", "Category", "Evidence Kind", "Confidence", "Evidence").Rows(rows).AlignLeft(0, 1, 2, 3, 4));
                }
                if (sec.Evidence.Count > 0)
                {
                    var rows = sec.Evidence.Select(x => (IReadOnlyList<string>)new[] { x.Label, x.Category, x.Confidence, x.Evidence }).ToList();
                    md.H3("Evidence Ledger").Table(t => t.Headers("Label", "Category", "Confidence", "Evidence").Rows(rows).AlignLeft(0, 1, 2, 3));
                }
                RenderReferences(md, sec.References);
            }

            void RenderTyposquatting()
            {
                if (b.Typosquatting == null)
                {
                    return;
                }

                var sec = SectionProjectors.BuildTyposquatting(b.Typosquatting);
                var narrative = b.Typosquatting.Raw != null ? TyposquattingNarrative.Build(b.Typosquatting.Raw) : null;
                md.H2("Typosquatting");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key", "Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0, 1); });
                    if (sec.Positives.Count > 0)
                    {
                        md.H3("Positives").Ul(sec.Positives.ToArray());
                    }
                    if (sec.Findings.Count > 0)
                    {
                        var findingRows = sec.Findings.Select(a => (IReadOnlyList<string>)new[] { a.Severity, a.Code, a.Target, a.Message }).ToList();
                        md.H3("Findings").Table(t => t.Headers("Severity", "Code", "Target", "Message").Rows(findingRows).AlignLeft(0, 1, 2, 3));
                    }
                    if (b.Typosquatting.KindCounts.Count > 0)
                    {
                        var kindRows = b.Typosquatting.KindCounts
                            .Select(x => (IReadOnlyList<string>)new[] { x.Kind, x.Count.ToString() })
                            .ToList();
                        md.H3("Variant Families").Table(t => t.Headers("Kind", "Count").Rows(kindRows).AlignLeft(0, 1));
                    }
                    if (sec.Campaigns.Count > 0)
                    {
                        var campaignRows = sec.Campaigns
                            .Take(100)
                            .Select(x => (IReadOnlyList<string>)new[]
                            {
                                x.Label,
                                string.IsNullOrWhiteSpace(x.Severity) ? "-" : x.Severity,
                                x.CampaignScore.ToString(),
                                x.CandidateCount.ToString(),
                                x.ActiveCount.ToString(),
                                x.ReachableWebCount.ToString(),
                                x.ThreatListedCount.ToString(),
                                x.LikelyMaliciousCount.ToString(),
                                x.LikelyImpersonationCount.ToString(),
                                x.LikelyImpersonatingCount.ToString(),
                                x.LikelyVisualCloneCount.ToString(),
                                string.IsNullOrWhiteSpace(x.TopCandidateDomain) ? "-" : x.TopCandidateDomain,
                                string.IsNullOrWhiteSpace(x.TopCandidateDisposition) ? "-" : x.TopCandidateDisposition,
                                string.IsNullOrWhiteSpace(x.Actionability) ? "-" : $"{x.Actionability} ({x.ActionabilityScore})",
                                string.IsNullOrWhiteSpace(x.PrimaryRegistrar) ? "-" : $"{x.PrimaryRegistrar} ({x.RegistrarConcentrationPercent}%)",
                                string.IsNullOrWhiteSpace(x.PrimaryHostingProvider) ? "-" : $"{x.PrimaryHostingProvider} ({x.HostingConcentrationPercent}%)",
                                string.IsNullOrWhiteSpace(x.PrimaryCountry) ? "-" : $"{x.PrimaryCountry} ({x.CountryConcentrationPercent}%)",
                                string.IsNullOrWhiteSpace(x.PrimaryAbuseContact) ? "-" : x.PrimaryAbuseContact,
                                string.IsNullOrWhiteSpace(x.PivotSummary) ? "-" : x.PivotSummary,
                                string.IsNullOrWhiteSpace(x.ActionabilitySummary) ? "-" : x.ActionabilitySummary,
                                string.IsNullOrWhiteSpace(x.RecommendedAction) ? "-" : x.RecommendedAction,
                                string.IsNullOrWhiteSpace(x.Summary) ? "-" : x.Summary
                            })
                            .ToList();
                        md.H3("Campaigns").Table(t => t.Headers("Label", "Severity", "Score", "Domains", "Active", "Reachable", "Threat", "Malicious", "Impersonation", "Content", "Visual", "Top Domain", "Disposition", "Actionability", "Registrar", "Hosting", "Country", "Abuse", "Pivots", "Actionability Summary", "Action", "Summary").Rows(campaignRows).AlignLeft(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21));
                    }
                    if (sec.Rows.Count > 0)
                    {
                        var rows = sec.Rows
                            .Take(200)
                            .Select(x => (IReadOnlyList<string>)new[]
                            {
                                x.Domain,
                                x.RiskScore.ToString(),
                                string.IsNullOrWhiteSpace(x.RiskLevel) ? "-" : x.RiskLevel,
                                string.IsNullOrWhiteSpace(x.Disposition) ? "-" : x.Disposition,
                                string.IsNullOrWhiteSpace(x.InfrastructureClusterLabel) ? "-" : $"{x.InfrastructureClusterLabel} ({x.InfrastructureClusterSize})",
                                x.Kind,
                                x.EditDistance.ToString(),
                                x.Resolves ? "Yes" : "No",
                                x.AppearsRegistered ? "Yes" : "No",
                                x.ACount.ToString(),
                                x.AaaaCount.ToString(),
                                x.NsCount.ToString(),
                                x.MxCount.ToString(),
                                x.LikelyOwned ? $"Likely ({x.OwnershipConfidence})" : "-",
                                string.IsNullOrWhiteSpace(x.OwnershipSummary) ? "-" : x.OwnershipSummary,
                                x.LikelyExternal ? $"Likely ({x.ExternalConfidence})" : "-",
                                string.IsNullOrWhiteSpace(x.ExternalSummary) ? "-" : x.ExternalSummary,
                                x.LikelyImpersonating ? $"Likely ({x.ContentSimilarityScore})" : (x.ContentSimilarityScore > 0 ? x.ContentSimilarityScore.ToString() : "-"),
                                string.IsNullOrWhiteSpace(x.ContentSimilaritySummary) ? "-" : x.ContentSimilaritySummary,
                                x.LikelyVisualClone ? $"Likely ({x.VisualSimilarityScore})" : (x.VisualSimilarityScore > 0 ? x.VisualSimilarityScore.ToString() : "-"),
                                string.IsNullOrWhiteSpace(x.VisualMatchType) ? "-" : x.VisualMatchType,
                                x.VisualSimilarityDistance?.ToString() ?? "-",
                                string.IsNullOrWhiteSpace(x.VisualSimilaritySummary) ? "-" : x.VisualSimilaritySummary,
                                string.IsNullOrWhiteSpace(x.EnrichmentSummary) ? "-" : x.EnrichmentSummary
                            })
                            .ToList();
                        md.H3("Candidates").Table(t => t.Headers("Domain", "Score", "Risk", "Disposition", "Cluster", "Kind", "Distance", "Resolves", "Registered", "A", "AAAA", "NS", "MX", "Owned", "Ownership", "External", "Distinct", "Content", "Similarity", "Visual", "Visual Type", "Visual Diff", "Visual Summary", "Enrichment").Rows(rows).AlignLeft(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23));
                    }
                    RenderNarrative(md, narrative);
                    RenderReferences(md, MergeReferences(sec.References, narrative?.References));
                }
            }

            void RenderDesiredState()
            {
                var ds = b.DesiredState;
                if (ds == null) return;

                md.H2("Desired State");
                md.Table(t => t.Headers("Key", "Value")
                    .Row("Mode", ds.Mode.ToString())
                    .Row("Conforms", ds.Conforms ? "Yes" : "No")
                    .Row("Desired State Warnings", ds.WarningCount.ToString())
                    .Row("Desired State Errors", ds.ErrorCount.ToString())
                    .Row("Best-Practice Warnings", ds.BestPracticeWarningCount.ToString())
                    .Row("Best-Practice Errors", ds.BestPracticeErrorCount.ToString())
                    .AlignLeft(0, 1));

                md.H3("Desired State Conformance");
                if (ds.Positives != null && ds.Positives.Count > 0)
                {
                    md.H4("Good posture").Ul(ds.Positives.Select(p => p.Title ?? p.Code ?? string.Empty).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray());
                }

                var desiredFind = (ds.DesiredAssessments ?? Array.Empty<DomainDetective.Assessment>())
                    .Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                    .Select(a => (IReadOnlyList<string>)new[]
                    {
                        a.Severity.ToString(),
                        a.Code ?? string.Empty,
                        a.Target ?? string.Empty,
                        a.Message ?? string.Empty
                    })
                    .ToList();
                if (desiredFind.Count > 0)
                {
                    md.H4("Findings").Table(t => t.Headers("Severity","Code","Target","Message")
                        .Rows(desiredFind)
                        .AlignLeft(0,1,2,3));
                }
                else
                {
                    md.P("No desired state drift findings.");
                }

                if (ds.Recommendations != null && ds.Recommendations.Count > 0)
                {
                    md.H4("Recommendations").Ul(ds.Recommendations
                        .Select(r => {
                            var title = r?.Title ?? r?.Code ?? string.Empty;
                            var how = r?.How ?? string.Empty;
                            return string.IsNullOrWhiteSpace(how) ? title : $"{title}: {how}";
                        })
                        .Where(s => !string.IsNullOrWhiteSpace(s))
                        .ToArray());
                }

                if (ds.Mode != DomainDetective.DesiredState.DesiredStateMode.BaselineOnly)
                {
                    md.H3("Best-Practice Gaps");
                    if (ds.BestPracticePositives != null && ds.BestPracticePositives.Count > 0)
                    {
                        md.H4("Good posture").Ul(ds.BestPracticePositives.Select(p => p.Title ?? p.Code ?? string.Empty).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray());
                    }

                    var bestFind = (ds.BestPracticeAssessments ?? Array.Empty<DomainDetective.Assessment>())
                        .Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                        .Select(a => (IReadOnlyList<string>)new[]
                        {
                            a.Severity.ToString(),
                            a.Code ?? string.Empty,
                            a.Target ?? string.Empty,
                            a.Message ?? string.Empty
                        })
                        .ToList();
                    if (bestFind.Count > 0)
                    {
                        md.H4("Findings").Table(t => t.Headers("Severity","Code","Target","Message")
                            .Rows(bestFind)
                            .AlignLeft(0,1,2,3));
                    }
                    else
                    {
                        md.P("No best-practice findings for this mode.");
                    }

                    if (ds.BestPracticeRecommendations != null && ds.BestPracticeRecommendations.Count > 0)
                    {
                        md.H4("Recommendations").Ul(ds.BestPracticeRecommendations
                            .Select(r => {
                                var title = r?.Title ?? r?.Code ?? string.Empty;
                                var how = r?.How ?? string.Empty;
                                return string.IsNullOrWhiteSpace(how) ? title : $"{title}: {how}";
                            })
                            .Where(s => !string.IsNullOrWhiteSpace(s))
                            .ToArray());
                    }
                }

                RenderReferences(md, ds.References);
            }

            void RenderSpf()
            {
                if (b.Spf == null) return;
                var sec = SectionProjectors.BuildSpf(b.Spf);
                var narrative = b.Spf?.Narrative;
                md.H2("SPF");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Highlights.Count > 0) md.H3("Highlights").Ul(sec.Highlights.ToArray());
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var spfFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (spfFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(spfFind).AlignLeft(0,1,2,3));
                    RenderNarrative(md, narrative);
                    if (!string.IsNullOrWhiteSpace(sec.SpfRecord)) { md.H3("Evidence").P("SPF Record:"); md.Code("", sec.SpfRecord!); }
                    if (sec.Mechanisms.Count > 0) { md.H3("Mechanisms"); var mechRows = sec.Mechanisms.Select(m => (IReadOnlyList<string>)new[]{ m.Qualifier, m.Type, m.Value, m.Provider }).ToList(); md.Table(t => t.Headers("Qualifier","Type","Value","Provider").Rows(mechRows).AlignLeft(0,1,2,3)); }
                    if (sec.FlattenedUniqueIpCount + sec.FlattenedDuplicateIpCount + sec.FlattenedTokenCount > 0) { md.H3("Flattened IP Analysis"); md.Table(t => t.Headers("Metric","Value").Row("Unique IPs", sec.FlattenedUniqueIpCount.ToString()).Row("Duplicate IPs", sec.FlattenedDuplicateIpCount.ToString()).Row("Tokens Resolved", sec.FlattenedTokenCount.ToString()).AlignLeft(0,1)); }
                    if (sec.ProviderHelp.Count > 0) { md.H3("Provider Help"); md.Ul(ul => { foreach (var (title, url) in sec.ProviderHelp.Take(5)) ul.ItemLink(title, url); }); }
                    RenderReferences(md, MergeReferences(sec?.References, narrative?.References));
                }
            }

            void RenderDmarc()
            {
                if (b.Dmarc == null) return;
                var sec = SectionProjectors.BuildDmarc(b.Dmarc);
                var narrative = b.Dmarc?.Narrative;
                md.H2("DMARC");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Highlights.Count > 0) md.H3("Highlights").Ul(sec.Highlights.ToArray());
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var dmFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (dmFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dmFind).AlignLeft(0,1,2,3));
                    RenderNarrative(md, narrative);
                    if (!string.IsNullOrWhiteSpace(sec.DmarcRecord)) { md.H3("Evidence").P("DMARC Record:"); md.Code("", sec.DmarcRecord!); }
                    if (sec.MailtoRua.Count + sec.HttpRua.Count + sec.MailtoRuf.Count + sec.HttpRuf.Count > 0)
                    {
                        md.H3("Reporting URIs");
                        if (sec.MailtoRua.Count + sec.HttpRua.Count > 0)
                        {
                            md.H4("Aggregate (RUA)");
                            var rowsRua = sec.MailtoRua.Select(x => (IReadOnlyList<string>)new[]{ "mailto", x }).Concat(sec.HttpRua.Select(x => (IReadOnlyList<string>)new[]{ "http", x })).ToList();
                            md.Table(t => t.Headers("Scheme","URI").Rows(rowsRua).AlignLeft(0,1));
                        }
                        if (sec.MailtoRuf.Count + sec.HttpRuf.Count > 0)
                        {
                            md.H4("Forensic (RUF)");
                            var rowsRuf = sec.MailtoRuf.Select(x => (IReadOnlyList<string>)new[]{ "mailto", x }).Concat(sec.HttpRuf.Select(x => (IReadOnlyList<string>)new[]{ "http", x })).ToList();
                            md.Table(t => t.Headers("Scheme","URI").Rows(rowsRuf).AlignLeft(0,1));
                        }
                    }
                    RenderReferences(md, MergeReferences(sec?.References, narrative?.References));
                }
            }

            void RenderDkim()
            {
                if (b.Dkim.Count == 0) return;
                md.H2("DKIM");
                var sec = SectionProjectors.BuildDkim(b.Dkim, b.Ttl);
                var narrative = b.Dkim.FirstOrDefault()?.Narrative;
                if (sec != null)
                {
                    if (sec.Rows.Count > 0) { var dkimRows = sec.Rows.Select(x => (IReadOnlyList<string>)new[]{ x.Selector, x.Status, x.KeyBits, x.Hash, x.Weak ? "Yes" : "No", x.Flags, (x.TtlSeconds?.ToString() ?? "-"), x.CnameResolved ? "Yes" : "No", (x.CnameTtlSeconds?.ToString() ?? "-") }).ToList(); md.Table(t => t.Headers("Selector","Status","Key Bits","Alg","Weak","Flags","TTL (s)","CNAME Resolved","CNAME TTL (s)").Rows(dkimRows).AlignLeft(0,1,2,3,4,5,6,7,8)); }
                    if (sec.Highlights.Count > 0) md.H3("Highlights").Ul(sec.Highlights.ToArray());
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var dkFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (dkFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dkFind).AlignLeft(0,1,2,3));
                    RenderNarrative(md, narrative);
                    if (sec.Rows.Any(r => !string.IsNullOrWhiteSpace(r.Record))) { md.H3("Evidence"); foreach (var r in sec.Rows.Where(r => !string.IsNullOrWhiteSpace(r.Record))) { md.H4($"Selector {r.Selector}"); md.Code("", r.Record); } }
                    RenderReferences(md, MergeReferences(sec?.References, narrative?.References));
                }
            }

            void RenderMx()
            {
                if (b.Mx == null) return;
                var sec = SectionProjectors.BuildMx(b.Mx, b.SmtpTls, b.ImapTls, b.PopTls);
                var narrative = b.Mx.Raw != null ? MxNarrative.Build(b.Mx.Raw) : null;
                md.H2("MX");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Records.Count > 0) { md.H3("MX Records"); md.Table(tt => { tt.Headers("Host"); foreach (var r2 in sec.Records) tt.Row(r2); tt.AlignLeft(0); }); }
                    if (!string.IsNullOrWhiteSpace(sec.MailTlsSmtp) || !string.IsNullOrWhiteSpace(sec.MailTlsImap) || !string.IsNullOrWhiteSpace(sec.MailTlsPop)) { md.H3("MailTLS"); md.Table(t => t.Headers("Service","Status").Row("SMTP", sec.MailTlsSmtp ?? "-").Row("IMAP", sec.MailTlsImap ?? "-").Row("POP3", sec.MailTlsPop ?? "-").AlignLeft(0,1)); }
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var mxFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (mxFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(mxFind).AlignLeft(0,1,2,3));
                    RenderNarrative(md, narrative);
                    var raw = b.Mx.Raw;
                    bool hasEvidence = raw != null && ((raw.MxRecords?.Count ?? 0) > 0 || (raw.MxRecordTtls?.Count ?? 0) > 0);
                    if (hasEvidence && raw != null)
                    {
                        md.H3("Evidence");
                        if (raw.MxRecords != null && raw.MxRecords.Count > 0)
                        {
                            md.H4("MX records");
                            var records = raw.MxRecords.Where(r => !string.IsNullOrWhiteSpace(r)).ToArray();
                            if (records.Length > 0) md.Code("", string.Join(Environment.NewLine, records));
                        }
                        if (raw.MxRecordTtls != null && raw.MxRecordTtls.Count > 0)
                        {
                            md.H4("TTL (seconds)");
                            md.Code("", string.Join(", ", raw.MxRecordTtls));
                        }
                    }
                    RenderReferences(md, MergeReferences(sec?.References, narrative?.References));
                }
            }

            void RenderMtasts()
            {
                if (b.Mtasts == null) return;
                var sec = SectionProjectors.BuildMtasts(b.Mtasts);
                var narrative = MtaStsNarrative.Build(b.Mtasts.Raw, b.Mtasts.Assessments);
                md.H2("MTA-STS");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var mtFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (mtFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(mtFind).AlignLeft(0,1,2,3));
                    RenderNarrative(md, narrative);
                    var raw = b.Mtasts.Raw;
                    bool hasEvidence = raw != null
                        && (!string.IsNullOrWhiteSpace(raw.PolicyId)
                            || !string.IsNullOrWhiteSpace(raw.Policy)
                            || (raw.Mx != null && raw.Mx.Count > 0)
                            || (raw.MissingMxFromPolicy != null && raw.MissingMxFromPolicy.Count > 0));
                    if (hasEvidence && raw != null)
                    {
                        md.H3("Evidence");
                        if (!string.IsNullOrWhiteSpace(raw.PolicyId))
                        {
                            md.P("MTA-STS TXT:");
                            md.Code("", $"v=STSv1; id={raw.PolicyId}");
                        }
                        if (!string.IsNullOrWhiteSpace(raw.Policy))
                        {
                            md.P("Policy (mta-sts.txt):");
                            md.Code("", raw.Policy);
                        }
                        if (raw.Mx != null && raw.Mx.Count > 0)
                        {
                            md.H4("Policy MX Patterns");
                            md.Ul(raw.Mx.ToArray());
                        }
                        if (raw.MissingMxFromPolicy != null && raw.MissingMxFromPolicy.Count > 0)
                        {
                            md.H4("Missing MX in policy");
                            md.Ul(raw.MissingMxFromPolicy.ToArray());
                        }
                    }
                    RenderReferences(md, MergeReferences(sec?.References, narrative?.References));
                }
            }

            void RenderTlsRpt()
            {
                if (b.TlsRpt == null) return;
                var sec = SectionProjectors.BuildTlsRpt(b.TlsRpt);
                var narrative = b.TlsRpt.Raw != null ? TlsRptNarrative.Build(b.TlsRpt.Raw) : null;
                md.H2("TLS-RPT");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var trFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (trFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(trFind).AlignLeft(0,1,2,3));
                    RenderNarrative(md, narrative);
                    bool hasEvidence = !string.IsNullOrWhiteSpace(b.TlsRpt.TlsRptRecord)
                        || (b.TlsRpt.MailtoRua != null && b.TlsRpt.MailtoRua.Count > 0)
                        || (b.TlsRpt.HttpRua != null && b.TlsRpt.HttpRua.Count > 0)
                        || (b.TlsRpt.InvalidRua != null && b.TlsRpt.InvalidRua.Count > 0)
                        || (b.TlsRpt.UnknownTags != null && b.TlsRpt.UnknownTags.Count > 0);
                    if (hasEvidence)
                    {
                        md.H3("Evidence");
                        if (!string.IsNullOrWhiteSpace(b.TlsRpt.TlsRptRecord))
                        {
                            md.P("TLS-RPT Record:");
                            md.Code("", b.TlsRpt.TlsRptRecord!);
                        }
                        if ((b.TlsRpt.MailtoRua?.Count ?? 0) + (b.TlsRpt.HttpRua?.Count ?? 0) > 0)
                        {
                            md.H4("Reporting URIs");
                            var rows = (b.TlsRpt.MailtoRua ?? Array.Empty<string>())
                                .Select(x => (IReadOnlyList<string>)new[] { "mailto", x })
                                .Concat((b.TlsRpt.HttpRua ?? Array.Empty<string>())
                                    .Select(x => (IReadOnlyList<string>)new[] { "https", x }))
                                .ToList();
                            md.Table(t => t.Headers("Scheme","URI").Rows(rows).AlignLeft(0,1));
                        }
                        if (b.TlsRpt.InvalidRua != null && b.TlsRpt.InvalidRua.Count > 0)
                        {
                            md.H4("Invalid rua");
                            md.Ul(b.TlsRpt.InvalidRua.ToArray());
                        }
                        if (b.TlsRpt.UnknownTags != null && b.TlsRpt.UnknownTags.Count > 0)
                        {
                            md.H4("Unknown tags");
                            md.Ul(b.TlsRpt.UnknownTags.ToArray());
                        }
                    }
                    RenderReferences(md, MergeReferences(sec?.References, narrative?.References));
                }
            }

            void RenderMailTls()
            {
                if (b.SmtpTls == null && b.ImapTls == null && b.PopTls == null) return;
                md.H2("MailTLS");
                var narrative = b.SmtpTls?.Raw != null
                    ? MailTlsNarrative.Build(b.SmtpTls.Raw, DomainDetective.MailTlsAnalysis.MailProtocol.Smtp)
                    : b.ImapTls?.Raw != null
                        ? MailTlsNarrative.Build(b.ImapTls.Raw, DomainDetective.MailTlsAnalysis.MailProtocol.Imap)
                        : b.PopTls?.Raw != null
                            ? MailTlsNarrative.Build(b.PopTls.Raw, DomainDetective.MailTlsAnalysis.MailProtocol.Pop3)
                            : null;
                IEnumerable<(string Service, DomainDetective.Views.MailTlsInfo Info)> svc()
                {
                    if (b.SmtpTls != null) yield return ("SMTP", b.SmtpTls);
                    if (b.ImapTls != null) yield return ("IMAP", b.ImapTls);
                    if (b.PopTls != null) yield return ("POP3", b.PopTls);
                }
                var rows = new List<IReadOnlyList<string>>();
                foreach (var (service, info) in svc())
                {
                    var servers = info.Servers ?? Array.Empty<DomainDetective.Views.MailTlsServerInfo>();
                    int n = servers.Count;
                    int starttls = servers.Count(s => s.StartTlsAdvertised);
                    int tls13 = servers.Count(s => s.Tls13Used || s.SupportsTls13);
                    int expSoon = servers.Count(s => s.DaysToExpire <= 30);
                    int a = servers.Count(s => s.Grade.ToString() == "A");
                    int bbb = servers.Count(s => s.Grade.ToString() == "B");
                    int ccc = servers.Count(s => s.Grade.ToString() == "C");
                    int ddd = servers.Count(s => s.Grade.ToString() == "D");
                    int fff = servers.Count(s => s.Grade.ToString() == "F");
                    rows.Add(new[] { service, info.Status ?? "-", n.ToString(), starttls.ToString(), tls13.ToString(), a.ToString(), bbb.ToString(), ccc.ToString(), ddd.ToString(), fff.ToString(), expSoon.ToString() });
                }
                if (rows.Count > 0)
                {
                    md.Table(t => t.Headers("Service","Status","Servers","StartTLS","TLS 1.3","A","B","C","D","F","Exp<=30d").Rows(rows).AlignLeft(0,1).AlignCenter(2,3,4,5,6,7,8,9,10));
                }
                var sec = SectionProjectors.BuildMailTls(b.SmtpTls, b.ImapTls, b.PopTls);
                if (sec != null)
                {
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var mtFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (mtFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(mtFind).AlignLeft(0,1,2,3));
                }
                RenderNarrative(md, narrative);
                bool hasEvidence = (b.SmtpTls?.Servers?.Count ?? 0) > 0
                    || (b.ImapTls?.Servers?.Count ?? 0) > 0
                    || (b.PopTls?.Servers?.Count ?? 0) > 0;
                if (hasEvidence)
                {
                    md.H3("Evidence");
                    if (b.SmtpTls?.Servers != null && b.SmtpTls.Servers.Count > 0) RenderMailTlsServers(md, "SMTP", b.SmtpTls);
                    if (b.ImapTls?.Servers != null && b.ImapTls.Servers.Count > 0) RenderMailTlsServers(md, "IMAP", b.ImapTls);
                    if (b.PopTls?.Servers != null && b.PopTls.Servers.Count > 0) RenderMailTlsServers(md, "POP3", b.PopTls);
                }
                RenderReferences(md, MergeReferences(sec?.References, narrative?.References));
            }

            void RenderDnsbl()
            {
                if (b.Dnsbl == null) return;
                var sec = SectionProjectors.BuildDnsbl(b.Dnsbl);
                var narrative = DnsblNarrative.Build(b.Dnsbl.Raw, b.Dnsbl.Assessments);
                md.H2("DNSBL");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Findings.Count > 0)
                    {
                        var dnsblRows = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                        md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dnsblRows).AlignLeft(0,1,2,3));
                    }
                    RenderNarrative(md, narrative);
                    var summaries = b.Dnsbl.HostSummaries ?? Array.Empty<DomainDetective.Views.DnsblHostSummary>();
                    var listed = b.Dnsbl.ListedRecords ?? Array.Empty<DomainDetective.DNSBLRecord>();
                    bool hasEvidence = summaries.Count > 0 || listed.Count > 0;
                    if (hasEvidence)
                    {
                        md.H3("Evidence");
                        if (summaries.Count > 0)
                        {
                            md.H4("Host summary");
                            var rows = summaries.Select(s => (IReadOnlyList<string>)new[]
                            {
                                s.Key,
                                $"{s.Listed}/{s.Total}",
                                s.Blacklists != null && s.Blacklists.Count > 0 ? string.Join(", ", s.Blacklists) : "-"
                            }).ToList();
                            md.Table(t => t.Headers("Host","Listed","Blacklists").Rows(rows).AlignLeft(0,1,2));
                        }
                        if (listed.Count > 0)
                        {
                            md.H4("Listed records");
                            var rows = listed.Select(r2 => (IReadOnlyList<string>)new[]
                            {
                                r2.SourceHost ?? r2.IpAddress ?? string.Empty,
                                r2.BlackList ?? string.Empty,
                                r2.ReplyMeaning ?? string.Empty
                            }).ToList();
                            md.Table(t => t.Headers("Host","Blacklist","Reason").Rows(rows).AlignLeft(0,1,2));
                        }
                    }
                    RenderReferences(md, MergeReferences(sec?.References, narrative?.References));
                }
            }

            void RenderNs()
            {
                if (b.Ns == null) return;
                var sec = SectionProjectors.BuildNs(b.Ns);
                var narrative = b.Ns.Raw != null ? NSNarrative.Build(b.Ns.Raw) : null;
                md.H2("NS");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var nsFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (nsFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(nsFind));
                    RenderNarrative(md, narrative);
                    var raw = b.Ns.Raw;
                    bool hasEvidence = raw != null
                        && ((raw.NsRecords?.Count ?? 0) > 0
                            || (raw.ParentNsRecords?.Count ?? 0) > 0
                            || (raw.RootServerResponses?.Count ?? 0) > 0
                            || (raw.RecursionEnabled?.Count ?? 0) > 0);
                    if (hasEvidence && raw != null)
                    {
                        md.H3("Evidence");
                        if (raw.NsRecords != null && raw.NsRecords.Count > 0)
                        {
                            md.H4("Child NS");
                            md.Ul(raw.NsRecords.ToArray());
                        }
                        if (raw.ParentNsRecords != null && raw.ParentNsRecords.Count > 0)
                        {
                            md.H4("Parent NS");
                            md.Ul(raw.ParentNsRecords.ToArray());
                        }
                        if (raw.RootServerResponses != null && raw.RootServerResponses.Count > 0)
                        {
                            md.H4("Root responses");
                            var rows = raw.RootServerResponses.Select(kv => (IReadOnlyList<string>)new[] { kv.Key, kv.Value ? "Yes" : "No" }).ToList();
                            md.Table(t => t.Headers("Server","Responded").Rows(rows).AlignLeft(0,1));
                        }
                        if (raw.RecursionEnabled != null && raw.RecursionEnabled.Count > 0)
                        {
                            md.H4("Recursion status");
                            var rows = raw.RecursionEnabled.Select(kv => (IReadOnlyList<string>)new[] { kv.Key, kv.Value ? "Yes" : "No" }).ToList();
                            md.Table(t => t.Headers("Server","Recursion").Rows(rows).AlignLeft(0,1));
                        }
                    }
                    RenderReferences(md, MergeReferences(sec?.References, narrative?.References));
                }
            }

            void RenderSoa()
            {
                if (b.Soa == null) return;
                var sec = SectionProjectors.BuildSoa(b.Soa);
                var narrative = b.Soa.Raw != null ? SoaNarrative.Build(b.Soa.Raw) : null;
                md.H2("SOA");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    var soaFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (soaFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(soaFind));
                    RenderNarrative(md, narrative);
                    var raw = b.Soa.Raw;
                    bool hasEvidence = raw != null && raw.RecordExists;
                    if (hasEvidence && raw != null)
                    {
                        md.H3("Evidence");
                        md.Table(t => t.Headers("Key","Value")
                            .Row("Primary NS", raw.PrimaryNameServer ?? "-")
                            .Row("Responsible", raw.ResponsibleMailbox ?? "-")
                            .Row("Serial", raw.SerialNumber.ToString())
                            .Row("Serial format", raw.SerialFormatValid ? "Valid" : "Check")
                            .Row("Refresh", raw.Refresh.ToString())
                            .Row("Retry", raw.Retry.ToString())
                            .Row("Expire", raw.Expire.ToString())
                            .Row("Minimum", raw.Minimum.ToString())
                            .Row("Negative cache TTL", raw.NegativeCacheTtl.ToString())
                            .AlignLeft(0,1));
                    }
                    RenderReferences(md, MergeReferences(sec?.References, narrative?.References));
                }
            }

            void RenderCaa()
            {
                if (b.Caa == null) return;
                var sec = SectionProjectors.BuildCaa(b.Caa);
                var narrative = b.Caa.Raw != null ? CaaNarrative.Build(b.Caa.Raw) : null;
                md.H2("CAA");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var caaFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (caaFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(caaFind));
                    RenderNarrative(md, narrative);
                    var raw = b.Caa.Raw;
                    if (raw != null && raw.AnalysisResults != null && raw.AnalysisResults.Count > 0)
                    {
                        md.H3("Evidence");
                        var rows = raw.AnalysisResults.Select(r => (IReadOnlyList<string>)new string[]
                        {
                            r.CAARecord ?? string.Empty,
                            r.Flag ?? string.Empty,
                            r.Tag.ToString(),
                            r.Value ?? string.Empty,
                            string.IsNullOrWhiteSpace(r.Issuer) ? "-" : r.Issuer!,
                            r.Critical ? "Yes" : "No",
                            r.Invalid ? "Yes" : "No"
                        }).ToList();
                        md.Table(t => t.Headers("Record","Flag","Tag","Value","Issuer","Critical","Invalid")
                            .Rows(rows)
                            .AlignLeft(0,1,2,3,4,5,6));
                    }
                    RenderReferences(md, MergeReferences(sec?.References, narrative?.References));
                }
            }

            void RenderDnssec()
            {
                if (b.Dnssec == null) return;
                var dsec = SectionProjectors.BuildDnssec(b.Dnssec);
                var narrative = DnssecNarrative.Build(b.Dnssec.Raw, b.Dnssec.Assessments);
                md.H2("DNSSEC");
                if (dsec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in dsec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (dsec.Positives.Count > 0) md.H3("Positives").Ul(dsec.Positives.ToArray());
                    var dnsFind = dsec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (dnsFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dnsFind));
                    RenderNarrative(md, narrative);
                    var raw = b.Dnssec.Raw;
                    bool hasEvidence = raw != null
                        && ((raw.DsRecords?.Count ?? 0) > 0
                            || (raw.DnsKeys?.Count ?? 0) > 0
                            || (raw.Rrsigs?.Count ?? 0) > 0
                            || raw.RootAnchorExpiration.HasValue
                            || (raw.MismatchSummary?.Count ?? 0) > 0
                            || (raw.Warnings?.Count ?? 0) > 0);
                    if (hasEvidence && raw != null)
                    {
                        md.H3("Evidence");
                        if (raw.DsRecords != null && raw.DsRecords.Count > 0)
                        {
                            md.H4("DS records");
                            md.Code("", string.Join(Environment.NewLine, raw.DsRecords));
                        }
                        if (raw.DnsKeys != null && raw.DnsKeys.Count > 0)
                        {
                            md.H4("DNSKEY records");
                            md.Code("", string.Join(Environment.NewLine, raw.DnsKeys));
                        }
                        if (raw.Rrsigs != null && raw.Rrsigs.Count > 0)
                        {
                            md.H4("RRSIG summary");
                            var rows = raw.Rrsigs.Select(r => (IReadOnlyList<string>)new[]
                            {
                                r.Algorithm,
                                r.KeyTag.ToString(),
                                r.Inception == DateTimeOffset.MinValue ? "-" : r.Inception.UtcDateTime.ToString("yyyy-MM-dd"),
                                r.Expiration == DateTimeOffset.MinValue ? "-" : r.Expiration.UtcDateTime.ToString("yyyy-MM-dd")
                            }).ToList();
                            md.Table(t => t.Headers("Algorithm","KeyTag","Inception","Expiration").Rows(rows).AlignLeft(0,1,2,3));
                        }
                        if (raw.RootAnchorExpiration.HasValue)
                        {
                            md.H4("Root trust anchor expires");
                            md.P(raw.RootAnchorExpiration.Value.UtcDateTime.ToString("yyyy-MM-dd"));
                        }
                        if (raw.MismatchSummary != null && raw.MismatchSummary.Count > 0)
                        {
                            md.H4("Mismatch summary");
                            md.Ul(raw.MismatchSummary.ToArray());
                        }
                        if (raw.Warnings != null && raw.Warnings.Count > 0)
                        {
                            md.H4("Warnings");
                            md.Ul(raw.Warnings.ToArray());
                        }
                    }
                    RenderReferences(md, MergeReferences(dsec?.References, narrative?.References));
                }
            }

            void RenderDane()
            {
                if (b.Dane == null) return;
                var dasec = SectionProjectors.BuildDane(b.Dane);
                var narrative = DaneNarrative.Build(b.Dane.Raw, b.Dane.Assessments);
                md.H2("DANE");
                if (dasec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in dasec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    var daFind = dasec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (daFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(daFind));
                    RenderNarrative(md, narrative);
                    var raw = b.Dane.Raw;
                    if (raw != null && raw.AnalysisResults != null && raw.AnalysisResults.Count > 0)
                    {
                        md.H3("Evidence");
                        var rows = raw.AnalysisResults.Select(r => (IReadOnlyList<string>)new string[]
                        {
                            r.DomainName ?? string.Empty,
                            r.CertificateUsage.ToString(),
                            r.SelectorField.ToString(),
                            r.MatchingTypeField.ToString(),
                            r.ValidDANERecord ? "Yes" : "No"
                        }).ToList();
                        md.Table(t => t.Headers("Host","Usage","Selector","Matching","Valid").Rows(rows).AlignLeft(0,1,2,3,4));
                    }
                    RenderReferences(md, MergeReferences(dasec?.References, narrative?.References));
                }
            }

            var present = GetPresentSections(b);
            var input = inputSectionOrder.TryGetValue(d, out var list) ? list : null;
            var order = SectionOrdering.ResolveOrder(mode, present, input, custom);
            foreach (var section in order)
            {
                switch (section)
                {
                    case "Classification":
                        RenderClassification();
                        break;
                    case "Desired State":
                        RenderDesiredState();
                        break;
                    case "Microsoft 365":
                        RenderMicrosoft365();
                        break;
                    case "Typosquatting":
                        RenderTyposquatting();
                        break;
                    case "SPF":
                        RenderSpf();
                        break;
                    case "DMARC":
                        RenderDmarc();
                        break;
                    case "DKIM":
                        RenderDkim();
                        break;
                    case "MX":
                        RenderMx();
                        break;
                    case "MTA-STS":
                        RenderMtasts();
                        break;
                    case "TLS-RPT":
                        RenderTlsRpt();
                        break;
                    case "MAILTLS":
                        RenderMailTls();
                        break;
                    case "DNSBL":
                        RenderDnsbl();
                        break;
                    case "NS":
                        RenderNs();
                        break;
                    case "SOA":
                        RenderSoa();
                        break;
                    case "CAA":
                        RenderCaa();
                        break;
                    case "DNSSEC":
                        RenderDnssec();
                        break;
                    case "DANE":
                        RenderDane();
                        break;
                }
            }
        }
    }

    private static IReadOnlyList<string> GetPresentSections(DomainBucket b)
    {
        var list = new List<string>();
        if (b.Classification != null) list.Add("Classification");
        if (b.DesiredState != null) list.Add("Desired State");
        if (b.Microsoft365 != null) list.Add("Microsoft 365");
        if (b.Typosquatting != null) list.Add("Typosquatting");
        if (b.Spf != null) list.Add("SPF");
        if (b.Dmarc != null) list.Add("DMARC");
        if (b.Dkim.Count > 0) list.Add("DKIM");
        if (b.Mx != null) list.Add("MX");
        if (b.Mtasts != null) list.Add("MTA-STS");
        if (b.TlsRpt != null) list.Add("TLS-RPT");
        if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null) list.Add("MAILTLS");
        if (b.Dnsbl != null) list.Add("DNSBL");
        if (b.Ns != null) list.Add("NS");
        if (b.Soa != null) list.Add("SOA");
        if (b.Caa != null) list.Add("CAA");
        if (b.Dnssec != null) list.Add("DNSSEC");
        if (b.Dane != null) list.Add("DANE");
        return list;
    }
}
