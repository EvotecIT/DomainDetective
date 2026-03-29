using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class TyposquattingWordSectionWriter
{
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Reports.SectionProjectors.TyposquattingSection section,
        DomainDetective.Views.TyposquattingInfo info,
        string domain,
        ReportScope scope,
        bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (section == null) throw new ArgumentNullException(nameof(section));
        if (info == null) throw new ArgumentNullException(nameof(info));

        headings.AddItem("Summary", baseLevel);
        var summaryRows = section.Summary.Count > 0
            ? section.Summary
            : new System.Collections.Generic.List<(string, string)> { ("Status", section.Status) };
        var summaryTable = doc.AddTable(summaryRows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < summaryRows.Count; i++)
        {
            summaryTable.Rows[i].Cells[0].AddParagraph(summaryRows[i].Item1);
            summaryTable.Rows[i].Cells[1].AddParagraph(summaryRows[i].Item2);
        }

        if (section.TopResponsePack != null)
        {
            headings.AddItem("Top Response Pack", baseLevel);
            var responseRows = new (string, string)[]
            {
                ("Campaign", string.IsNullOrWhiteSpace(section.TopResponsePack.Label) ? "-" : section.TopResponsePack.Label),
                ("Case", string.IsNullOrWhiteSpace(section.TopResponsePack.CaseId) ? "-" : section.TopResponsePack.CaseId),
                ("Severity", string.IsNullOrWhiteSpace(section.TopResponsePack.Severity) ? "-" : section.TopResponsePack.Severity),
                ("Top Domain", string.IsNullOrWhiteSpace(section.TopResponsePack.TopDomain) ? "-" : section.TopResponsePack.TopDomain),
                ("Primary Contact", string.IsNullOrWhiteSpace(section.TopResponsePack.PrimaryContact) ? "-" : section.TopResponsePack.PrimaryContact),
                ("Tracking", string.IsNullOrWhiteSpace(section.TopResponsePack.TrackingSummary) ? "-" : section.TopResponsePack.TrackingSummary),
                ("Escalation", string.IsNullOrWhiteSpace(section.TopResponsePack.EscalationSummary) ? "-" : section.TopResponsePack.EscalationSummary),
                ("Actionability", string.IsNullOrWhiteSpace(section.TopResponsePack.ActionabilitySummary) ? "-" : section.TopResponsePack.ActionabilitySummary),
                ("Next Step", string.IsNullOrWhiteSpace(section.TopResponsePack.RecommendedAction) ? "-" : section.TopResponsePack.RecommendedAction),
                ("Draft", string.IsNullOrWhiteSpace(section.TopResponsePack.DraftPreview) ? "-" : section.TopResponsePack.DraftPreview)
            };
            var responseTable = doc.AddTable(responseRows.Length, 2, WordTableStyle.TableGrid);
            for (int i = 0; i < responseRows.Length; i++)
            {
                responseTable.Rows[i].Cells[0].AddParagraph(responseRows[i].Item1);
                responseTable.Rows[i].Cells[1].AddParagraph(responseRows[i].Item2);
            }
        }

        if (section.Campaigns.Count > 0)
        {
            headings.AddItem("Campaigns", baseLevel);
            int takeCampaigns = Math.Min(section.Campaigns.Count, 100);
            var campaignTable = doc.AddTable(takeCampaigns + 1, 26, WordTableStyle.TableGrid);
            campaignTable.Rows[0].Cells[0].AddParagraph("Label");
            campaignTable.Rows[0].Cells[1].AddParagraph("Severity");
            campaignTable.Rows[0].Cells[2].AddParagraph("Score");
            campaignTable.Rows[0].Cells[3].AddParagraph("Domains");
            campaignTable.Rows[0].Cells[4].AddParagraph("Active");
            campaignTable.Rows[0].Cells[5].AddParagraph("Reachable");
            campaignTable.Rows[0].Cells[6].AddParagraph("Threat");
            campaignTable.Rows[0].Cells[7].AddParagraph("Malicious");
            campaignTable.Rows[0].Cells[8].AddParagraph("Impersonation");
            campaignTable.Rows[0].Cells[9].AddParagraph("Content");
            campaignTable.Rows[0].Cells[10].AddParagraph("Visual");
            campaignTable.Rows[0].Cells[11].AddParagraph("Top Domain");
            campaignTable.Rows[0].Cells[12].AddParagraph("Disposition");
            campaignTable.Rows[0].Cells[13].AddParagraph("Actionability");
            campaignTable.Rows[0].Cells[14].AddParagraph("Registrar");
            campaignTable.Rows[0].Cells[15].AddParagraph("Hosting");
            campaignTable.Rows[0].Cells[16].AddParagraph("Country");
            campaignTable.Rows[0].Cells[17].AddParagraph("Abuse");
            campaignTable.Rows[0].Cells[18].AddParagraph("Pivots");
            campaignTable.Rows[0].Cells[19].AddParagraph("Actionability Summary");
            campaignTable.Rows[0].Cells[20].AddParagraph("Action");
            campaignTable.Rows[0].Cells[21].AddParagraph("Case");
            campaignTable.Rows[0].Cells[22].AddParagraph("Tracking");
            campaignTable.Rows[0].Cells[23].AddParagraph("Draft");
            campaignTable.Rows[0].Cells[24].AddParagraph("Escalation");
            campaignTable.Rows[0].Cells[25].AddParagraph("Summary");
            for (int i = 0; i < takeCampaigns; i++)
            {
                var row = section.Campaigns[i];
                campaignTable.Rows[i + 1].Cells[0].AddParagraph(row.Label);
                campaignTable.Rows[i + 1].Cells[1].AddParagraph(string.IsNullOrWhiteSpace(row.Severity) ? "-" : row.Severity);
                campaignTable.Rows[i + 1].Cells[2].AddParagraph(row.CampaignScore.ToString());
                campaignTable.Rows[i + 1].Cells[3].AddParagraph(row.CandidateCount.ToString());
                campaignTable.Rows[i + 1].Cells[4].AddParagraph(row.ActiveCount.ToString());
                campaignTable.Rows[i + 1].Cells[5].AddParagraph(row.ReachableWebCount.ToString());
                campaignTable.Rows[i + 1].Cells[6].AddParagraph(row.ThreatListedCount.ToString());
                campaignTable.Rows[i + 1].Cells[7].AddParagraph(row.LikelyMaliciousCount.ToString());
                campaignTable.Rows[i + 1].Cells[8].AddParagraph(row.LikelyImpersonationCount.ToString());
                campaignTable.Rows[i + 1].Cells[9].AddParagraph(row.LikelyImpersonatingCount.ToString());
                campaignTable.Rows[i + 1].Cells[10].AddParagraph(row.LikelyVisualCloneCount.ToString());
                campaignTable.Rows[i + 1].Cells[11].AddParagraph(string.IsNullOrWhiteSpace(row.TopCandidateDomain) ? "-" : row.TopCandidateDomain);
                campaignTable.Rows[i + 1].Cells[12].AddParagraph(string.IsNullOrWhiteSpace(row.TopCandidateDisposition) ? "-" : row.TopCandidateDisposition);
                campaignTable.Rows[i + 1].Cells[13].AddParagraph(string.IsNullOrWhiteSpace(row.Actionability) ? "-" : $"{row.Actionability} ({row.ActionabilityScore})");
                campaignTable.Rows[i + 1].Cells[14].AddParagraph(string.IsNullOrWhiteSpace(row.PrimaryRegistrar) ? "-" : $"{row.PrimaryRegistrar} ({row.RegistrarConcentrationPercent}%)");
                campaignTable.Rows[i + 1].Cells[15].AddParagraph(string.IsNullOrWhiteSpace(row.PrimaryHostingProvider) ? "-" : $"{row.PrimaryHostingProvider} ({row.HostingConcentrationPercent}%)");
                campaignTable.Rows[i + 1].Cells[16].AddParagraph(string.IsNullOrWhiteSpace(row.PrimaryCountry) ? "-" : $"{row.PrimaryCountry} ({row.CountryConcentrationPercent}%)");
                campaignTable.Rows[i + 1].Cells[17].AddParagraph(string.IsNullOrWhiteSpace(row.PrimaryAbuseContact) ? "-" : row.PrimaryAbuseContact);
                campaignTable.Rows[i + 1].Cells[18].AddParagraph(string.IsNullOrWhiteSpace(row.PivotSummary) ? "-" : row.PivotSummary);
                campaignTable.Rows[i + 1].Cells[19].AddParagraph(string.IsNullOrWhiteSpace(row.ActionabilitySummary) ? "-" : row.ActionabilitySummary);
                campaignTable.Rows[i + 1].Cells[20].AddParagraph(string.IsNullOrWhiteSpace(row.RecommendedAction) ? "-" : row.RecommendedAction);
                campaignTable.Rows[i + 1].Cells[21].AddParagraph(string.IsNullOrWhiteSpace(row.EscalationCaseId) ? "-" : row.EscalationCaseId);
                campaignTable.Rows[i + 1].Cells[22].AddParagraph(string.IsNullOrWhiteSpace(row.EscalationTrackingSummary) ? "-" : row.EscalationTrackingSummary);
                campaignTable.Rows[i + 1].Cells[23].AddParagraph(string.IsNullOrWhiteSpace(row.EscalationDraftPreview) ? "-" : row.EscalationDraftPreview);
                campaignTable.Rows[i + 1].Cells[24].AddParagraph(string.IsNullOrWhiteSpace(row.EscalationSummary) ? "-" : row.EscalationSummary);
                campaignTable.Rows[i + 1].Cells[25].AddParagraph(string.IsNullOrWhiteSpace(row.Summary) ? "-" : row.Summary);
            }
        }

        if (section.Rows.Count > 0)
        {
            headings.AddItem("Candidates", baseLevel);
            int take = Math.Min(section.Rows.Count, 250);
            var candidateTable = doc.AddTable(take + 1, 24, WordTableStyle.TableGrid);
            candidateTable.Rows[0].Cells[0].AddParagraph("Domain");
            candidateTable.Rows[0].Cells[1].AddParagraph("Score");
            candidateTable.Rows[0].Cells[2].AddParagraph("Risk");
            candidateTable.Rows[0].Cells[3].AddParagraph("Disposition");
            candidateTable.Rows[0].Cells[4].AddParagraph("Cluster");
            candidateTable.Rows[0].Cells[5].AddParagraph("Kind");
            candidateTable.Rows[0].Cells[6].AddParagraph("Distance");
            candidateTable.Rows[0].Cells[7].AddParagraph("Resolves");
            candidateTable.Rows[0].Cells[8].AddParagraph("Registered");
            candidateTable.Rows[0].Cells[9].AddParagraph("A");
            candidateTable.Rows[0].Cells[10].AddParagraph("AAAA");
            candidateTable.Rows[0].Cells[11].AddParagraph("NS");
            candidateTable.Rows[0].Cells[12].AddParagraph("MX");
            candidateTable.Rows[0].Cells[13].AddParagraph("Owned");
            candidateTable.Rows[0].Cells[14].AddParagraph("Ownership");
            candidateTable.Rows[0].Cells[15].AddParagraph("External");
            candidateTable.Rows[0].Cells[16].AddParagraph("Distinct");
            candidateTable.Rows[0].Cells[17].AddParagraph("Content");
            candidateTable.Rows[0].Cells[18].AddParagraph("Similarity");
            candidateTable.Rows[0].Cells[19].AddParagraph("Visual");
            candidateTable.Rows[0].Cells[20].AddParagraph("Visual Type");
            candidateTable.Rows[0].Cells[21].AddParagraph("Visual Diff");
            candidateTable.Rows[0].Cells[22].AddParagraph("Visual Summary");
            candidateTable.Rows[0].Cells[23].AddParagraph("Enrichment");
            for (int i = 0; i < take; i++)
            {
                var row = section.Rows[i];
                candidateTable.Rows[i + 1].Cells[0].AddParagraph(row.Domain);
                candidateTable.Rows[i + 1].Cells[1].AddParagraph(row.RiskScore.ToString());
                candidateTable.Rows[i + 1].Cells[2].AddParagraph(string.IsNullOrWhiteSpace(row.RiskLevel) ? "-" : row.RiskLevel);
                candidateTable.Rows[i + 1].Cells[3].AddParagraph(string.IsNullOrWhiteSpace(row.Disposition) ? "-" : row.Disposition);
                candidateTable.Rows[i + 1].Cells[4].AddParagraph(string.IsNullOrWhiteSpace(row.InfrastructureClusterLabel) ? "-" : $"{row.InfrastructureClusterLabel} ({row.InfrastructureClusterSize})");
                candidateTable.Rows[i + 1].Cells[5].AddParagraph(row.Kind);
                candidateTable.Rows[i + 1].Cells[6].AddParagraph(row.EditDistance.ToString());
                candidateTable.Rows[i + 1].Cells[7].AddParagraph(row.Resolves ? "Yes" : "No");
                candidateTable.Rows[i + 1].Cells[8].AddParagraph(row.AppearsRegistered ? "Yes" : "No");
                candidateTable.Rows[i + 1].Cells[9].AddParagraph(row.ACount.ToString());
                candidateTable.Rows[i + 1].Cells[10].AddParagraph(row.AaaaCount.ToString());
                candidateTable.Rows[i + 1].Cells[11].AddParagraph(row.NsCount.ToString());
                candidateTable.Rows[i + 1].Cells[12].AddParagraph(row.MxCount.ToString());
                candidateTable.Rows[i + 1].Cells[13].AddParagraph(row.LikelyOwned ? "Likely" : "-");
                candidateTable.Rows[i + 1].Cells[14].AddParagraph(string.IsNullOrWhiteSpace(row.OwnershipSummary) ? "-" : row.OwnershipSummary);
                candidateTable.Rows[i + 1].Cells[15].AddParagraph(row.LikelyExternal ? "Likely" : "-");
                candidateTable.Rows[i + 1].Cells[16].AddParagraph(string.IsNullOrWhiteSpace(row.ExternalSummary) ? "-" : row.ExternalSummary);
                candidateTable.Rows[i + 1].Cells[17].AddParagraph(row.LikelyImpersonating ? "Likely" : (row.ContentSimilarityScore > 0 ? row.ContentSimilarityScore.ToString() : "-"));
                candidateTable.Rows[i + 1].Cells[18].AddParagraph(string.IsNullOrWhiteSpace(row.ContentSimilaritySummary) ? "-" : row.ContentSimilaritySummary);
                candidateTable.Rows[i + 1].Cells[19].AddParagraph(row.LikelyVisualClone ? "Likely" : (row.VisualSimilarityScore > 0 ? row.VisualSimilarityScore.ToString() : "-"));
                candidateTable.Rows[i + 1].Cells[20].AddParagraph(string.IsNullOrWhiteSpace(row.VisualMatchType) ? "-" : row.VisualMatchType);
                candidateTable.Rows[i + 1].Cells[21].AddParagraph(row.VisualSimilarityDistance?.ToString() ?? "-");
                candidateTable.Rows[i + 1].Cells[22].AddParagraph(string.IsNullOrWhiteSpace(row.VisualSimilaritySummary) ? "-" : row.VisualSimilaritySummary);
                candidateTable.Rows[i + 1].Cells[23].AddParagraph(string.IsNullOrWhiteSpace(row.EnrichmentSummary) ? "-" : row.EnrichmentSummary);
            }
        }

        var findings = section.Findings;
        if (!showInfoFindings)
        {
            findings = findings
                .Where(f => !string.Equals(f.Severity, "Info", StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        if (findings.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            var findingsTable = doc.AddTable(findings.Count + 1, 4, WordTableStyle.TableGrid);
            findingsTable.Rows[0].Cells[0].AddParagraph("Severity");
            findingsTable.Rows[0].Cells[1].AddParagraph("Code");
            findingsTable.Rows[0].Cells[2].AddParagraph("Target");
            findingsTable.Rows[0].Cells[3].AddParagraph("Message");
            for (int i = 0; i < findings.Count; i++)
            {
                var finding = findings[i];
                findingsTable.Rows[i + 1].Cells[0].AddParagraph(finding.Severity);
                findingsTable.Rows[i + 1].Cells[1].AddParagraph(finding.Code);
                findingsTable.Rows[i + 1].Cells[2].AddParagraph(finding.Target);
                findingsTable.Rows[i + 1].Cells[3].AddParagraph(finding.Message);
            }
        }

        if (section.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var reference in section.References)
            {
                list.AddItem(reference);
            }
        }
    }
}
