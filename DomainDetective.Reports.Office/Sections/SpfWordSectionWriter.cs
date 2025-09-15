using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Writes the SPF section into an existing WordDocument. Extracted from SpfWordReport to enable reuse.
/// </summary>
/// <summary>
/// Writes an SPF section into an existing Word document.
/// </summary>
public static class SpfWordSectionWriter
{
    /// <summary>
    /// Writes the SPF section body.
    /// </summary>
    /// <param name="doc">Destination <see cref="WordDocument"/>.</param>
    /// <param name="spf">SPF view model.</param>
    /// <param name="domain">Domain subject.</param>
    /// <param name="scope">Detail level.</param>
    /// <param name="showInfoFindings">Whether to include Info-level findings in tables.</param>
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.SpfRecordInfo spf, string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true, bool includeMechanismMeanings = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (spf == null) throw new ArgumentNullException(nameof(spf));

        var nar = spf.Narrative;
        // Narrative-backed sections
        if (includeNarrative && nar != null)
        {
            if (!string.IsNullOrWhiteSpace(nar.Introduction))
            {
                headings.AddItem("Introduction", baseLevel);
                doc.AddParagraph(nar.Introduction);
            }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters))
            {
                headings.AddItem("Why this matters", baseLevel);
                doc.AddParagraph(nar.WhyItMatters);
            }
        }

        // Summary
        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Key SPF posture indicators for this domain.");
        var summaryTable = doc.AddTable(5, 2, WordTableStyle.TableGrid);
        summaryTable.Rows[0].Cells[0].AddParagraph("Record Present");
        summaryTable.Rows[0].Cells[1].AddParagraph(spf.SpfRecordExists ? "Yes" : "No");
        summaryTable.Rows[1].Cells[0].AddParagraph("Starts Correctly");
        summaryTable.Rows[1].Cells[1].AddParagraph(spf.StartsCorrectly ? "Yes" : "No");
        summaryTable.Rows[2].Cells[0].AddParagraph("DNS Lookups");
        summaryTable.Rows[2].Cells[1].AddParagraph(spf.DnsLookupsCount.ToString());
        summaryTable.Rows[3].Cells[0].AddParagraph("Multiple 'all'");
        summaryTable.Rows[3].Cells[1].AddParagraph(spf.MultipleAllMechanisms ? "Yes" : "No");
        summaryTable.Rows[4].Cells[0].AddParagraph("All Mechanism");
        summaryTable.Rows[4].Cells[1].AddParagraph(spf.Raw?.AllMechanism ?? string.Empty);

        // Highlights
        if (spf.Highlights != null && spf.Highlights.Count > 0)
        {
            headings.AddItem("Highlights", baseLevel);
            doc.AddParagraph("Notable observations:");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var h in spf.Highlights) list.AddItem(h);
        }

        // Negatives from narrative
        if (nar?.Negatives != null && nar.Negatives.Count > 0)
        {
            headings.AddItem("Negatives", baseLevel);
            doc.AddParagraph("Areas needing improvement:");
            var nlist = doc.AddList(WordListStyle.Bulleted);
            foreach (var n in nar.Negatives) nlist.AddItem(n);
        }

        // Good posture (positives)
        if (scope != ReportScope.Minimal && spf.Positives != null && spf.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in spf.Positives.Select(x => x.Title).Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                plist.AddItem(p!);
            }
        }

        // Findings
        var assessAll = spf.Assessments?.ToList() ?? new System.Collections.Generic.List<DomainDetective.Assessment>();
        var assess = showInfoFindings ? assessAll : assessAll.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (assess.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");
            var table = doc.AddTable(assess.Count + 1, 4, WordTableStyle.TableGrid);
            table.Rows[0].Cells[0].AddParagraph("Severity");
            table.Rows[0].Cells[1].AddParagraph("Code");
            table.Rows[0].Cells[2].AddParagraph("Target");
            table.Rows[0].Cells[3].AddParagraph("Message");
            for (int i = 0; i < assess.Count; i++)
            {
                var a = assess[i];
                table.Rows[i + 1].Cells[0].AddParagraph(a.Severity.ToString());
                table.Rows[i + 1].Cells[1].AddParagraph(a.Code ?? string.Empty);
                table.Rows[i + 1].Cells[2].AddParagraph(a.Target ?? string.Empty);
                table.Rows[i + 1].Cells[3].AddParagraph(a.Message);
            }
        }
        else
        {
            doc.AddParagraph("No findings.");
        }

        if (scope == ReportScope.Minimal)
        {
            // Minimal stops here
            return;
        }

        // DNS Lookups (from raw)
        if (spf.Raw?.DnsLookups != null && spf.Raw.DnsLookups.Count > 0)
        {
            headings.AddItem("DNS Lookups", baseLevel);
            doc.AddParagraph("DNS queries performed while evaluating SPF.");
            var lookList = doc.AddList(WordListStyle.Bulleted);
            foreach (var l in spf.Raw.DnsLookups.Distinct()) lookList.AddItem(l);
        }

        // Flattened IP Analysis (from raw)
        var flat = spf.Raw?.FlattenedIpAnalysis;
        if (flat != null)
        {
            headings.AddItem("Flattened IP Analysis", baseLevel);
            var flatTable = doc.AddTable(3, 2, WordTableStyle.TableGrid);
            flatTable.Rows[0].Cells[0].AddParagraph("Unique IPs");
            flatTable.Rows[0].Cells[1].AddParagraph((flat?.UniqueIps?.Count ?? 0).ToString());
            flatTable.Rows[1].Cells[0].AddParagraph("Duplicate IPs");
            flatTable.Rows[1].Cells[1].AddParagraph((flat?.DuplicateIps?.Count ?? 0).ToString());
            flatTable.Rows[2].Cells[0].AddParagraph("Tokens Resolved");
            flatTable.Rows[2].Cells[1].AddParagraph((flat?.TokenIpMap?.Count ?? 0).ToString());
            if (flat?.TokenIpMap != null && flat.TokenIpMap.Count > 0)
            {
                doc.AddParagraph("Token → IPs (counts)");
                var t = doc.AddTable(flat.TokenIpMap.Count + 1, 2, WordTableStyle.TableGrid);
                t.Rows[0].Cells[0].AddParagraph("Token");
                t.Rows[0].Cells[1].AddParagraph("IP Count");
                int r = 1;
                foreach (var kv in flat.TokenIpMap)
                {
                    t.Rows[r].Cells[0].AddParagraph(kv.Key);
                    t.Rows[r].Cells[1].AddParagraph((kv.Value?.Count ?? 0).ToString());
                    r++;
                }
            }
        }

        // Policy Checks (from raw)
        if (spf.Raw != null)
        {
            headings.AddItem("Policy Checks", baseLevel);
            doc.AddParagraph("Policy-level validations and advisories.");
            var checks = doc.AddTable(3, 2, WordTableStyle.TableGrid);
            checks.Rows[0].Cells[0].AddParagraph("Cycle Detected");
            checks.Rows[0].Cells[1].AddParagraph(spf.Raw.CycleDetected ? "Yes" : "No");
            checks.Rows[1].Cells[0].AddParagraph("Cycle Path");
            checks.Rows[1].Cells[1].AddParagraph(spf.Raw.CyclePath ?? string.Empty);
            checks.Rows[2].Cells[0].AddParagraph("Advisory");
            checks.Rows[2].Cells[1].AddParagraph(spf.Raw.Advisory ?? string.Empty);
        }

        // Mechanisms breakdown (Normal/Detailed)
        if (spf.Mechanisms != null && spf.Mechanisms.Count > 0)
        {
            headings.AddItem("Mechanisms", baseLevel);
            doc.AddParagraph("SPF mechanisms present in the evaluated record.");
            var mechTable = doc.AddTable(spf.Mechanisms.Count + 1, 4, WordTableStyle.TableGrid);
            mechTable.Rows[0].Cells[0].AddParagraph("Qualifier");
            mechTable.Rows[0].Cells[1].AddParagraph("Type");
            mechTable.Rows[0].Cells[2].AddParagraph("Value");
            mechTable.Rows[0].Cells[3].AddParagraph("Provider");
            for (int i = 0; i < spf.Mechanisms.Count; i++)
            {
                var p = spf.Mechanisms[i];
                mechTable.Rows[i + 1].Cells[0].AddParagraph(string.IsNullOrEmpty(p.Prefix) ? "+" : p.Prefix);
                mechTable.Rows[i + 1].Cells[1].AddParagraph(p.Type ?? string.Empty);
                mechTable.Rows[i + 1].Cells[2].AddParagraph(p.Value ?? string.Empty);
                mechTable.Rows[i + 1].Cells[3].AddParagraph(p.Provider ?? string.Empty);
            }

            if (scope == ReportScope.Detailed && includeMechanismMeanings)
            {
                var types = spf.Mechanisms.Select(p => p.Type).Where(t => !string.IsNullOrWhiteSpace(t)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                if (types.Count > 0)
                {
                    headings.AddItem("Mechanism meanings", baseLevel + 1);
                    doc.AddParagraph("Quick reference for SPF tokens and qualifiers.");
                    var exp = doc.AddTable(types.Count + 1, 2, WordTableStyle.TableGrid);
                    exp.Rows[0].Cells[0].AddParagraph("Type");
                    exp.Rows[0].Cells[1].AddParagraph("Meaning");
                    int r = 1;
                    foreach (var t in types)
                    {
                        exp.Rows[r].Cells[0].AddParagraph(t!);
                        exp.Rows[r].Cells[1].AddParagraph(MechanismMeaning(t!));
                        r++;
                    }
                    var ql = doc.AddList(WordListStyle.Bulleted);
                    ql.AddItem("+ (pass): explicitly allow");
                    ql.AddItem("- (fail): explicitly deny");
                    ql.AddItem("~ (softfail): likely deny");
                    ql.AddItem("? (neutral): no assertion");
                }
            }
        }

        // Evidence (Normal/Detailed)
        headings.AddItem("Evidence", baseLevel);
        doc.AddParagraph("Raw SPF record values.");
        var lbl = doc.AddParagraph("SPF Record:");
        lbl.Bold = true;
        var rec = doc.AddParagraph(spf.SpfRecord ?? string.Empty);
        rec.FontSize = 10;

        // References
        if (spf.References != null && spf.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            WordLinkHelpers.AddReferencesList(doc, spf.References);
        }
    }

    private static string MechanismMeaning(string type)
    {
        switch (type.ToLowerInvariant())
        {
            case "a": return "Authorize host A/AAAA addresses.";
            case "mx": return "Authorize hosts listed as MX.";
            case "ip4": return "Authorize IPv4 address or CIDR block.";
            case "ip6": return "Authorize IPv6 address or CIDR block.";
            case "include": return "Import another domain's SPF policy.";
            case "exists": return "Authorize based on existence of DNS record.";
            case "ptr": return "Authorize hosts by PTR (discouraged).";
            case "redirect": return "Redirect evaluation to another domain.";
            case "all": return "Catch‑all for remaining senders.";
            case "version": return "SPF version token (v=spf1).";
            default: return "SPF token present.";
        }
    }

    /// <summary>
    /// Projector-aware overload: renders common data from <see cref="DomainDetective.Reports.SectionProjectors.SpfSection"/>,
    /// while preserving Word-only narrative and evidence from the original view when provided.
    /// </summary>
    public static void Write(WordDocument doc, WordList headings, int baseLevel,
        DomainDetective.Reports.SectionProjectors.SpfSection sec,
        DomainDetective.Views.SpfRecordInfo? original,
        string domain, ReportScope scope, bool showInfoFindings,
        bool includeNarrative = true, bool includeMechanismMeanings = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        // Narrative (from original view)
        if (includeNarrative && original?.Narrative != null)
        {
            var nar = original.Narrative;
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        // Summary from DTO
        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Key SPF posture indicators for this domain.");
        var rows = sec.Summary.Count > 0 ? sec.Summary : new System.Collections.Generic.List<(string Key, string Value)>() { ("Status", sec.Status), ("DNS Lookups", sec.DnsLookupsCount.ToString()), ("Record Present", (original?.SpfRecordExists ?? false) ? "Yes" : "No") };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Count; i++) { t.Rows[i].Cells[0].AddParagraph(rows[i].Key); t.Rows[i].Cells[1].AddParagraph(rows[i].Value); }

        // Positives
        if (sec.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in sec.Positives) list.AddItem(p);
        }

        // Findings
        var f = sec.Findings;
        if (!showInfoFindings)
            f = f.Where(x => !string.Equals(x.Severity, "Info", System.StringComparison.OrdinalIgnoreCase)).ToList();
        if (f.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            var ft = doc.AddTable(f.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].AddParagraph("Severity");
            ft.Rows[0].Cells[1].AddParagraph("Code");
            ft.Rows[0].Cells[2].AddParagraph("Target");
            ft.Rows[0].Cells[3].AddParagraph("Message");
            for (int i = 0; i < f.Count; i++)
            {
                var a = f[i];
                ft.Rows[i + 1].Cells[0].AddParagraph(a.Severity);
                ft.Rows[i + 1].Cells[1].AddParagraph(a.Code);
                ft.Rows[i + 1].Cells[2].AddParagraph(a.Target);
                ft.Rows[i + 1].Cells[3].AddParagraph(a.Message);
            }
        }

        // References
        if (sec.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            WordLinkHelpers.AddReferencesList(doc, sec.References);
        }

        // Preserve Word-only details from original view (evidence, flattened IP, mechanisms)
        if (original != null)
        {
            // Evidence
            headings.AddItem("Evidence", baseLevel);
            doc.AddParagraph("Raw SPF record values.");
            var lbl = doc.AddParagraph("SPF Record:"); lbl.Bold = true;
            var rec = doc.AddParagraph(original.SpfRecord ?? string.Empty); rec.FontSize = 10;

            // Mechanisms (normal/detailed)
            if (original.Mechanisms != null && original.Mechanisms.Count > 0)
            {
                headings.AddItem("Mechanisms", baseLevel);
                var mech = doc.AddTable(original.Mechanisms.Count + 1, 4, WordTableStyle.TableGrid);
                mech.Rows[0].Cells[0].AddParagraph("Qualifier");
                mech.Rows[0].Cells[1].AddParagraph("Type");
                mech.Rows[0].Cells[2].AddParagraph("Value");
                mech.Rows[0].Cells[3].AddParagraph("Provider");
                for (int i = 0; i < original.Mechanisms.Count; i++)
                {
                    var p = original.Mechanisms[i];
                    mech.Rows[i + 1].Cells[0].AddParagraph(string.IsNullOrEmpty(p.Prefix) ? "+" : p.Prefix);
                    mech.Rows[i + 1].Cells[1].AddParagraph(p.Type ?? string.Empty);
                    mech.Rows[i + 1].Cells[2].AddParagraph(p.Value ?? string.Empty);
                    mech.Rows[i + 1].Cells[3].AddParagraph(p.Provider ?? string.Empty);
                }
            }

            // Flattened IP Analysis
            var flat = original.Raw?.FlattenedIpAnalysis;
            if (flat != null)
            {
                headings.AddItem("Flattened IP Analysis", baseLevel);
                var flatTable = doc.AddTable(3, 2, WordTableStyle.TableGrid);
                flatTable.Rows[0].Cells[0].AddParagraph("Unique IPs"); flatTable.Rows[0].Cells[1].AddParagraph((flat?.UniqueIps?.Count ?? 0).ToString());
                flatTable.Rows[1].Cells[0].AddParagraph("Duplicate IPs"); flatTable.Rows[1].Cells[1].AddParagraph((flat?.DuplicateIps?.Count ?? 0).ToString());
                flatTable.Rows[2].Cells[0].AddParagraph("Tokens Resolved"); flatTable.Rows[2].Cells[1].AddParagraph((flat?.TokenIpMap?.Count ?? 0).ToString());
            }
        }
    }
}
