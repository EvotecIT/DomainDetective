using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class TtlNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(DnsTtlAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject!;
        var title = $"DNS TTL Report — {subj}";
        var subtitle = "DNS TTL Assessment";
        var category = "DNS";
        var keywords = $"DNS, TTL, caching, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Time to Live (TTL) values control how long DNS data stays cached before revalidation.";
        var why = "Appropriate TTLs balance caching efficiency with agility for updates; inconsistent values can cause cache churn or stale records.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        void AppendTtlRange(List<string> target, IReadOnlyList<int>? ttls, string label)
        {
            if (ttls == null || ttls.Count == 0)
            {
                return;
            }

            target.Add($"{label} TTLs min/max {ttls.Min()}/{ttls.Max()}s.");
        }

        void AppendAuthoritativeRange(List<string> target, IReadOnlyList<int>? ttls, string label)
        {
            if (ttls == null || ttls.Count == 0)
            {
                return;
            }

            target.Add($"{label} TTLs (authoritative) min/max {ttls.Min()}/{ttls.Max()}s.");
        }

        void AppendDetail(List<string> target, IReadOnlyList<int>? ttls, string label)
        {
            if (ttls == null || ttls.Count == 0)
            {
                return;
            }

            target.Add($"{label}: {string.Join(", ", ttls)}");
        }

        if (analysis == null)
        {
            return new Sections
            {
                Introduction = intro,
                WhyItMatters = why,
                Highlights = new List<string> { "No TTL data available." },
                Details = det,
                References = new List<string> { "https://www.rfc-editor.org/rfc/rfc1035" }
            };
        }

        hi.Add($"SOA TTL: {analysis.SoaTtl}s.");
        if (analysis.AuthoritativeSoaTtl.HasValue)
        {
            hi.Add($"SOA TTL (authoritative): {analysis.AuthoritativeSoaTtl.Value}s.");
        }
        AppendTtlRange(hi, analysis.ATtls, "A");
        AppendTtlRange(hi, analysis.AaaaTtls, "AAAA");
        AppendAuthoritativeRange(hi, analysis.AuthoritativeATtls, "A");
        AppendAuthoritativeRange(hi, analysis.AuthoritativeAaaaTtls, "AAAA");
        if (analysis.AUniformAcrossServers)
        {
            hi.Add("A TTLs uniform across name servers.");
        }
        else if (analysis.ServerTtlA.Count > 0)
        {
            hi.Add("A TTLs vary across name servers.");
        }
        if (analysis.AaaaUniformAcrossServers)
        {
            hi.Add("AAAA TTLs uniform across name servers.");
        }
        else if (analysis.ServerTtlAaaa.Count > 0)
        {
            hi.Add("AAAA TTLs vary across name servers.");
        }
        if (analysis.NsUniformAcrossServers)
        {
            hi.Add("NS TTLs uniform across name servers.");
        }
        else if (analysis.ServerTtlNs.Count > 0)
        {
            hi.Add("NS TTLs vary across name servers.");
        }
        AppendTtlRange(hi, analysis.MxTtls, "MX");
        AppendTtlRange(hi, analysis.SpfTxtTtls, "SPF TXT");
        AppendTtlRange(hi, analysis.DmarcTxtTtls, "DMARC TXT");
        AppendTtlRange(hi, analysis.MtastsTxtTtls, "MTA-STS TXT");
        AppendTtlRange(hi, analysis.TlsRptTxtTtls, "TLS-RPT TXT");
        AppendAuthoritativeRange(hi, analysis.AuthoritativeMxTtls, "MX");
        AppendAuthoritativeRange(hi, analysis.AuthoritativeSpfTxtTtls, "SPF TXT");
        AppendAuthoritativeRange(hi, analysis.AuthoritativeDmarcTxtTtls, "DMARC TXT");
        AppendAuthoritativeRange(hi, analysis.AuthoritativeMtastsTxtTtls, "MTA-STS TXT");
        AppendAuthoritativeRange(hi, analysis.AuthoritativeTlsRptTxtTtls, "TLS-RPT TXT");
        var dkimAll = analysis.DkimTxtTtls?.Values?.SelectMany(v => v ?? Array.Empty<int>()).ToArray() ?? Array.Empty<int>();
        if (dkimAll.Length > 0)
        {
            AppendTtlRange(hi, dkimAll, "DKIM TXT");
        }
        var dkimAuthAll = analysis.AuthoritativeDkimTxtTtls?.Values?.SelectMany(v => v ?? Array.Empty<int>()).ToArray() ?? Array.Empty<int>();
        if (dkimAuthAll.Length > 0)
        {
            AppendAuthoritativeRange(hi, dkimAuthAll, "DKIM TXT");
        }

        if (analysis.Warnings != null && analysis.Warnings.Count > 0)
        {
            hi.AddRange(analysis.Warnings);
        }
        else
        {
            hi.Add("TTL values appear balanced for caching and agility.");
        }

        if (analysis.ATtls?.Count > 0)
        {
            det.Add($"A: {string.Join(", ", analysis.ATtls)}");
        }
        if (analysis.AaaaTtls?.Count > 0)
        {
            det.Add($"AAAA: {string.Join(", ", analysis.AaaaTtls)}");
        }
        AppendDetail(det, analysis.MxTtls, "MX");
        AppendDetail(det, analysis.SpfTxtTtls, "SPF TXT");
        AppendDetail(det, analysis.DmarcTxtTtls, "DMARC TXT");
        AppendDetail(det, analysis.MtastsTxtTtls, "MTA-STS TXT");
        AppendDetail(det, analysis.TlsRptTxtTtls, "TLS-RPT TXT");
        if (analysis.DkimTxtTtls != null && analysis.DkimTxtTtls.Count > 0)
        {
            var dkimDetails = analysis.DkimTxtTtls
                .Where(kv => kv.Value != null && kv.Value.Count > 0)
                .Select(kv => $"{kv.Key}: {string.Join(", ", kv.Value)}")
                .ToArray();
            if (dkimDetails.Length > 0)
            {
                det.Add($"DKIM TXT: {string.Join("; ", dkimDetails)}");
            }
        }
        AppendDetail(det, analysis.AuthoritativeSpfTxtTtls, "SPF TXT (authoritative)");
        AppendDetail(det, analysis.AuthoritativeDmarcTxtTtls, "DMARC TXT (authoritative)");
        AppendDetail(det, analysis.AuthoritativeMtastsTxtTtls, "MTA-STS TXT (authoritative)");
        AppendDetail(det, analysis.AuthoritativeTlsRptTxtTtls, "TLS-RPT TXT (authoritative)");
        if (analysis.AuthoritativeDkimTxtTtls != null && analysis.AuthoritativeDkimTxtTtls.Count > 0)
        {
            var dkimAuthDetails = analysis.AuthoritativeDkimTxtTtls
                .Where(kv => kv.Value != null && kv.Value.Count > 0)
                .Select(kv => $"{kv.Key}: {string.Join(", ", kv.Value)}")
                .ToArray();
            if (dkimAuthDetails.Length > 0)
            {
                det.Add($"DKIM TXT (authoritative): {string.Join("; ", dkimAuthDetails)}");
            }
        }
        if (analysis.NsTtls?.Count > 0)
        {
            det.Add($"NS: {string.Join(", ", analysis.NsTtls)}");
        }

        var refs = new List<string> { "https://www.rfc-editor.org/rfc/rfc1035" };

        try
        {
            var ass = assessments ?? analysis.Assessments;
            if (ass != null)
            {
                (positives, negatives, remediations) = AssessmentSplit.SplitTitles(ass);
            }
        }
        catch { }

        return new Sections
        {
            Title = title,
            Subtitle = subtitle,
            Category = category,
            Keywords = keywords,
            Creator = creator,
            Introduction = intro,
            WhyItMatters = why,
            Highlights = hi,
            Details = det,
            References = refs,
            Positives = positives,
            Negatives = negatives,
            Remediations = remediations
        };
    }
}
