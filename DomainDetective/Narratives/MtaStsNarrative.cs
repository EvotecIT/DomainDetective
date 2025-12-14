using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class MtaStsNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(MTASTSAnalysis? analysis, IEnumerable<Assessment>? assessments = null)
    {
        var domainCandidate = analysis?.Domain;
        string subj;
        if (domainCandidate != null && !string.IsNullOrWhiteSpace(domainCandidate))
        {
            subj = domainCandidate;
        }
        else
        {
            subj = "(domain)";
        }
        var title = $"MTA-STS Report — {subj}";
        var subtitle = "MTA-STS Assessment";
        var category = "Email Security";
        var kb = new StringBuilder("MTA-STS, email, security, DomainDetective");
        if (!string.IsNullOrWhiteSpace(subj))
        {
            kb.Append(", ").Append(subj);
        }

        var keywords = kb.ToString();
        var creator = "DomainDetective";
        var intro = "SMTP MTA Strict Transport Security (MTA-STS) allows a domain to require TLS for inbound mail using a policy published over HTTPS.";
        var why = "A valid MTA-STS policy helps prevent downgrade attacks by ensuring sending MTAs use TLS.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null)
        {
            return new Sections
            {
                Introduction = intro,
                WhyItMatters = why,
                Highlights = new List<string> { "No MTA-STS data available." },
                Details = det,
                References = DefaultRefs(null)
            };
        }

        hi.Add(analysis.DnsRecordPresent ? "MTA-STS record published." : "No MTA-STS record published.");

        if (analysis.PolicyPresent)
        {
            if (analysis.PolicyValid)
            {
                hi.Add($"Policy mode: {analysis.Mode ?? "unknown"}.");
                if (analysis.ValidMaxAge)
                {
                    hi.Add($"Max age: {analysis.MaxAge} seconds.");
                }
            }
            else
            {
                hi.Add("Policy file invalid or unreadable.");
            }
        }
        else
        {
            hi.Add("Policy file not found.");
        }

        if (!string.IsNullOrWhiteSpace(analysis.Advisory))
        {
            det.Add($"Advisory: {analysis.Advisory}");
        }

        var refs = DefaultRefs(analysis);

        try
        {
            var ass = assessments ?? analysis.Assessments;
            if (ass != null)
            {
                (positives, negatives, remediations) = AssessmentSplit.SplitTitles(ass);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine(ex);
        }

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

    private static List<string> DefaultRefs(MTASTSAnalysis? analysis) =>
        analysis?.RfcReferences?.Select(r => string.IsNullOrWhiteSpace(r.Url) ? r.Reference : r.Url).ToList()
        ?? new List<string> { "https://datatracker.ietf.org/doc/html/rfc8461" };
}
