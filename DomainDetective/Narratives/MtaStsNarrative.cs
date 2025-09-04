using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class MtaStsNarrative
{
    public sealed class Sections
    {
        public string Title { get; init; } = string.Empty;
        public string Subtitle { get; init; } = string.Empty;
        public string Category { get; init; } = string.Empty;
        public string Keywords { get; init; } = string.Empty;
        public string Creator { get; init; } = string.Empty;
        public string Introduction { get; init; } = string.Empty;
        public string WhyItMatters { get; init; } = string.Empty;
        public List<string> Highlights { get; init; } = new();
        public List<string> Details { get; init; } = new();
        public List<string> References { get; init; } = new();
        public List<string> Positives { get; init; } = new();
        public List<string> Remediations { get; init; } = new();
    }

    public static Sections Build(MTASTSAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Domain) ? "(domain)" : analysis.Domain;
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
                AssessmentSplit.SplitTitles(ass, out positives, out remediations);
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
            Remediations = remediations
        };
    }

    private static List<string> DefaultRefs(MTASTSAnalysis? analysis) =>
        analysis?.RfcReferences?.Select(r => string.IsNullOrWhiteSpace(r.Url) ? r.Reference : r.Url).ToList()
        ?? new List<string> { "https://datatracker.ietf.org/doc/html/rfc8461" };
}
