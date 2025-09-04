using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class SmtpAuthNarrative
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

    public static Sections Build(SmtpAuthAnalysis analysis)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject!;
        var title = $"SMTP AUTH Report — {subj}";
        var subtitle = "SMTP AUTH Assessment";
        var category = "Email Security";
        var keywords = $"SMTP AUTH, SASL, email, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "SMTP AUTH allows clients to authenticate before sending mail.";
        var why = "Securing authentication prevents unauthorized use and protects credentials.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null || analysis.ServerMechanisms.Count == 0)
        {
            hi.Add("No SMTP AUTH data available.");
        }
        else
        {
            foreach (var kv in analysis.ServerMechanisms)
            {
                var mechs = kv.Value.Length == 0 ? "(none)" : string.Join(" ", kv.Value);
                hi.Add($"{kv.Key} supports {mechs}");
                if (analysis.InspectCapabilities && analysis.ServerCapabilities.TryGetValue(kv.Key, out var caps))
                {
                    hi.Add(caps.Contains("STARTTLS", StringComparer.OrdinalIgnoreCase) ? $"{kv.Key} advertises STARTTLS." : $"{kv.Key} does not advertise STARTTLS.");
                }
            }
            AssessmentSplit.SplitTitles(analysis.Assessments ?? new List<Assessment>(), out positives, out remediations);
        }

        var refs = new List<string>
        {
            "https://www.rfc-editor.org/rfc/rfc4954",
            "https://www.rfc-editor.org/rfc/rfc8314"
        };

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
}
