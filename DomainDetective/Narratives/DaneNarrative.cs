using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class DaneNarrative
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

    public static Sections Build(DANEAnalysis dane, IEnumerable<Assessment>? assessments = null)
    {
        var subject = dane?.Subject ?? "(domain)";
        var title = $"DANE TLSA Records — {subject}";
        var subtitle = "DANE TLSA Assessment";
        var category = "TLS Security";
        var keywords = $"DANE, TLSA, {subject}";
        var creator = "DomainDetective";
        var intro = "DNS-Based Authentication of Named Entities (DANE) binds TLS certificates via DNSSEC.";
        var why = "Valid TLSA records help clients authenticate TLS connections and detect tampering.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        if (dane == null || dane.NumberOfRecords == 0)
        {
            hi.Add("No TLSA records published.");
        }
        else
        {
            foreach (var r in dane.AnalysisResults)
            {
                hi.Add($"TLSA record for {r.DomainName} uses selector {r.SelectorField} and matching {r.MatchingTypeField}.");
                hi.Add(r.ValidDANERecord ? "TLSA record fields are valid." : "TLSA record has validation issues.");
                if (r.ValidCertificateAssociationData && r.CorrectLengthOfCertificateAssociationData)
                {
                    hi.Add("Certificate association data is valid.");
                }
                det.Add($"Usage: {r.CertificateUsage}; Selector: {r.SelectorField}; Matching: {r.MatchingTypeField}; Length: {r.LengthOfCertificateAssociationData}");
            }
        }

        var refs = DefaultRefs();

        try
        {
            if (assessments != null)
            {
                AssessmentSplit.SplitTitles(assessments, out positives, out remediations);
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
            Remediations = remediations
        };
    }

    private static List<string> DefaultRefs() => new()
    {
        "https://datatracker.ietf.org/doc/html/rfc6698"
    };
}
