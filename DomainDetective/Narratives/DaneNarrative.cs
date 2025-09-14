using System;
using System.Collections.Generic;
namespace DomainDetective.Narratives;

/// <summary>
/// Builds narrative sections describing DANE TLSA analysis results.
/// </summary>
public static class DaneNarrative
{
    private static string FormatRecord(string domain, object selector, object matching) =>
        $"TLSA record for {domain} uses selector {selector} and matching {matching}.";
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(DANEAnalysis? dane, IEnumerable<Assessment>? assessments = null)
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
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (dane == null || dane.NumberOfRecords == 0)
        {
            hi.Add("No TLSA records published.");
        }
        else
        {
            foreach (var r in dane.AnalysisResults)
            {
                hi.Add(FormatRecord(r.DomainName, r.SelectorField, r.MatchingTypeField));
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
                AssessmentSplit.SplitTitles(assessments, out positives, out negatives, out remediations);
            }
        }
        catch (ArgumentException ex)
        {
            det.Add($"Assessment processing failed: {ex.Message}");
        }
        catch (InvalidOperationException ex)
        {
            det.Add($"Assessment processing failed: {ex.Message}");
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

    private static List<string> DefaultRefs() => new()
    {
        "https://datatracker.ietf.org/doc/html/rfc6698"
    };
}
