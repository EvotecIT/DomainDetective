using System;
using System.Collections.Generic;

namespace DomainDetective.Narratives;

public static class RdapNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(RdapAnalysis rdap)
    {
        var subj = string.IsNullOrWhiteSpace(rdap.DomainName) ? "(domain)" : rdap.DomainName;
        var title = $"RDAP Report — {subj}";
        var subtitle = "RDAP Registration";
        var category = "Domain Registration";
        var keywords = $"RDAP, domain, registration, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Registration Data Access Protocol (RDAP) provides standardized domain registration information.";
        var why = "RDAP reveals ownership, registrar, and lifecycle dates that help assess domain control.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (!string.IsNullOrWhiteSpace(rdap.CreationDate))
            hi.Add($"Registered on {rdap.CreationDate}");
        if (!string.IsNullOrWhiteSpace(rdap.ExpiryDate))
            hi.Add($"Expires on {rdap.ExpiryDate}");
        hi.Add(!string.IsNullOrWhiteSpace(rdap.Registrar) ? $"Registrar: {rdap.Registrar}" : "Registrar unknown");

        if (!string.IsNullOrWhiteSpace(rdap.RegistrarId))
            det.Add($"Registrar ID: {rdap.RegistrarId}");
        if (rdap.NameServers != null && rdap.NameServers.Count > 0)
            det.Add($"Name servers: {string.Join(", ", rdap.NameServers)}");
        if (rdap.Status != null && rdap.Status.Count > 0)
            det.Add($"Status: {string.Join(", ", rdap.Status)}");

        var refs = new List<string>
        {
            "https://datatracker.ietf.org/doc/html/rfc9082"
        };

        try
        {
            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(rdap.Assessments ?? new List<Assessment>());
        }
        catch (Exception)
        {
            // best effort
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
}
