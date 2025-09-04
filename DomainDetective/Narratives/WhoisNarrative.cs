using System;
using System.Collections.Generic;

namespace DomainDetective.Narratives;

public static class WhoisNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(WhoisAnalysis whois)
    {
        var subj = string.IsNullOrWhiteSpace(whois?.DomainName) ? "(domain)" : whois.DomainName;
        var title = $"WHOIS Report — {subj}";
        var subtitle = "WHOIS Registration";
        var category = "Domain Registration";
        var keywords = $"WHOIS, domain, registration, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "WHOIS provides legacy domain registration information about a domain.";
        var why = "WHOIS data reveals ownership, privacy use, and expiration which affect domain control.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        if (!string.IsNullOrWhiteSpace(whois?.RegisteredTo))
        {
            hi.Add($"Registered to {whois.RegisteredTo}");
        }
        else
        {
            hi.Add("Registrant information not disclosed");
        }

        hi.Add(whois?.PrivacyProtected == true
            ? "WHOIS privacy protection enabled"
            : "WHOIS privacy protection not enabled");

        if (!string.IsNullOrWhiteSpace(whois?.ExpiryDate))
        {
            hi.Add($"Expires on {whois.ExpiryDate}");
        }
        else
        {
            hi.Add("Expiration date unavailable");
        }

        if (!string.IsNullOrWhiteSpace(whois?.Registrar))
        {
            det.Add($"Registrar: {whois.Registrar}");
        }
        if (!string.IsNullOrWhiteSpace(whois?.Country))
        {
            det.Add($"Country: {whois.Country}");
        }
        if (whois?.NameServers != null && whois.NameServers.Count > 0)
        {
            det.Add($"Name servers: {string.Join(", ", whois.NameServers)}");
        }

        var refs = new List<string>
        {
            "https://datatracker.ietf.org/doc/html/rfc3912"
        };

        try
        {
            AssessmentSplit.SplitTitles(whois?.Assessments ?? new List<Assessment>(), out positives, out remediations);
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
            Remediations = remediations
        };
    }
}
