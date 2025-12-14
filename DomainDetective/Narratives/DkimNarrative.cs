using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class DkimNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(DkimRecordAnalysis dkim, string? selector = null, System.Collections.Generic.IEnumerable<Assessment>? assessments = null)
    {
        var shown = selector ?? dkim?.Name ?? "(selector)";
        var title = $"DKIM Record — {shown}";
        var subtitle = "DKIM Assessment";
        var category = "Email Security";
        var keywords = $"DKIM, email, security, DomainDetective, {shown}";
        var creator = "DomainDetective";
        var intro = "DomainKeys Identified Mail (DKIM) uses a cryptographic signature to prove a message was authorized by the domain and not altered in transit.";
        var why = "DKIM is one of the two mechanisms (alongside SPF) that can satisfy DMARC alignment. Strong keys and valid configuration improve deliverability and security.";

        var sel = selector ?? dkim?.Name;
        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        // Highlights
        if (dkim == null)
        {
            return new Sections
            {
                Introduction = intro,
                WhyItMatters = why,
                Highlights = new List<string> { "No DKIM data available." },
                Details = det,
                References = DefaultRefs()
            };
        }

        hi.Add(dkim.DkimRecordExists
            ? $"DKIM record is published for selector '{sel}'."
            : $"No DKIM record is published for selector '{sel}'.");
        if (dkim.DkimRecordExists)
        {
            hi.Add(dkim.StartsCorrectly
                ? "Record starts with v=DKIM1."
                : "Record does not start with v=DKIM1.");
        }

        if (dkim.PublicKeyExists)
        {
            var keyBits = dkim.KeyLength > 0 ? $", {dkim.KeyLength} bits" : string.Empty;
            hi.Add($"Public key present{keyBits}{(dkim.WeakKey ? " (weak)" : string.Empty)}.");
            if (dkim.ValidRsaKeyLength && dkim.KeyLength >= 2048)
                hi.Add("RSA key strength: strong (>= 2048 bits).");
        }
        else
        {
            hi.Add("Public key missing (p=). This selector cannot validate.");
        }

        var hashAlgorithm = dkim.HashAlgorithm;
        if (hashAlgorithm != null && !string.IsNullOrWhiteSpace(hashAlgorithm))
        {
            hi.Add($"Hash algorithm: {hashAlgorithm}.");
            if (hashAlgorithm.IndexOf("sha256", StringComparison.OrdinalIgnoreCase) >= 0)
                hi.Add("Hash includes sha256.");
        }

        if (!string.IsNullOrWhiteSpace(dkim.Canonicalization))
        {
            hi.Add($"Canonicalization: {dkim.Canonicalization}{(dkim.ValidCanonicalization ? string.Empty : " (invalid)")}.");
            if (dkim.ValidCanonicalization)
                hi.Add("Canonicalization value valid.");
        }

        if (dkim.OldKey)
        {
            hi.Add("Key appears older than 12 months.");
        }

        // Details
        if (!string.IsNullOrWhiteSpace(dkim.KeyType))
        {
            det.Add($"Key type: {dkim.KeyType}{(dkim.ValidKeyType ? string.Empty : " (unknown)")}");
            if (dkim.ValidKeyType)
                hi.Add("Key type valid.");
        }
        if (!string.IsNullOrWhiteSpace(dkim.ServiceType))
            det.Add($"Service flag (s=): {dkim.ServiceType}");
        if (!string.IsNullOrWhiteSpace(dkim.Flags))
        {
            det.Add($"Flags (t=): {dkim.Flags}{(dkim.ValidFlags ? string.Empty : $" (unknown: {dkim.UnknownFlagCharacters})")}");
            if (dkim.ValidFlags)
                hi.Add("Flags are valid.");
        }

        if (dkim.DeprecatedTags != null && dkim.DeprecatedTags.Count > 0)
            det.Add($"Deprecated: {string.Join(", ", dkim.DeprecatedTags)}");
        if (dkim.UnknownCanonicalizationModes != null && dkim.UnknownCanonicalizationModes.Count > 0)
            det.Add($"Unknown canonicalization: {string.Join(", ", dkim.UnknownCanonicalizationModes)}");

        // References
        var refs = DefaultRefs();

        try
        {
            if (assessments != null)
            {
                (positives, negatives, remediations) = AssessmentSplit.SplitTitles(assessments);
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

    private static List<string> DefaultRefs() => new()
    {
        "https://datatracker.ietf.org/doc/html/rfc6376",
        "https://www.dkimcore.org/tools/"
    };
}
