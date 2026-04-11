using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static IEnumerable<DkimRecordInfo> Convert(DkimAnalysis analysis)
    {
        foreach (var kvp in analysis.AnalysisResults)
        {
            var result = kvp.Value;
            var a = analysis.Assessments?.Where(x => string.Equals(x.Target, kvp.Key, StringComparison.OrdinalIgnoreCase)).ToList() ?? new List<Assessment>();
            var recs = RecommendationEngine.FromProblems(a);
            Summarize(a, out var warnCount, out var errCount, out var status);
            var narrative = DomainDetective.Narratives.DkimNarrative.Build(result, kvp.Key, a);
            yield return new DkimRecordInfo
            {
                Check = HealthCheckType.DKIM,
                Area = AreaForKind(HealthCheckType.DKIM),
                Subject = analysis.Subject ?? string.Empty,
                Selector = kvp.Key,
                Name = result.Name ?? string.Empty,
                DnsRecordTtl = result.DnsRecordTtl,
                CnameTtl = result.CnameTtl,
                IsCnameResolved = result.IsCnameResolved,
                DkimRecord = result.DkimRecord,
                DkimRecordExists = result.DkimRecordExists,
                StartsCorrectly = result.StartsCorrectly,
                PublicKeyExists = result.PublicKeyExists,
                ValidPublicKey = result.ValidPublicKey,
                ValidRsaKeyLength = result.ValidRsaKeyLength,
                KeyLength = result.KeyLength,
                WeakKey = result.WeakKey,
                KeyTypeExists = result.KeyTypeExists,
                ValidKeyType = result.ValidKeyType,
                PublicKey = result.PublicKey,
                ServiceType = result.ServiceType,
                Flags = result.Flags ?? string.Empty,
                ValidFlags = result.ValidFlags,
                UnknownFlagCharacters = result.UnknownFlagCharacters,
                Canonicalization = result.Canonicalization,
                ValidCanonicalization = result.ValidCanonicalization,
                KeyType = result.KeyType,
                HashAlgorithm = result.HashAlgorithm ?? string.Empty,
                CreationDate = result.CreationDate,
                KeyAgeDays = result.KeyAgeDays,
                OldKey = result.OldKey,
                DeprecatedTags = result.DeprecatedTags,
                Assessments = a,
                Status = status,
                WarningCount = warnCount,
                ErrorCount = errCount,
                Summary = $"{(result.PublicKeyExists ? result.KeyLength.ToString() : "no key")} bits; alg {result.HashAlgorithm ?? "?"}",
                Recommendations = recs,
                Positives = RecommendationEngine.FromPositives(a),
                References = BuildReferences(analysis.RfcReferences, recs),
                Raw = result,
                Narrative = narrative,
                Highlights = narrative.Highlights
            };
        }
    }
}

/// <summary>
/// View model summarizing DKIM selector analysis for reporting.
/// </summary>
public class DkimRecordInfo
{
    /// <summary>Type of health check.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Logical analysis area.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Subject domain.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>Selector value.</summary>
    public string Selector { get; set; } = string.Empty;
    /// <summary>DNS name queried (selector._domainkey.domain).</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>DNS TTL (seconds) of the selector TXT record.</summary>
    public int? DnsRecordTtl { get; set; }
    /// <summary>TTL (seconds) of the CNAME record when resolved via CNAME alias.</summary>
    public int? CnameTtl { get; set; }
    /// <summary>True when the DKIM record was resolved through a CNAME alias.</summary>
    public bool IsCnameResolved { get; set; }
    /// <summary>Raw DKIM TXT record.</summary>
    public string DkimRecord { get; set; } = string.Empty;
    /// <summary>Gets or sets the dkim record exists value.</summary>
    public bool DkimRecordExists { get; set; }
    /// <summary>Gets or sets the starts correctly value.</summary>
    public bool StartsCorrectly { get; set; }
    /// <summary>Gets or sets the public key exists value.</summary>
    public bool PublicKeyExists { get; set; }
    /// <summary>Gets or sets the valid public key value.</summary>
    public bool ValidPublicKey { get; set; }
    /// <summary>Gets or sets the valid rsa key length value.</summary>
    public bool ValidRsaKeyLength { get; set; }
    /// <summary>Gets or sets the key length value.</summary>
    public int KeyLength { get; set; }
    /// <summary>Gets or sets the weak key value.</summary>
    public bool WeakKey { get; set; }
    /// <summary>Gets or sets the key type exists value.</summary>
    public bool KeyTypeExists { get; set; }
    /// <summary>Gets or sets the valid key type value.</summary>
    public bool ValidKeyType { get; set; }
    /// <summary>Base64-encoded public key (p=).</summary>
    public string PublicKey { get; set; } = string.Empty;
    /// <summary>Service type flag (s=).</summary>
    public string ServiceType { get; set; } = string.Empty;
    /// <summary>Flags (t=).</summary>
    public string Flags { get; set; } = string.Empty;
    /// <summary>Gets or sets the valid flags value.</summary>
    public bool ValidFlags { get; set; }
    /// <summary>Any unrecognized flag characters.</summary>
    public string UnknownFlagCharacters { get; set; } = string.Empty;
    /// <summary>Canonicalization modes (c=).</summary>
    public string Canonicalization { get; set; } = string.Empty;
    /// <summary>Gets or sets the valid canonicalization value.</summary>
    public bool ValidCanonicalization { get; set; }
    /// <summary>Key type (k=).</summary>
    public string KeyType { get; set; } = string.Empty;
    /// <summary>Hash algorithm (h=) or inferred from key.</summary>
    public string HashAlgorithm { get; set; } = string.Empty;
    /// <summary>Gets or sets the creation date value.</summary>
    public DateTime? CreationDate { get; set; }
    /// <summary>Gets or sets the key age days value.</summary>
    public int KeyAgeDays { get; set; }
    /// <summary>Gets or sets the old key value.</summary>
    public bool OldKey { get; set; }
    /// <summary>Deprecated tags present in the record.</summary>
    public IReadOnlyList<string> DeprecatedTags { get; set; } = System.Array.Empty<string>();
    /// <summary>Assessment list.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Overall status (OK/Warning/Error).</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Short summary text for executive reports.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Actionable recommendations.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Positive posture notes.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Reference links.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Underlying DKIM analysis result.</summary>
    public DkimRecordAnalysis Raw { get; set; } = new DkimRecordAnalysis();
    /// <summary>Narrative (human-friendly) content blocks.</summary>
    public DomainDetective.Narratives.DkimNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.DkimNarrative.Sections();
    /// <summary>Key highlights extracted for the report.</summary>
    public IReadOnlyList<string> Highlights { get; set; } = System.Array.Empty<string>();
}
