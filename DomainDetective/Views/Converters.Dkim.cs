using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static IEnumerable<DkimRecordInfo> Convert(DkimAnalysis analysis)
    {
        foreach (var kvp in analysis.AnalysisResults)
        {
            var result = kvp.Value;
            var a = analysis.Assessments?.Where(x => string.Equals(x.Target, kvp.Key, StringComparison.OrdinalIgnoreCase)).ToList() ?? new List<Assessment>();
            var recs = RecommendationEngine.From(a);
            Summarize(a, out var warnCount, out var errCount, out var status);
            var narrative = DomainDetective.Narratives.DkimNarrative.Build(result, kvp.Key);
            yield return new DkimRecordInfo
            {
                Check = HealthCheckType.DKIM,
                Area = AreaForKind(HealthCheckType.DKIM),
                Subject = analysis.Subject,
                Selector = kvp.Key,
                Name = result.Name,
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
                Flags = result.Flags,
                ValidFlags = result.ValidFlags,
                UnknownFlagCharacters = result.UnknownFlagCharacters,
                Canonicalization = result.Canonicalization,
                ValidCanonicalization = result.ValidCanonicalization,
                KeyType = result.KeyType,
                HashAlgorithm = result.HashAlgorithm,
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
                References = BuildReferences(analysis.RfcReferences, recs),
                Raw = result,
                Narrative = narrative,
                Highlights = narrative.Highlights
            };
        }
    }
}

public class DkimRecordInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public string Selector { get; set; }
    public string Name { get; set; }
    public string DkimRecord { get; set; }
    public bool DkimRecordExists { get; set; }
    public bool StartsCorrectly { get; set; }
    public bool PublicKeyExists { get; set; }
    public bool ValidPublicKey { get; set; }
    public bool ValidRsaKeyLength { get; set; }
    public int KeyLength { get; set; }
    public bool WeakKey { get; set; }
    public bool KeyTypeExists { get; set; }
    public bool ValidKeyType { get; set; }
    public string PublicKey { get; set; }
    public string ServiceType { get; set; }
    public string Flags { get; set; }
    public bool ValidFlags { get; set; }
    public string UnknownFlagCharacters { get; set; }
    public string Canonicalization { get; set; }
    public bool ValidCanonicalization { get; set; }
    public string KeyType { get; set; }
    public string HashAlgorithm { get; set; }
    public DateTime? CreationDate { get; set; }
    public int KeyAgeDays { get; set; }
    public bool OldKey { get; set; }
    public IReadOnlyList<string> DeprecatedTags { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public DkimRecordAnalysis Raw { get; set; }
    public DomainDetective.Narratives.DkimNarrative.Sections Narrative { get; set; }
    public IReadOnlyList<string> Highlights { get; set; }
}
