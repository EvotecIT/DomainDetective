using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static SpfFlattenedInfo Convert(FlattenedSpfResult result)
    {
        var tokens = result.Tokens?.Count ?? 0;
        var unique = result.UniqueIps?.Count ?? 0;
        var dupes = result.DuplicateIps?.Count ?? 0;
        return new SpfFlattenedInfo
        {
            Check = HealthCheckType.SPFFLATTENED,
            Area = AreaForKind(HealthCheckType.SPFFLATTENED),
            Subject = result.Subject,
            Tokens = result.Tokens ?? new List<string>(),
            TokenIpMap = result.TokenIpMap ?? new Dictionary<string, List<string>>(),
            UniqueIps = result.UniqueIps ?? new List<string>(),
            DuplicateIps = result.DuplicateIps ?? new List<string>(),
            Assessments = new List<Assessment>(),
            Status = "OK",
            WarningCount = 0,
            ErrorCount = 0,
            Summary = $"tokens {tokens}; unique {unique}; dupes {dupes}",
            Recommendations = new List<RecommendationAdvice>(),
            References = new [] { "https://www.rfc-editor.org/rfc/rfc7208" },
            Raw = result
        };
    }
}

/// <summary>Provides spf flattened info functionality.</summary>
public sealed class SpfFlattenedInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the tokens value.</summary>
    public IReadOnlyList<string> Tokens { get; set; } = null!;
    /// <summary>Gets or sets the token ip map value.</summary>
    public IReadOnlyDictionary<string, List<string>> TokenIpMap { get; set; } = null!;
    /// <summary>Gets or sets the unique ips value.</summary>
    public IReadOnlyList<string> UniqueIps { get; set; } = null!;
    /// <summary>Gets or sets the duplicate ips value.</summary>
    public IReadOnlyList<string> DuplicateIps { get; set; } = null!;
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = null!;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = null!;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = null!;
    /// <summary>Gets or sets the raw value.</summary>
    public FlattenedSpfResult Raw { get; set; } = null!;
}

