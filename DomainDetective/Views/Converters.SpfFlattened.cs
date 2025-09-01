using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
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
            Tokens = result.Tokens,
            TokenIpMap = result.TokenIpMap,
            UniqueIps = result.UniqueIps,
            DuplicateIps = result.DuplicateIps,
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

public sealed class SpfFlattenedInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public IReadOnlyList<string> Tokens { get; set; }
    public IReadOnlyDictionary<string, List<string>> TokenIpMap { get; set; }
    public IReadOnlyList<string> UniqueIps { get; set; }
    public IReadOnlyList<string> DuplicateIps { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public FlattenedSpfResult Raw { get; set; }
}

