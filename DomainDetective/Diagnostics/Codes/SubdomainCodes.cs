namespace DomainDetective;

internal static class SubdomainCodes {
    public const string PassiveQueryFailed = "SUBDOM.Passive.QueryFailed";
    public const string CtQueryFailed = "SUBDOM.CT.QueryFailed";
    public const string CtParseFailed = "SUBDOM.CT.ParseFailed";
    public const string CtNoResults = "SUBDOM.CT.NoResults";
    public const string CtResultsPresent = "SUBDOM.CT.ResultsPresent";
    public const string CtResultsCapped = "SUBDOM.CT.ResultsCapped";
    public const string ResolutionReduced = "SUBDOM.Dns.ResolutionReduced";
    public const string SensitiveSubdomainsHigh = "SUBDOM.Sensitive.High";
    public const string SensitiveSubdomainsModerate = "SUBDOM.Sensitive.Moderate";
    public const string AiInfrastructureExposed = "SUBDOM.AI.Exposed";
    public const string SensitiveTxtSuspicious = "SUBDOM.Sensitive.Txt.Suspicious";
    public const string NonPublicIpAddress = "SUBDOM.Dns.NonPublicIp";
}
