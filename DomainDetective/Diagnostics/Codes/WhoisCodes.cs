namespace DomainDetective;

internal static class WhoisCodes {
    public const string QueryFailed = "WHOIS.Query.Failed";
    public const string IpQueryFailed = "WHOIS.IP.QueryFailed";
    public const string ExpirySoon = "WHOIS.Expiry.Soon";
    public const string Expired = "WHOIS.Expiry.Expired";
    public const string NoRegistrar = "WHOIS.Registrar.Missing";
    public const string ParseAnomaly = "WHOIS.Parse.Anomaly";
}
