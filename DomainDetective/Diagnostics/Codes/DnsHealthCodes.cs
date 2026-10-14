namespace DomainDetective;

internal static class DnsHealthCodes {
    public const string SoaSerialSkew = "DNS.Health.SOA.SerialSkew";
    public const string ApexInconsistent = "DNS.Health.Apex.Inconsistent";
    public const string SoaSerialConsistent = "DNS.Health.SOA.SerialConsistent";
    public const string ServersResponsive = "DNS.Health.Servers.Responsive";
    public const string CoverageIncomplete = "DNS.Health.Coverage.Incomplete";
    public const string QueryFailed = "DNS.Health.Query.Failed";
}
