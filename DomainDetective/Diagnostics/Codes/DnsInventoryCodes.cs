namespace DomainDetective;

internal static class DnsInventoryCodes
{
    public const string InventoryFailed = "DNSINV.Inventory.Failed";
    public const string QueryFailed = "DNSINV.Query.Failed";
    public const string NoRecords = "DNSINV.NoRecords";
    public const string ResultsPresent = "DNSINV.ResultsPresent";
    public const string ApexAaaaMissing = "DNSINV.Apex.AAAA.Missing";
    public const string NonPublicIpAddress = "DNSINV.Apex.IP.NonPublic";
    public const string TxtSuspiciousContent = "DNSINV.TXT.Suspicious";
    public const string TxtSignalsExposed = "DNSINV.TXT.Signals.Exposed";
    public const string ServiceDiscoveryExposed = "DNSINV.ServiceDiscovery.Exposed";
    public const string Ipv6Incomplete = "DNSINV.IPv6.Incomplete";
}
