namespace DomainDetective;

internal static class DnsAmplificationCodes
{
    public const string HighRisk = "DNSAMPLIFICATION.Risk.High";
    public const string OpenRecursion = "DNSAMPLIFICATION.Recursion.Open";
    public const string EdnsUdpPayloadTooLarge = "DNSAMPLIFICATION.EDNS.UdpPayload.TooLarge";
    public const string LargeUdpResponse = "DNSAMPLIFICATION.Response.Udp.Large";
    public const string NoIndicators = "DNSAMPLIFICATION.Risk.Low";
    public const string CheckFailed = "DNSAMPLIFICATION.Check.Failed";
    public const string NameServersMissing = "DNSAMPLIFICATION.NS.Missing";
    public const string NameServerAddressesMissing = "DNSAMPLIFICATION.NS.NoAddresses";
}

