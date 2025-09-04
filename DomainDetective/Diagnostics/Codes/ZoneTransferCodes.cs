namespace DomainDetective;

internal static class ZoneTransferCodes {
    public const string Allowed = "AXFR.Allowed";
    public const string CheckFailed = "AXFR.Check.Failed";
    // Positive signal when zone transfers are properly restricted
    public const string Restricted = "AXFR.Restricted";
}

