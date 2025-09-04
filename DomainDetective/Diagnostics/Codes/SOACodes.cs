namespace DomainDetective;

internal static class SOACodes {
    public const string Missing = "SOA.Missing";
    public const string SerialFormatNonStandard = "SOA.Serial.NonStandard";
    public const string MnameInvalid = "SOA.MNAME.Invalid";
    public const string RnameInvalid = "SOA.RNAME.Invalid";
    public const string RefreshExtreme = "SOA.Refresh.Extreme";
    public const string RetryExtreme = "SOA.Retry.Extreme";
    public const string MinimumExtreme = "SOA.Minimum.Extreme";
    public const string RefreshSane = "SOA.Refresh.Sane";
    public const string RetrySane = "SOA.Retry.Sane";
    public const string ExpireSane = "SOA.Expire.Sane";
    public const string MnameMatchesNs = "SOA.MNAME.MatchesNS";
}

